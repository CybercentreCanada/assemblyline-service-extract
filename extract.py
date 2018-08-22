from __future__ import absolute_import

import re
import os
import subprocess
import shutil
import tempfile
import time
import email
import zlib

import logging
from lxml import html, etree

from assemblyline.common.charset import safe_str
from assemblyline.common.identify import ident
from assemblyline.al.common.result import Result, ResultSection, SCORE, TAG_TYPE, TAG_WEIGHT
from assemblyline.al.service.base import ServiceBase
from al_services.alsvc_extract.ext.xxxswf import xxxswf
from assemblyline.common.reaper import set_death_signal
from assemblyline.common.timeout import SubprocessTimer

extract_docx = None
msoffice = None
RepairZip = None
BadZipfile = None
ExtractionError = None
PasswordError = None
BeautifulSoup = None
mstools = None

chunk_size = 65536
DEBUG = False


class ExtractMaxExceeded(Exception):
    pass


class ExtractIgnored(Exception):
    pass


class Extract(ServiceBase):
    SERVICE_ACCEPTS = '(archive|executable|java|android)/.*|document/email|document/pdf|document/office/unknown'
    SERVICE_CATEGORY = "Extraction"
    SERVICE_DESCRIPTION = "This service extracts embedded files from file containers (like ZIP, RAR, 7z, ...)"
    SERVICE_ENABLED = True
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_STAGE = 'EXTRACT'
    SERVICE_TIMEOUT = 60
    SERVICE_VERSION = '1'
    SERVICE_CPU_CORES = 0.1
    SERVICE_RAM_MB = 256

    SERVICE_DEFAULT_CONFIG = {
        "DEFAULT_PW_LIST": ["password", "infected", "VelvetSweatshop", "add_more_passwords"],
        "NAMED_EMAIL_ATTACHMENTS_ONLY": True,
        "MAX_EMAIL_ATTACHMENT_SIZE": 10 * 1024**3,
    }
    SERVICE_DEFAULT_SUBMISSION_PARAMS = [{"default": "", "name": "password", "type": "str", "value": ""},
                                         {"default": False,
                                          "name": "extract_pe_sections",
                                          "type": "bool",
                                          "value": False},
                                         {"default": False,
                                          "name": "continue_after_extract",
                                          "type": "bool",
                                          "value": False}]

    FORBIDDEN_EXE = [".text", ".rsrc", ".rdata", ".reloc", ".pdata", ".idata", "UPX", "file"]
    FORBIDDEN_ELF_EXE = [str(x) for x in xrange(20)]
    MAX_EXTRACT = 500
    MAX_EXTRACT_LIVE = 100

    LAUNCHABLE_EXTENSIONS = [
        '.ade',
        '.adp',
        '.as',  # Adobe ActionScript
        '.bat',  # DOS/Windows batch file
        '.chm',
        '.cmd',  # Windows command
        '.com',  # DOS command
        '.cpl',
        '.exe',  # DOS/Windows executable
        '.dll',  # Windows library
        '.hta',
        '.inf',  # Windows autorun file
        '.ins',
        '.isp',
        '.jar',  # Java JAR
        '.jse',
        '.js',  # Javascript
        '.lib',
        '.lnk',  # Windows shortcut
        '.mde',
        '.msc',
        '.msp',
        '.mst',
        '.pif',
        '.py',  # Python script
        '.scr',  # Windows screen saver
        '.sct',
        '.shb',
        '.sys',
        '.vb',  # VB Script
        '.vbe',  # Encrypted VB script
        '.vbs',  # VB Script
        '.vxd',
        '.wsc',
        '.wsf',
        '.wsh'
    ]

    def __init__(self, cfg=None):
        super(Extract, self).__init__(cfg)
        self._last_password = None
        self.extract_methods = [
            self.extract_7zip,
            self.extract_tnef,
            self.extract_swf,
            self.extract_ace,
            self.extract_eml,
            self.repair_zip,
            self.extract_office,
            self.extract_pdf,
        ]
        self.anomaly_detections = [self.archive_with_executables, self.archive_is_arc]
        self.white_listing_methods = [self.jar_whitelisting]
        self.st = None
        self.named_attachments_only = None
        self.max_attachment_size = None
        self.isipa = False

    # noinspection PyUnresolvedReferences
    def import_service_deps(self):
        global BeautifulSoup, RepairZip, BadZipfile, mstools, extract_docx, ExtractionError, PasswordError

        from bs4 import BeautifulSoup

        from al_services.alsvc_extract.repair_zip import RepairZip, BadZipfile
        from al_services.alsvc_extract.doc_extract import mstools, extract_docx, ExtractionError, PasswordError

    def start(self):
        self.st = SubprocessTimer(2*self.SERVICE_TIMEOUT/3)
        self.named_attachments_only = self.cfg.get('NAMED_EMAIL_ATTACHMENTS_ONLY', True)
        self.max_attachment_size = self.cfg.get('MAX_EMAIL_ATTACHMENT_SIZE', None)

    def execute(self, request):
        result = Result()
        continue_after_extract = request.get_param('continue_after_extract')
        self._last_password = None
        self.isipa = False
        local = request.download()
        password_protected = False
        white_listed = 0

        try:
            password_protected, white_listed = self.extract(request, local)
        except ExtractMaxExceeded, e:
            result.add_section(ResultSection(score=SCORE["NULL"], title_text=str(e)))
        except ExtractIgnored, e:
            result.add_section(ResultSection(score=SCORE["NULL"], title_text=str(e)))
        except ExtractionError as ee:
            # If we don't support the encryption method. This will tell us what we need to add support for
            result.add_section(
                ResultSection(score=SCORE.VHIGH,
                              title_text="Password protected file, could not extract: %s" % ee.message)
            )

        num_extracted = len(request.extracted)

        section = None
        if not request.extracted and password_protected:
            section = ResultSection(SCORE.VHIGH,
                                    "Failed to extract password protected file.")
            result.add_tag(TAG_TYPE['FILE_SUMMARY'], "Archive Unknown Password", TAG_WEIGHT['MED'])

        elif request.extracted and password_protected and self._last_password is not None:
            section = ResultSection(SCORE.NULL,
                                    "Successfully extracted %s file(s) using password: %s"
                                    % (num_extracted, self._last_password))

        elif request.extracted and password_protected and self._last_password is None:
            pwlist = " | ".join(self.get_passwords(request))
            section = ResultSection(SCORE.NULL,
                                    "Successfully extracted %s file(s) using one of the following passwords: %s"
                                    % (num_extracted, pwlist))

        elif num_extracted != 0 and white_listed != 0:
            section = ResultSection(SCORE.NULL,
                                    "Successfully extracted %s file(s) out of %s. The rest was whitelisted."
                                    % (num_extracted, white_listed + num_extracted))

        elif num_extracted != 0:
            section = ResultSection(SCORE.NULL,
                                    "Successfully extracted %s file(s)." % num_extracted)

        if section:
            result.add_section(section)

        for anomaly in self.anomaly_detections:
            anomaly(request, result)

        if (request.extracted
                and not request.tag.startswith("executable")
                and not request.tag.startswith("java")
                and not request.tag.startswith("android")
                and not request.tag.startswith("document")
                and not self.isipa
                and not continue_after_extract) \
                or (request.tag == "document/email"
                    and not continue_after_extract):
            request.drop()

        request.result = result

    def extract(self, request, local):
        encoding = request.tag.replace('archive/', '')
        password_protected = False
        white_listed_count = 0
        extracted = []

        # Try all extracting methods
        for extract_method in self.extract_methods:
            extracted, temp_password_protected = extract_method(request, local, encoding)
            if temp_password_protected:
                password_protected = temp_password_protected
            if extracted:
                break

        # Perform needed white listing
        if extracted:
            for white_listing_method in self.white_listing_methods:
                extracted, white_listed_count = white_listing_method(extracted, white_listed_count, encoding)

        for child in extracted:
            if not request.add_extracted(*child):
                raise ExtractMaxExceeded("This file contains more files than the maximum embedded number of %s. "
                                         "None of the %s files where extracted."
                                         % (str(request.max_extracted), str(len(extracted))))

        return password_protected, white_listed_count

    def get_passwords(self, request):
        passwords = self.cfg.get('DEFAULT_PW_LIST', [])
        user_supplied = request.get_param('password')
        if user_supplied:
            passwords.append(user_supplied)

        if "email_body" in self.submission_tags:
            passwords.extend(self.submission_tags["email_body"])

        return passwords

    # noinspection PyCallingNonCallable
    def repair_zip(self, _, local, encoding):
        try:
            with RepairZip(local, strict=False) as rz:
                if not (rz.is_zip and rz.broken):
                    return [], False
                rz.fix_zip()

                with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False) as fh:
                    out_name = fh.name
                    with RepairZip(fh, "w") as zo:
                        for path in rz.namelist():
                            with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=True) as tmp_f:
                                try:
                                    tmp_f.write(rz.read(path))
                                    tmp_f.flush()
                                    zo.write(tmp_f.name, path, rz.ZIP_DEFLATED)
                                except zlib.error:
                                    # Corrupted compression, which is expected
                                    pass
                                except BadZipfile:
                                    # Corrupted zip file, also expected
                                    pass

                return [[out_name, encoding, "repaired_zip_file.zip"]], False
        except ValueError:
            return [], False
        except NotImplementedError:
            # Compression type 99 is not implemented in python zipfile
            return [], False

    # noinspection PyCallingNonCallable
    def extract_office(self, request, local, encoding):
        # When encrypted, AL will identify the document as an unknown office type.
        if request.tag != "document/office/unknown":
            return [], False

        passwords = self.get_passwords(request)
        try:
            # Check is msoffice is compiled
            if os.path.isfile("/opt/al/support/extract/msoffice/bin/msoffice-crypt.exe"):
                # Still going to use extract_docx as a backup for now, so try that module if msoffice fails
                try_next = True
                res = mstools(local, passwords, self.working_directory)
            else:
                try_next = False
                self.log.warning("Extract service out of date. Reinstall on workers with "
                                 "/opt/al/pkg/assemblyline/al/install/reinstall_service.py Extract")
                res = extract_docx(local, passwords, self.working_directory)

            if res is None and not try_next:
                raise ValueError()
            # Try old module if msoffice errors
            if res is None:
                res = extract_docx(local, passwords, self.working_directory)
                if res is None:
                    raise ValueError()
        except ValueError:
            # Not a valid supported/valid file
            return [], False
        except PasswordError:
            # Could not guess password
            return [], True

        out_name, password = res
        self._last_password = password
        display_name = "_decoded".join(os.path.splitext(os.path.basename(request.path)))
        return [[out_name, encoding, display_name]], True

    def _7zip_submit_extracted(self, request, path, encoding):
        extract_pe_sections = request.get_param('extract_pe_sections')
        extracted_children = []

        for root, _, files in os.walk(path):
            for f in files:
                filename = safe_str(os.path.join(root, f).replace(path, ""))
                if filename.startswith("/"):
                    filename = filename[1:]
                if re.match("Payload/[^/]*.app/Info.plist", safe_str(filename)):
                    self.isipa = True
                if not extract_pe_sections and \
                        ((encoding.startswith("executable/windows") and
                          [f for f in self.FORBIDDEN_EXE if filename.startswith(f)]) or
                         (encoding.startswith("executable/linux")and filename in self.FORBIDDEN_ELF_EXE)):
                    raise ExtractIgnored("Detected extraction of forbidden PE/ELF file sections. "
                                         "No files will be extracted.")

                extracted_children.append([os.path.join(root, f), encoding, safe_str(filename)])

        return extracted_children

    def extract_ace(self, request, local, encoding):
        if encoding != 'ace':
            return [], False

        path = os.path.join(self.working_directory, "ace")
        try:
            os.mkdir(path)
        except OSError:
            pass

        # noinspection PyBroadException
        try:
            with tempfile.NamedTemporaryFile(suffix=".ace", dir=path) as tf:
                # unace needs the .ace file extension
                with open(local, "rb") as fh:
                    tf.write(fh.read())
                    tf.flush()

                proc = self.st.run(subprocess.Popen(
                    '/usr/bin/unace e -y %s' % tf.name,
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, cwd=path, env=os.environ, shell=True,
                    preexec_fn=set_death_signal()))

                # Note, proc.communicate() hangs
                stdoutput = proc.stdout.read()
                while True:
                    stdoutput += proc.stdout.read()
                    if proc.poll() is not None:
                        break
                    time.sleep(0.01)

            if stdoutput:
                extracted_children = []
                if "extracted:" in stdoutput:
                    for line in stdoutput.splitlines():
                        line = line.strip()
                        m = re.match("extracting (.+?)[ ]*(CRC OK)?$", line)
                        if not m:
                            continue

                        filename = m.group(1)
                        filepath = os.path.join(path, filename)
                        if os.path.isdir(filepath):
                            continue
                        else:
                            extracted_children.append([filepath, encoding, safe_str(filename)])

                return extracted_children, False

        except ExtractIgnored:
            raise
        except Exception:
            self.log.exception('While extracting %s with unace', request.srl)

        return [], False

    def extract_pdf(self, request, local, encoding):
        extracted_children = []

        if encoding == 'document/pdf':
            output_path = os.path.join(self.working_directory, "TEST_pdf")
            if not os.path.exists(output_path):
                os.makedirs(output_path)

            env = os.environ.copy()
            env['LANG'] = 'en_US.UTF-8'

            subprocess.Popen(
                ['pdfdetach', '-saveall', '-o', output_path, local],
                env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE).communicate()

            files = (filename for filename in os.listdir(output_path) if
                     os.path.isfile(os.path.join(output_path, filename)))

            for filename in files:
                extracted_children.append([output_path + "/" + filename, encoding, safe_str(filename)])

        return extracted_children, False

    def extract_7zip(self, request, local, encoding):
        password_protected = False
        if request.tag == 'archive/audiovisual/flash' or encoding == 'ace' or request.tag.startswith('document') or \
                encoding == 'tnef':
            return [], password_protected
        path = os.path.join(self.working_directory, "7zip")

        # noinspection PyBroadException
        try:
            env = os.environ.copy()
            env['LANG'] = 'en_US.UTF-8'

            stdoutput, _ = subprocess.Popen(
                ['7z', 'x', '-p', '-y', local, '-o%s' % path],
                env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE).communicate()

            if stdoutput and stdoutput.strip().find("Everything is Ok") > 0:
                return self._7zip_submit_extracted(request, path, encoding), password_protected
            else:
                if "Wrong password?" in stdoutput:
                    password_protected = True
                    password_list = self.get_passwords(request)
                    for password in password_list:
                        try:
                            shutil.rmtree(path, ignore_errors=True)

                            proc = subprocess.Popen([
                                '7za', 'x', '-p%s' % password,
                                            '-o%s' % path, local
                            ], env=env, stdout=subprocess.PIPE)
                            stdout = proc.communicate()[0]
                            if "\nEverything is Ok\n" in stdout:
                                self._last_password = password
                                return self._7zip_submit_extracted(request, path, encoding), password_protected

                        except OSError:
                            pass

        except ExtractIgnored:
            raise
        except Exception:
            if request.tag != 'archive/cab':
                self.log.exception('While extracting %s with 7zip', request.srl)

        return [], password_protected

    def extract_swf(self, _, file_path, encoding):
        extracted_children = []

        if encoding == 'audiovisual/flash':
            output_path = os.path.join(self.working_directory, "swf")
            if not os.path.exists(output_path):
                os.makedirs(output_path)

            files_found = []
            # noinspection PyBroadException
            try:
                swf = xxxswf()
                files_found = swf.extract(file_path, output_path)
            except ImportError:
                self.log.exception("Import error: pylzma library not installed.")
            except Exception:
                self.log.exception("Error occurred while trying to decompress swf...")

            for child in files_found:
                extracted_children.append([output_path + "/" + child, encoding, child])

        return extracted_children, False

    def extract_tnef(self, _, file_path, encoding):
        children = []

        if encoding != 'tnef':
            return children, False

        # noinspection PyBroadException
        try:
            # noinspection PyUnresolvedReferences
            from tnefparse import tnef
            tnef_logger = logging.getLogger("tnef-decode")
            tnef_logger.setLevel(60)  # This completely turns off the TNEF logger

            count = 0
            for a in tnef.TNEF(open(file_path).read()).attachments:
                # This may not exist so try to access it and deal the
                # possible AttributeError, by skipping this entry as
                # there is no point if there is no data.
                try:
                    data = a.data
                except AttributeError:
                    continue

                count += 1

                # This may not exist either but long_filename still
                # seems to return so deal with the AttributeError
                # here rather than blowing up.
                try:
                    name = a.long_filename() or a.name
                    if not name:
                        continue

                    name = safe_str(name)
                except AttributeError:
                    name = 'unknown_tnef_%d' % count

                if not name:
                    continue

                path = os.path.join(self.working_directory, str(count))
                with open(path, 'w') as f:
                    f.write(data)

                children.append([path, encoding, name])
        except ImportError:
            self.log.exception("Import error: tnefparse library not installed:")
        except Exception:
            self.log.exception("Error extracting from tnef file:")

        return children, False

    @staticmethod
    def jar_whitelisting(extracted, whitelisted_count, encoding):
        if encoding == "java/jar" or encoding == "android/apk":
            whitelisted_tags_re = [
                re.compile(r'android/(xml|dex|resource)'),
                re.compile(r'audiovisual/.*'),
                re.compile(r'certificate/rsa'),
                re.compile(r'code/.*'),
                re.compile(r'db/.*'),
                re.compile(r'font/.*'),
                re.compile(r'image/.*'),
                re.compile(r'java/(class|manifest|jbdiff|signature)'),
                re.compile(r'resource/.*'),
            ]

            whitelisted_mime_re = [
                re.compile(r'text/plain'),
                re.compile(r'text/x-c'),
            ]

            whitelisted_fname_regex = [
                # commonly used libs files
                re.compile(r'com/google/i18n/phonenumbers/data/(PhoneNumber|ShortNumber)[a-zA-Z]*_[0-9A-Z]{1,3}$'),
                re.compile(r'looksery/([a-zA-Z_]*/){1,5}[a-zA-Z0-9_.]*.glsl$'),
                re.compile(r'org/apache/commons/codec/language/bm/[a-zA-Z0-9_.]*\.txt$'),
                re.compile(r'org/joda/time/format/messages([a-zA-Z_]{0,3})\.properties$'),
                re.compile(r'org/joda/time/tz/data/[a-zA-Z0-9_/\-+]*$'),
                re.compile(r'sharedassets[0-9]{1,3}\.assets(\.split[0-9]{1,3})?$'),
                re.compile(r'zoneinfo(-global)?/([a-zA-Z_\-]*/){1,2}[a-zA-Z_\-]*\.ics$'),

                # noisy files
                re.compile(r'assets/.*\.atf$'),
                re.compile(r'assets/.*\.ffa$'),
                re.compile(r'assets/.*\.ffm$'),
                re.compile(r'assets/.*\.jsa$'),
                re.compile(r'assets/.*\.lua$'),
                re.compile(r'assets/.*\.pf$'),
            ]

            jar_filter_count = whitelisted_count
            tmp_new_files = []

            for cur_file in extracted:
                f = open(cur_file[0], "rb")
                byte_block = f.read(65535 * 2)
                f.close()

                to_add = True
                file_info = ident(byte_block, len(byte_block))
                for exp in whitelisted_tags_re:
                    if exp.search(file_info['tag']):
                        if DEBUG:
                            print "T", file_info['tag'], file_info['ascii'], cur_file[0]
                        to_add = False
                        jar_filter_count += 1

                if to_add:
                    for exp in whitelisted_mime_re:
                        if exp.search(file_info['mime']):
                            if DEBUG:
                                print "M", file_info['mime'], file_info['ascii'], cur_file[0]
                            to_add = False
                            jar_filter_count += 1

                if to_add:
                    for ext in whitelisted_fname_regex:
                        if ext.search(cur_file[0]):
                            if DEBUG:
                                print "F", ext.pattern, file_info['ascii'], cur_file[0]
                            to_add = False
                            jar_filter_count += 1

                if to_add:
                    tmp_new_files.append(cur_file)

            return tmp_new_files, jar_filter_count
        else:
            return extracted, whitelisted_count

    @staticmethod
    def archive_with_executables(request, result):
        if len(request.extracted) == 1 and \
                os.path.splitext(request.extracted[0].display_name)[1].lower() in Extract.LAUNCHABLE_EXTENSIONS:

            new_section = ResultSection(SCORE.VHIGH,
                                        "Archive file with single executable inside. Potentially malicious...")
            result.add_section(new_section)
            result.add_tag(TAG_TYPE['FILE_SUMMARY'], "Archived Single Executable", TAG_WEIGHT['MED'])
        else:
            for extracted in request.extracted:
                if os.path.splitext(extracted.display_name)[1].lower() in Extract.LAUNCHABLE_EXTENSIONS:
                    result.add_tag(TAG_TYPE['FILE_SUMMARY'], "Executable Content in Archive", TAG_WEIGHT['MED'])
                    break

    @staticmethod
    def archive_is_arc(request, result):
        if request.tag == 'archive/ace':
            result.add_section(ResultSection(score=SCORE.VHIGH, title_text="Uncommon format: archive/ace"))
            result.add_tag(TAG_TYPE['FILE_SUMMARY'], "Uncommon format: archive/ace", TAG_WEIGHT['MED'])

    @staticmethod
    def yield_eml_parts(message):
        if message.is_multipart():
            for part in message.walk():
                p_type = part.get_content_type()
                p_disp = part.get("Content-Disposition", "")
                p_load = part.get_payload(decode=True)
                p_name = part.get_filename(None)
                p_cset = part.get_content_charset()
                yield (p_type, p_disp, p_load, p_name, p_cset)
        else:
            p_type = message.get_content_type()
            p_disp = message.get("Content-Disposition", "")
            p_load = message.get_payload(decode=True)
            p_name = message.get_filename(None)
            p_cset = message.get_content_charset()
            yield (p_type, p_disp, p_load, p_name, p_cset)

    # noinspection PyCallingNonCallable
    def extract_eml(self, _, local, encoding):
        if encoding != "document/email":
            return [], False

        extracted = []
        body_words = set()
        with open(local, "r") as fh:
            message = email.message_from_file(fh)
            for part_num, (p_t, p_d, p_l, p_n, p_c) in enumerate(self.yield_eml_parts(message)):
                is_body = not p_n and "attachment" not in p_d and p_t != "application/octet-stream"
                if p_l is None or p_l.strip() == "":
                    continue
                if is_body:
                    encoding = p_c or "utf-8"
                    try:
                        try:
                            body = unicode(p_l, encoding=encoding)
                        except LookupError:
                            # This is usually old windows codepages or jibberish
                            body = unicode(p_l, encoding="utf8", errors="ignore")
                            self.log.info("Detected non-supported codepage %s" % encoding)
                        if p_t == "text/html":
                            try:
                                body = html.document_fromstring(body).text_content()
                            except ValueError:
                                # For documents with xml encoding declarations
                                body = html.document_fromstring(p_l).text_content()
                            except etree.ParserError:
                                # If /body is empty, just grab the text
                                body = BeautifulSoup(body).text
                        if len(body) > 0:
                            # Go through once separating by whitespace
                            words = re.findall("[^ \n\t\r\xa0]+", body)
                            body_words.update(words)
                            # Go through again separating by ANY special character
                            words = re.findall("[A-Za-z0-9]+", body)
                            body_words.update(words)
                    except UnicodeDecodeError:
                        # cannot decode body by specified content
                        pass

                if self.max_attachment_size is not None and len(p_l) > self.max_attachment_size:
                    continue
                if self.named_attachments_only and is_body:
                    continue
                elif p_n is None:
                    p_n = "email_part_%i" % part_num

                ft = tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False)
                ft.write(p_l)
                name = ft.name
                ft.close()
                extracted.append((name, p_t, p_n, self.SERVICE_CLASSIFICATION, {'email_body': list(body_words)}))

        return extracted, False
