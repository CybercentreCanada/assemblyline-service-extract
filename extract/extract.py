import hashlib
import logging
import os
import random
import re
import shutil
import string
import subprocess
import tempfile
import zipfile
import zlib
from copy import deepcopy

from assemblyline.common.identify import cart_ident, fileinfo, ident
from assemblyline.common.str_utils import safe_str
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import MaxExtractedExceeded, ServiceRequest
from assemblyline_v4_service.common.result import (
    Heuristic,
    Result,
    ResultSection,
    ResultTextSection,
)
from assemblyline_v4_service.common.utils import set_death_signal
from bs4 import BeautifulSoup
from cart import get_metadata_only, unpack_stream

from extract.ext.office_extract import (
    ExtractionError,
    PasswordError,
    extract_office_docs,
)
from extract.ext.repair_zip import BadZipfile, RepairZip
from extract.ext.xxxswf import xxxswf

DEBUG = False


class ExtractIgnored(Exception):
    pass


class Extract(ServiceBase):
    FORBIDDEN_WIN = [".text", ".rsrc", ".rdata", ".reloc", ".pdata", ".idata", "UPX", "file"]
    FORBIDDEN_ELF = [str(x) for x in range(20)]
    FORBIDDEN_ELF_SW = ["."]
    FORBIDDEN_MACH = ["__DATA__", "__LINKEDIT", "__TEXT__", "__PAGEZERO"]
    MAX_EXTRACT = 500
    MAX_EXTRACT_LIVE = 100

    LAUNCHABLE_EXTENSIONS = [
        ".ade",
        ".adp",
        ".as",  # Adobe ActionScript
        ".bat",  # DOS/Windows batch file
        ".chm",
        ".cmd",  # Windows command
        ".com",  # DOS command
        ".cpl",
        ".exe",  # DOS/Windows executable
        ".dll",  # Windows library
        ".hta",
        ".inf",  # Windows autorun file
        ".ins",
        ".isp",
        ".jar",  # Java JAR
        ".jse",
        ".js",  # Javascript
        ".lib",
        ".lnk",  # Windows shortcut
        ".mde",
        ".msc",
        ".msp",
        ".mst",
        ".pif",
        ".py",  # Python script
        ".scr",  # Windows screen saver
        ".sct",
        ".shb",
        ".sys",
        ".vb",  # VB Script
        ".vbe",  # Encrypted VB script
        ".vbs",  # VB Script
        ".vxd",
        ".wsc",
        ".wsf",
        ".wsh",
    ]

    def __init__(self, config=None):
        super().__init__(config)
        self._last_password = None
        self.extract_methods = [
            self.extract_zip,
            self.extract_tnef,
            self.extract_swf,
            self.extract_ace,
            self.repair_zip,
            self.extract_office,
            self.extract_pdf,
            self.extract_vbe,
            self.extract_onenote,
            self.extract_script,
        ]
        self.anomaly_detections = [self.archive_with_executables, self.archive_is_arc]
        self.safelisting_methods = [self.jar_safelisting, self.ipa_safelisting]
        self.is_ipa = False
        self.sha = None

    def execute(self, request: ServiceRequest):
        """Main Module. See README for details."""
        result = Result()
        self.sha = request.sha256
        continue_after_extract = request.get_param("continue_after_extract")
        self._last_password = None
        local = request.file_path
        password_protected = False
        safelisted = 0
        symlinks = []

        # Check if the file itself is archive/cart
        if cart_ident(request.file_path) != "corrupted/cart":
            self.log.info("File is cARTed. Will be un-cARTed and processed")
            uncart_output = tempfile.NamedTemporaryFile()

            with open(request.file_path, "rb") as ifile, open(uncart_output.name, "wb") as ofile:
                unpack_stream(ifile, ofile)

            # Proceed extract process as uncarted file
            request.file_name = get_metadata_only(request.file_path)["name"]
            request.file_type = fileinfo(uncart_output.name)["type"]
            local = uncart_output.name

        try:
            password_protected, safelisted, symlinks = self.extract(request, local)
        except MaxExtractedExceeded as e:
            result.add_section(ResultSection(str(e)))
        except ExtractIgnored as e:
            result.add_section(ResultSection(str(e)))
        except ExtractionError as ee:
            # If we don't support the encryption method. This will tell us what we need to add support for
            result.add_section(
                ResultSection(f"Password protected file, could not extract: {str(ee)}", heuristic=Heuristic(12))
            )

        num_extracted = len(request.extracted)

        section = None
        if num_extracted == 0 and password_protected:
            section = ResultTextSection("Failed to extract password protected file.", heuristic=Heuristic(12))
            section.add_tag("file.behavior", "Archive Unknown Password")
            if zipfile.is_zipfile(request.file_path):
                try:
                    with zipfile.ZipFile(request.file_path, "r") as z:
                        section.add_line("Files in password protected zip archive:")
                        for name in z.namelist():
                            section.add_line(name)
                            section.add_tag("file.name.extracted", name)
                except Exception:
                    pass
            if not request.file_type.startswith("executable"):
                # Don't drop executables that contain password protected zip sections
                request.drop()

        elif num_extracted != 0:
            if password_protected and self._last_password is not None:
                section = ResultSection(
                    f"Successfully extracted {num_extracted} "
                    f"file{'s' if num_extracted > 1 else ''} "
                    f"using password: {self._last_password}"
                )
                section.add_tag("info.password", self._last_password)

            elif password_protected and self._last_password is None:
                pw_list = " | ".join(self.get_passwords(request))
                section = ResultSection(
                    f"Successfully extracted {num_extracted} "
                    f"file{'s' if num_extracted > 1 else ''} "
                    f"using one of the following passwords: {pw_list}"
                )

            elif safelisted != 0:
                section = ResultSection(
                    f"Successfully extracted {num_extracted} "
                    f"file{'s' if num_extracted > 1 else ''} "
                    f"out of {safelisted + num_extracted}. The other {safelisted} "
                    f"file{'s' if safelisted > 1 else ''} were safelisted"
                )

            else:
                section = ResultTextSection(
                    f"Successfully extracted {num_extracted} file{'s' if num_extracted > 1 else ''}"
                )
                for extracted in request.extracted:
                    section.add_line(extracted["name"])
                    section.add_tag("file.name.extracted", extracted["name"])

            if request.file_type.startswith("executable"):
                section.set_heuristic(2)
            elif request.file_type.startswith("java"):
                section.set_heuristic(3)
            elif request.file_type.startswith("android"):
                section.set_heuristic(4)
            elif request.file_type.startswith("document/office"):
                section.set_heuristic(6)
            elif request.file_type.startswith("document/pdf"):
                section.set_heuristic(7)
            elif request.file_type.startswith("archive/audiovisual/flash"):
                section.set_heuristic(8)
            elif request.file_type.startswith("code/vbe"):
                section.set_heuristic(11)
            elif request.file_type.startswith("ios/ipa"):
                section.set_heuristic(9)
            elif password_protected:
                section.set_heuristic(10)
            else:
                section.set_heuristic(1)

            few_small_files_only = os.path.getsize(request.file_path) > self.config.get(
                "small_size_bypass_drop", 10485760
            ) and num_extracted <= self.config.get("max_file_count_bypass_drop", 5)

            if (
                not few_small_files_only
                and not request.file_type.startswith("executable")
                and not request.file_type.startswith("java")
                and not request.file_type.startswith("android")
                and not request.file_type.startswith("document")
                and not request.file_type.startswith("ios/ipa")
                and not request.file_type.startswith("code/html")
                and not continue_after_extract
            ):
                request.drop()

        if section is not None:
            if symlinks:
                syslink_section = ResultTextSection(f"{len(symlinks)} Symlink(s) Found")
                syslink_section.add_lines(symlinks)
                syslink_section.set_heuristic(15)
                section.add_subsection(syslink_section)
            result.add_section(section)

        for anomaly in self.anomaly_detections:
            anomaly(request, result)

        request.result = result

    def extract(self, request: ServiceRequest, local: str):
        """Iterate through extraction methods to extract archived, embedded or encrypted content from a sample.

        Args:
            request: AL request object.
            local: File path of AL sample.

        Returns:
            True if archive is password protected, and number of white-listed embedded files.
        """
        encoding = request.file_type.replace("archive/", "")
        password_protected = False
        safelisted_count = 0
        extracted = []

        # Try all extracting methods
        for extract_method in self.extract_methods:
            # noinspection PyArgumentList
            extracted, temp_password_protected = extract_method(request, local, encoding)
            if temp_password_protected:
                password_protected = temp_password_protected
            if extracted:
                for extracted_file in extracted:
                    extracted_file[-1] = f"Extracted using {extract_method.__name__}"
                break

        # Perform safelisting on request
        if extracted and request.get_param("use_custom_safelisting"):
            for safelisting_method in self.safelisting_methods:
                extracted, safelisted_count = safelisting_method(extracted, safelisted_count, encoding)

        extracted_count = len(extracted)
        symlinks = []
        for child in extracted:
            try:
                if os.path.islink(child[0]):
                    link_desc = f"{child[1]} -> {os.readlink(child[0])}"
                    symlinks.append(link_desc)
                    self.log.info(f"Symlink detected: {link_desc}")
                    extracted_count -= 1
                # If the file is not successfully added as extracted, then decrease the extracted file counter
                elif not request.add_extracted(*child, safelist_interface=self.api_interface):
                    extracted_count -= 1
                    safelisted_count += 1
            except MaxExtractedExceeded:
                raise MaxExtractedExceeded(
                    f"This file contains {extracted_count} extracted files, exceeding the "
                    f"maximum of {request.max_extracted} extracted files allowed. "
                    "None of the files were extracted."
                )

        return password_protected, safelisted_count, symlinks

    def get_passwords(self, request: ServiceRequest):
        """
        Create list of possible password strings to be used against AL sample if encryption is detected.

        Uses service configuration variable 'DEFAULT_PW_LIST';
        submission parameter 'password' (if supplied);
        content of email body (if 'email_body' is in submission tags);
        and any passwords passed by other services in the submission tags.

        Args:
            request: AL request object.

        Returns:
            List of strings.
        """
        passwords = deepcopy(self.config.get("default_pw_list", []))
        user_supplied = request.get_param("password")
        if user_supplied:
            passwords.append(user_supplied)

        if "email_body" in request.temp_submission_data:
            passwords.extend(request.temp_submission_data["email_body"])
        if "passwords" in request.temp_submission_data:
            passwords.extend(request.temp_submission_data["passwords"])

        return passwords

    # noinspection PyCallingNonCallable
    def repair_zip(self, _: ServiceRequest, local: str, encoding: str):
        """Attempts to use modules in repair_zip.py when a possible corruption of ZIP archive has been detected.

        Args:
            _: Unused AL request object.
            local: File path of AL sample.
            encoding: AL tag with string 'archive/' replaced.

        Returns:
            List containing repaired zip path, encoding, and display name "repaired_zip_file.zip", or a blank list if
            repair failed; and False as encryption will not be detected.
        """
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
                                except EOFError:
                                    # Unable to read path
                                    pass

                return [[out_name, "repaired_zip_file.zip", encoding]], False
        except ValueError:
            return [], False
        except NotImplementedError:
            # Compression type 99 is not implemented in python zipfile
            return [], False

    # noinspection PyCallingNonCallable
    def extract_office(self, request: ServiceRequest, local, encoding: str):
        """Will attempt to use modules in office_extract.py to extract a document from an encrypted Office file.

        Args:
            request: AL request object.
            local: File path of AL sample.
            encoding: AL tag with string 'archive/' replaced.

        Returns:
            List containing decoded file path, encoding, and display name "[orig FH name]", or a blank list if
            decryption failed; and True if encryption successful (indicating encryption detected).
        """
        # When encrypted, AL will identify the document as a passwordprotected office type.
        if request.file_type != "document/office/passwordprotected":
            return [], False

        passwords = self.get_passwords(request)
        try:
            res = extract_office_docs(local, passwords, self.working_directory)

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
        display_name = request.file_name
        return [[out_name, display_name, encoding]], True

    def _7zip_submit_extracted(self, request: ServiceRequest, path: str, encoding: str):
        """Will attempt to use 7zip library to extract content from a generic archive or PE file.

        Args:
            request AL request object.
            path: File path of AL sample.
            encoding: AL tag with string 'archive/' replaced.

        Returns:
            List containing extracted file information, including: extracted path, encoding, and display name
            or a blank list if extraction failed.
        """

        def ascii_sanitize(input: str):
            split_input = input.split("/")
            if len(split_input) > 1:
                for index in range(len(split_input)):
                    split_input[index] = ascii_sanitize(split_input[index])
                return "/".join(split_input)
            else:
                ext = f".{input.split('.')[1]}" if len(input.split(".")) > 1 else ""
                try:
                    return input.encode("ascii").decode()
                except UnicodeEncodeError:
                    return f"{''.join([random.choice(string.ascii_lowercase) for _ in range(5)])}{ext}"

        extract_executable_sections = request.get_param("extract_executable_sections")
        extracted_children = []

        # Fix problems with directory
        changes_made = True
        while changes_made:
            for root, _, files in os.walk(path):
                # Sanitize root
                new_root = ascii_sanitize(root)
                if new_root != root:
                    # Implies there was a correction made to path, copy contents to new directory
                    shutil.copytree(root, new_root)
                    shutil.rmtree(root)
                    changes_made = True
                    break
                for f in files:
                    file_path = os.path.join(root, f)
                    # Sanitize filename
                    new_file_path = ascii_sanitize(file_path)
                    if file_path != new_file_path:
                        shutil.move(file_path, new_file_path)
                changes_made = False

        # Add Extracted
        for root, _, files in os.walk(path):
            for f in files:
                skip = False
                filename = safe_str(os.path.join(root, f).replace(path, ""))
                if filename.startswith("/"):
                    filename = filename[1:]
                if not extract_executable_sections and encoding.startswith("executable"):
                    if "windows" in encoding:
                        for forbidden in self.FORBIDDEN_WIN:
                            if filename.startswith(forbidden):
                                skip = True
                                break

                    elif "linux" in encoding:
                        if filename in self.FORBIDDEN_ELF:
                            skip = True
                        for forbidden in self.FORBIDDEN_ELF_SW:
                            if filename.startswith(forbidden):
                                skip = True
                                break

                    elif "mach-o" in encoding:
                        for forbidden in self.FORBIDDEN_MACH:
                            if filename.startswith(forbidden):
                                skip = True
                                break
                if not skip:
                    extracted_children.append([os.path.join(root, f), safe_str(filename), encoding])
                else:
                    self.log.debug(f"File '{filename}' skipped because extract_executable_sections is turned off")

        return extracted_children

    def extract_ace(self, request: ServiceRequest, local, encoding):
        """Will attempt to use command-line tool unace to extract content from an ACE archive.

        Args:
            request: AL request object.
            local: File path of AL sample.
            encoding: AL tag with string 'archive/' replaced.

        Returns:
            List containing extracted file information, including: extracted path, encoding, and display name,
            or a blank list if extraction failed; and True if encryption with password detected.
        """
        if encoding != "ace":
            return [], False

        path = os.path.join(self.working_directory, "extracted_ace")
        try:
            os.mkdir(path)
        except OSError:
            pass

        # noinspection PyBroadException
        try:
            with tempfile.NamedTemporaryFile(suffix=".ace", dir=path, delete=False) as tf:
                # unace needs the .ace file extension
                with open(local, "rb") as fh:
                    tf.write(fh.read())
                    tf.flush()

                proc = subprocess.run(
                    f"/usr/bin/unace e -y {tf.name}",
                    timeout=2 * self.service_attributes.timeout / 3,
                    capture_output=True,
                    cwd=path,
                    env=os.environ,
                    shell=True,
                    preexec_fn=set_death_signal(),
                )
                stdoutput = proc.stdout

            if stdoutput:
                extracted_children = []
                if b"extracted:" in stdoutput:
                    for line in stdoutput.splitlines():
                        line = line.strip()
                        m = re.match(b"extracting (.+?)[ ]*(CRC OK)?$", line)
                        if not m:
                            continue

                        filename = safe_str(m.group(1))
                        filepath = safe_str(os.path.join(path, filename))
                        if os.path.isdir(filepath):
                            continue
                        else:
                            extracted_children.append([filepath, filename, encoding])

                return extracted_children, False

        except ExtractIgnored:
            raise
        except Exception:
            self.log.exception(f"While extracting {request.sha256} with unace")

        return [], False

    def extract_pdf(self, _: ServiceRequest, local, encoding):
        """Will attempt to use command-line tool pdfdetach to extract embedded files from a PDF sample.

        Args:
            _: AL request object.
            local: File path of AL sample.
            encoding: AL tag with string 'archive/' replaced.

        Returns:
            List containing extracted file information, including: extracted path, encoding, and display name,
            or a blank list if extraction failed or no embedded files are detected; and False as no passwords will
            ever be detected.
        """
        extracted_children = []

        if encoding == "document/pdf":
            output_path = os.path.join(self.working_directory, "extracted_pdf")
            if not os.path.exists(output_path):
                os.makedirs(output_path)

            env = os.environ.copy()
            env["LANG"] = "en_US.UTF-8"

            # noinspection PyBroadException
            try:
                subprocess.run(["pdfdetach", "-saveall", "-o", output_path, local], env=env, capture_output=True)
            except Exception:
                self.log.error("Extract service needs poppler-utils to extract embedded PDF files.")
                return extracted_children, False

            files = (
                filename for filename in os.listdir(output_path) if os.path.isfile(os.path.join(output_path, filename))
            )

            for filename in files:
                extracted_children.append([output_path + "/" + filename, safe_str(filename), encoding])

        return extracted_children, False

    # noinspection PyBroadException
    def decode_vbe(self, data):
        """Will attempt to decode VBE script. Modified code that was written by Didier Stevens, found here:
        https://blog.didierstevens.com/2016/03/29/decoding-vbe/

        Args:
            data: VBE content.

        Returns:
            Decoded script if successful, or None.
        """
        try:
            # fmt: off
            d_decode = {
                9: "\x57\x6E\x7B", 10: "\x4A\x4C\x41", 11: "\x0B\x0B\x0B", 12: "\x0C\x0C\x0C",
                13: "\x4A\x4C\x41", 14: "\x0E\x0E\x0E", 15: "\x0F\x0F\x0F", 16: "\x10\x10\x10",
                17: "\x11\x11\x11", 18: "\x12\x12\x12", 19: "\x13\x13\x13", 20: "\x14\x14\x14",
                21: "\x15\x15\x15", 22: "\x16\x16\x16", 23: "\x17\x17\x17", 24: "\x18\x18\x18",
                25: "\x19\x19\x19", 26: "\x1A\x1A\x1A", 27: "\x1B\x1B\x1B", 28: "\x1C\x1C\x1C",
                29: "\x1D\x1D\x1D", 30: "\x1E\x1E\x1E", 31: "\x1F\x1F\x1F", 32: "\x2E\x2D\x32",
                33: "\x47\x75\x30", 34: "\x7A\x52\x21", 35: "\x56\x60\x29", 36: "\x42\x71\x5B",
                37: "\x6A\x5E\x38", 38: "\x2F\x49\x33", 39: "\x26\x5C\x3D", 40: "\x49\x62\x58",
                41: "\x41\x7D\x3A", 42: "\x34\x29\x35", 43: "\x32\x36\x65", 44: "\x5B\x20\x39",
                45: "\x76\x7C\x5C", 46: "\x72\x7A\x56", 47: "\x43\x7F\x73", 48: "\x38\x6B\x66",
                49: "\x39\x63\x4E", 50: "\x70\x33\x45", 51: "\x45\x2B\x6B", 52: "\x68\x68\x62",
                53: "\x71\x51\x59", 54: "\x4F\x66\x78", 55: "\x09\x76\x5E", 56: "\x62\x31\x7D",
                57: "\x44\x64\x4A", 58: "\x23\x54\x6D", 59: "\x75\x43\x71", 60: "\x4A\x4C\x41",
                61: "\x7E\x3A\x60", 62: "\x4A\x4C\x41", 63: "\x5E\x7E\x53", 64: "\x40\x4C\x40",
                65: "\x77\x45\x42", 66: "\x4A\x2C\x27", 67: "\x61\x2A\x48", 68: "\x5D\x74\x72",
                69: "\x22\x27\x75", 70: "\x4B\x37\x31", 71: "\x6F\x44\x37", 72: "\x4E\x79\x4D",
                73: "\x3B\x59\x52", 74: "\x4C\x2F\x22", 75: "\x50\x6F\x54", 76: "\x67\x26\x6A",
                77: "\x2A\x72\x47", 78: "\x7D\x6A\x64", 79: "\x74\x39\x2D", 80: "\x54\x7B\x20",
                81: "\x2B\x3F\x7F", 82: "\x2D\x38\x2E", 83: "\x2C\x77\x4C", 84: "\x30\x67\x5D",
                85: "\x6E\x53\x7E", 86: "\x6B\x47\x6C", 87: "\x66\x34\x6F", 88: "\x35\x78\x79",
                89: "\x25\x5D\x74", 90: "\x21\x30\x43", 91: "\x64\x23\x26", 92: "\x4D\x5A\x76",
                93: "\x52\x5B\x25", 94: "\x63\x6C\x24", 95: "\x3F\x48\x2B", 96: "\x7B\x55\x28",
                97: "\x78\x70\x23", 98: "\x29\x69\x41", 99: "\x28\x2E\x34", 100: "\x73\x4C\x09",
                101: "\x59\x21\x2A", 102: "\x33\x24\x44", 103: "\x7F\x4E\x3F", 104: "\x6D\x50\x77",
                105: "\x55\x09\x3B", 106: "\x53\x56\x55", 107: "\x7C\x73\x69", 108: "\x3A\x35\x61",
                109: "\x5F\x61\x63", 110: "\x65\x4B\x50", 111: "\x46\x58\x67", 112: "\x58\x3B\x51",
                113: "\x31\x57\x49", 114: "\x69\x22\x4F", 115: "\x6C\x6D\x46", 116: "\x5A\x4D\x68",
                117: "\x48\x25\x7C", 118: "\x27\x28\x36", 119: "\x5C\x46\x70", 120: "\x3D\x4A\x6E",
                121: "\x24\x32\x7A", 122: "\x79\x41\x2F", 123: "\x37\x3D\x5F", 124: "\x60\x5F\x4B",
                125: "\x51\x4F\x5A", 126: "\x20\x42\x2C", 127: "\x36\x65\x57",
            }

            d_combination = {
                0: 0, 1: 1, 2: 2, 3: 0, 4: 1, 5: 2, 6: 1, 7: 2,
                8: 2, 9: 1, 10: 2, 11: 1, 12: 0, 13: 2, 14: 1, 15: 2,
                16: 0, 17: 2, 18: 1, 19: 2, 20: 0, 21: 0, 22: 1, 23: 2,
                24: 2, 25: 1, 26: 0, 27: 2, 28: 1, 29: 2, 30: 2, 31: 1,
                32: 0, 33: 0, 34: 2, 35: 1, 36: 2, 37: 1, 38: 2, 39: 0,
                40: 2, 41: 0, 42: 0, 43: 1, 44: 2, 45: 0, 46: 2, 47: 1,
                48: 0, 49: 2, 50: 1, 51: 2, 52: 0, 53: 0, 54: 1, 55: 2,
                56: 2, 57: 0, 58: 0, 59: 1, 60: 2, 61: 0, 62: 2, 63: 1,
            }
            # fmt: on

            result = ""
            index = -1
            for char in (
                data.replace("@&", chr(10))
                .replace("@#", chr(13))
                .replace("@*", ">")
                .replace("@!", "<")
                .replace("@$", "@")
            ):
                byte = ord(char)
                if byte < 128:
                    index += 1
                if (byte == 9 or 31 < byte < 128) and byte != 60 and byte != 62 and byte != 64:
                    char = [c for c in d_decode[byte]][d_combination[index % 64]]
                result += char
            return result
        except Exception:
            result = None
            return result

    # noinspection PyBroadException
    def extract_vbe(self, _: ServiceRequest, local: str, encoding: str):
        """Will attempt to decode VBA code data from a VBE container.

        Args:
            _: Unused AL request object.
            local: File path of AL sample.
            encoding: AL tag with string 'archive/' replaced.

        Returns:
            List containing decoded file information, including: decoded file path, encoding, and display name,
            or a blank list if decode failed; and False (no passwords will ever be detected).
        """
        if encoding == "code/vbe":
            with open(local, "r") as fh:
                text = fh.read()
            try:
                # Ensure file format is correct via regex
                evbe_regex = re.compile(r"#@~\^......==(.+)......==\^#~@")
                evbe_present = re.search(evbe_regex, text)
                evbe_res = self.decode_vbe(evbe_present.groups()[0])
                if evbe_res and evbe_present != text:
                    path = os.path.join(self.working_directory, "extracted_vbe")
                    with open(path, "w") as f:
                        f.write(evbe_res)
                    return [[path, "vbe_decoded", encoding]], False
            except Exception:
                pass
        return [], False

    def extract_zip(self, request: ServiceRequest, local: str, encoding: str):
        """Will attempt to use 7zip (or zipfile) and then unrar to extract content from an archive, or sections from a Windows
        executable file.

        Args:
            request: AL request object.
            local: File path of AL sample.
            encoding: AL tag with string 'archive/' replaced.

        Returns:
            List containing extracted file information, including: extracted path, encoding, and display name,
            or a blank list if extraction failed; and True if encryption detected.
        """
        password_protected = False
        # If we cannot extract the file, we shouldn't pass it around. Let keep track of if we can't.
        password_failed = False
        if (
            request.file_type == "archive/audiovisual/flash"
            or encoding == "ace"
            or (request.file_type.startswith("document") and not request.file_type.startswith("document/installer"))
            or encoding == "tnef"
            or request.file_type.startswith("code")
        ):
            return [], password_protected
        path = os.path.join(self.working_directory, "extracted_zip")
        try:
            # Attempt extraction of zip
            try:
                # with 7z
                extracted_files, password_protected, password_failed = self.extract_zip_7zip(
                    request, local, encoding, path
                )
                if extracted_files:
                    return extracted_files, password_protected
            except UnicodeEncodeError:
                # with zipfile
                extracted_files, password_protected, password_failed = self.extract_zip_zipfile(
                    request, local, encoding, path
                )
                if extracted_files:
                    return extracted_files, password_protected
            except TypeError:
                pass

            # Try unrar if 7zip fails for rar archives
            if encoding == "rar":
                env = os.environ.copy()
                env["LANG"] = "C.UTF-8"

                password_protected = False

                # Resetting back to False because we are giving it another chance.
                password_failed = False
                shutil.rmtree(path, ignore_errors=True)
                os.mkdir(path)
                try:
                    p = subprocess.run(["unrar", "x", "-y", "-p-", local, path], env=env, capture_output=True)
                    stdout_rar, stderr_rar = p.stdout, p.stderr
                except OSError:
                    self.log.warning(
                        f"Error running unrar on sample {request.sha256}. Extract service may be out of date."
                    )
                    stdout_rar = None
                    stderr_rar = None
                if stdout_rar:
                    if b"All OK" in stdout_rar:
                        return self._7zip_submit_extracted(request, path, encoding), password_protected
                    if b"wrong password" in stderr_rar:
                        password_protected = True
                        password_list = self.get_passwords(request)
                        for password in password_list:
                            try:
                                shutil.rmtree(path, ignore_errors=True)
                                os.mkdir(path)
                                stdout = subprocess.run(
                                    ["unrar", "x", "-y", f"-p{password}", local, path], env=env, capture_output=True
                                ).stdout
                                if b"All OK" in stdout:
                                    self._last_password = password
                                    return self._7zip_submit_extracted(request, path, encoding), password_protected
                            except OSError:
                                pass
                    password_failed = True
        except ExtractIgnored:
            raise
        except Exception as e:
            if request.file_type != "archive/cab":
                self.log.exception(f"While extracting {request.sha256} with 7zip: {str(e)}")
        if password_failed and request.file_type.startswith("archive"):
            # stop processing the request
            request.drop()

        return [], password_protected

    def extract_zip_7zip(self, request: ServiceRequest, local: str, encoding: str, path: str):
        password_protected = False
        env = os.environ.copy()
        env["LANG"] = "C.UTF-8"

        try:
            p = subprocess.run(["7z", "x", "-p", "-y", local, f"-o{path}"], env=env, capture_output=True)
            stdoutput, stderr = p.stdout, p.stderr
            if stdoutput and any(
                stdoutput.strip().find(msg) > 0 for msg in [b"Everything is Ok", b"ERRORS:\nHeaders Error"]
            ):
                return self._7zip_submit_extracted(request, path, encoding), password_protected, False
            else:
                if b"Wrong password" in stderr:
                    password_protected = True
                    password_list = self.get_passwords(request)
                    for password in password_list:
                        try:
                            shutil.rmtree(path, ignore_errors=True)
                            p = subprocess.run(
                                ["7za", "x", f"-p{password}", f"-o{path}", local], env=env, capture_output=True
                            )
                            stdoutput = p.stdout + p.stderr
                            if stdoutput and b"\nEverything is Ok\n" in stdoutput:
                                self._last_password = password
                                return self._7zip_submit_extracted(request, path, encoding), password_protected, False
                        except OSError:
                            pass
                    return None, password_protected, True
                elif b"Can not open the file as archive" in stdoutput:
                    raise TypeError
        except UnicodeEncodeError:
            raise

    def extract_zip_zipfile(self, request: ServiceRequest, local: str, encoding: str, path: str):
        shutil.rmtree(path, ignore_errors=True)
        password_protected = False
        try:
            with zipfile.ZipFile(local, "r") as zipped_file:
                zipped_file.extractall(path=path)
            return self._7zip_submit_extracted(request, path, encoding), password_protected, False
        except RuntimeError as e:
            if any("password required for extraction" in event for event in e.args):
                # Try with available passwords
                password_protected = True
                password_list = self.get_passwords(request)
                for password in password_list:
                    try:
                        shutil.rmtree(path, ignore_errors=True)
                        with zipfile.ZipFile(local, "r") as zipped_file:
                            zipped_file.extractall(path=path, pwd=password.encode())
                        return self._7zip_submit_extracted(request, path, encoding), password_protected, False
                    except RuntimeError:
                        pass
                return None, password_protected, True
        except BadZipfile:
            self.log.warning("A non-zip file was passed to zipfile library")
            return None, password_protected, False

    def extract_swf(self, _: ServiceRequest, local: str, encoding: str):
        """Will attempt to extract compressed SWF files.

        Args:
            _: Unused AL request object.
            local: File path of AL sample.
            encoding: AL tag with string 'archive/' replaced.

        Returns:
            List containing extracted file information, including: extracted path, encoding, and display name,
            or a blank list if extract failed; and False (no passwords will ever be detected).
        """
        extracted_children = []

        if encoding == "audiovisual/flash":
            output_path = os.path.join(self.working_directory, "extracted_swf")
            if not os.path.exists(output_path):
                os.makedirs(output_path)

            files_found = []
            # noinspection PyBroadException
            try:
                swf = xxxswf()
                files_found = swf.extract(local, output_path)
            except ImportError:
                self.log.exception("Import error: pylzma library not installed.")
            except Exception:
                self.log.exception("Error occurred while trying to decompress swf...")

            for child in files_found:
                extracted_children.append([output_path + "/" + child, child, encoding])

        return extracted_children, False

    def extract_tnef(self, request: ServiceRequest, local: str, encoding: str):
        """Will attempt to extract data from a TNEF container.

        Args:
            request: AL request object.
            local: File path of AL sample.
            encoding: AL tag with string 'archive/' replaced.

        Returns:
            List containing extracted file information, including: extracted path, encoding, and display name,
            or a blank list if extract failed; and False (no passwords will ever be detected).
        """
        children = []

        if encoding != "tnef":
            return children, False

        # noinspection PyBroadException
        try:
            # noinspection PyUnresolvedReferences
            from tnefparse import tnef

            tnef_logger = logging.getLogger("tnef-decode")
            tnef_logger.setLevel(60)  # This completely turns off the TNEF logger

            count = 0
            with open(local, "rb") as f:
                content = f.read()
            if not content:
                return children, False
            parsed_tnef = tnef.TNEF(content)
            if parsed_tnef.body:
                temp_data_email_body = request.temp_submission_data.get("email_body", [])
                temp_data_email_body.extend(parsed_tnef.body.split())
                request.temp_submission_data["email_body"] = temp_data_email_body

            for a in parsed_tnef.attachments:
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
                except (AttributeError, UnicodeDecodeError):
                    name = f"unknown_tnef_{count}"

                if not name:
                    continue

                with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False) as tmp_f:
                    tmp_f.write(data)
                children.append([tmp_f.name, name, encoding])
        except ImportError:
            self.log.exception("Import error: tnefparse library not installed:")
        except Exception:
            self.log.exception("Error extracting from tnef file:")

        return children, False

    def ipa_safelisting(self, extracted, safelisted_count: int, encoding: str):
        """Filters file paths that are considered safelisted from a list of extracted IPA files.

        Args:
            extracted: List of extracted file information, including: extracted path, encoding, and display name.
            safelisted_count: Current safelist count.
            encoding: AL tag with string 'archive/' replaced.

        Returns:
            List of filtered file names and updated count of safelisted files.
        """
        if encoding == "ios/ipa":
            safelisted_fname_regex = [
                re.compile(r".app/.*\.plist$"),
                re.compile(r".app/.*\.nib$"),
                re.compile(r".app/.*/PkgInfo$"),
            ]

            ipa_filter_count = safelisted_count
            tmp_new_files = []

            for cur_file in extracted:
                to_add = True
                for ext in safelisted_fname_regex:
                    if ext.search(cur_file[0]):
                        to_add = False
                        ipa_filter_count += 1

                if to_add:
                    tmp_new_files.append(cur_file)

            return tmp_new_files, ipa_filter_count
        else:
            return extracted, safelisted_count

    def jar_safelisting(self, extracted, safelisted_count: int, encoding: str):
        """Filters file paths that are considered safelisted from a list of extracted JAR files.

        Args:
            extracted: List of extracted file information, including: extracted path, encoding, and display name.
            safelisted_count: Current safelist count.
            encoding: AL tag with string 'archive/' replaced.

        Returns:
            List of filtered file names and updated count of safelisted files.
        """
        if encoding == "java/jar" or encoding == "android/apk":
            safelisted_tags_re = [
                re.compile(r"android/(xml|dex|resource)"),
                re.compile(r"audiovisual/.*"),
                re.compile(r"certificate/rsa"),
                re.compile(r"code/.*"),
                re.compile(r"db/.*"),
                re.compile(r"font/.*"),
                re.compile(r"image/.*"),
                re.compile(r"java/(class|manifest|jbdiff|signature)"),
                re.compile(r"resource/.*"),
            ]

            safelisted_mime_re = [
                re.compile(r"text/plain"),
                re.compile(r"text/x-c"),
            ]

            safelisted_fname_regex = [
                # commonly used libs files
                re.compile(r"com/google/i18n/phonenumbers/data/(PhoneNumber|ShortNumber)[a-zA-Z]*_[0-9A-Z]{1,3}$"),
                re.compile(r"looksery/([a-zA-Z_]*/){1,5}[a-zA-Z0-9_.]*.glsl$"),
                re.compile(r"org/apache/commons/codec/language/bm/[a-zA-Z0-9_.]*\.txt$"),
                re.compile(r"org/joda/time/format/messages([a-zA-Z_]{0,3})\.properties$"),
                re.compile(r"org/joda/time/tz/data/[a-zA-Z0-9_/\-+]*$"),
                re.compile(r"sharedassets[0-9]{1,3}\.assets(\.split[0-9]{1,3})?$"),
                re.compile(r"zoneinfo(-global)?/([a-zA-Z_\-]*/){1,2}[a-zA-Z_\-]*\.ics$"),
                # noisy files
                re.compile(r"assets/.*\.atf$"),
                re.compile(r"assets/.*\.ffa$"),
                re.compile(r"assets/.*\.ffm$"),
                re.compile(r"assets/.*\.jsa$"),
                re.compile(r"assets/.*\.lua$"),
                re.compile(r"assets/.*\.pf$"),
            ]

            jar_filter_count = safelisted_count
            tmp_new_files = []

            for cur_file in extracted:
                f = open(cur_file[0], "rb")
                byte_block = f.read(65535 * 2)
                f.close()

                to_add = True
                file_info = ident(byte_block, len(byte_block), cur_file[0])
                for exp in safelisted_tags_re:
                    if exp.search(file_info["type"]):
                        if DEBUG:
                            print("T", file_info["type"], file_info["ascii"], cur_file[0])
                        to_add = False
                        jar_filter_count += 1

                if to_add and file_info["mime"]:
                    for exp in safelisted_mime_re:
                        if exp.search(file_info["mime"]):
                            if DEBUG:
                                print("M", file_info["mime"], file_info["ascii"], cur_file[0])
                            to_add = False
                            jar_filter_count += 1

                if to_add:
                    for ext in safelisted_fname_regex:
                        if ext.search(cur_file[0]):
                            if DEBUG:
                                print("F", ext.pattern, file_info["ascii"], cur_file[0])
                            to_add = False
                            jar_filter_count += 1

                if to_add:
                    tmp_new_files.append(cur_file)

            return tmp_new_files, jar_filter_count
        else:
            return extracted, safelisted_count

    def archive_with_executables(self, request: ServiceRequest, result: Result):
        """Detects executable files contained in an archive using the service's LAUNCHABLE_EXTENSIONS list.

        Args:
            request: AL request object.
            result: AL result object.

        Returns:
            Al result object scoring VHIGH if executables detected in container, or None.
        """
        if (
            len(request.extracted) == 1
            and os.path.splitext(request.extracted[0]["name"])[1].lower() in Extract.LAUNCHABLE_EXTENSIONS
        ):

            new_section = ResultTextSection("Archive file with single executable inside. Potentially malicious...")
            new_section.add_line(request.extracted[0]["name"])
            new_section.add_tag("file.name.extracted", request.extracted[0]["name"])
            new_section.set_heuristic(13)
            new_section.add_tag("file.behavior", "Archived Single Executable")
            result.add_section(new_section)
        else:
            lunchable_extracted = []
            for extracted in request.extracted:
                if os.path.splitext(extracted["name"])[1].lower() in Extract.LAUNCHABLE_EXTENSIONS:
                    lunchable_extracted.append(extracted)
            if lunchable_extracted:
                new_section = ResultTextSection("Executable Content in Archive. Potentially malicious...")
                new_section.add_tag("file.behavior", "Executable Content in Archive")
                for extracted in lunchable_extracted:
                    new_section.add_line(extracted["name"])
                    new_section.add_tag("file.name.extracted", extracted["name"])
                if len(request.extracted) <= self.config.get("heur16_max_file_count", 5):
                    new_section.set_heuristic(16)

                result.add_section(new_section)

    def archive_is_arc(self, request: ServiceRequest, result):
        """Uses AL tag to determine if container is an ACE archive.

        Args:
            request: AL request object.
            result: AL result object.

        Returns:
            Al result object scoring VHIGH if sample type is ACE container, or None.
        """
        if request.file_type == "archive/ace":
            new_section = ResultSection("Uncommon format: archive/ace")
            new_section.set_heuristic(14)
            new_section.add_tag("file.behavior", "Uncommon format: archive/ace")
            result.add_section(new_section)

    def extract_onenote(self, request: ServiceRequest, local: str, encoding: str):
        """Extract embedded files from OneNote (.one) files

        Args:
            request: Unused AL request object.
            local: File path of AL sample.
            encoding: AL tag with string 'archive/' replaced.

        Returns:
            List containing extracted attachment information, including: extracted path, display name, encoding;
            and False (no encryption will be detected).
        """
        if encoding != "document/office/onenote":
            return [], False
        with open(local, "rb") as f:
            data = f.read()
        # From MS-ONESTORE FileDataStoreObject definition
        # https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-onestore/8806fd18-6735-4874-b111-227b83eaac26
        # guidHeader:  {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}
        # guidFooter:  {71FBA722-0F79-4A0B-BB13-899256426B24}
        # Note: the first 3 fields are stored little-endian so the bytes are in reverse order in the document.
        embedded_files = re.findall(
            b"(?s)\xE7\x16\xE3\xBD\x65\x26\x11\x45\xA4\xC4\x8D\x4D\x0B\x7A\x9E\xAC"
            b".{20}(.*?)\x22\xA7\xFB\x71\x79\x0F\x0B\x4A\xBB\x13\x89\x92\x56\x42\x6B\\\x24",
            data,
        )
        extracted = []
        for embedded in embedded_files:
            with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False) as out:
                out.write(embedded)
            extracted.append([out.name, hashlib.sha256(embedded).hexdigest(), encoding])
        return extracted, False

    def extract_script(self, request: ServiceRequest, local: str, encoding: str):
        """Extract embedded scripts from HTML documents

        Args:
            request: Unused AL request object.
            local: File path of AL sample.
            encoding: AL tag with string 'archive/' replaced.

        Returns:
            List containing extracted script information, including: extracted path, display name, encoding;
            and False (no encryption will be detected).
        """
        if encoding not in ["code/hta", "code/html"]:
            return [], False
        with open(local, "rb") as f:
            data = f.read()

        soup = BeautifulSoup(data, features="html5lib")
        scripts = soup.findAll("script")
        extracted = []
        for script in scripts:
            if script.string is None:
                continue
            encoded_script = str(script.string).encode()
            with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False) as out:
                out.write(encoded_script)
            extracted.append([out.name, hashlib.sha256(encoded_script).hexdigest(), encoding])
        return extracted, False
