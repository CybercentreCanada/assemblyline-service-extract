import hashlib
import itertools
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
import zlib
from copy import deepcopy
from datetime import datetime
from io import BytesIO

import pefile
from assemblyline.common import forge
from assemblyline.common.entropy import BufferedCalculator
from assemblyline.common.identify import cart_ident
from assemblyline.common.str_utils import safe_str
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import MaxExtractedExceeded, ServiceRequest
from assemblyline_v4_service.common.result import (
    Heuristic,
    Result,
    ResultKeyValueSection,
    ResultOrderedKeyValueSection,
    ResultSection,
    ResultTableSection,
    ResultTextSection,
    TableRow,
)
from assemblyline_v4_service.common.utils import (
    PASSWORD_WORDS,
    extract_passwords,
    set_death_signal,
)
from bs4 import BeautifulSoup
from bs4.element import Comment
from cart import get_metadata_only, unpack_stream
from msoffcrypto import exceptions as msoffcryptoexceptions
from nrs.nsi.extractor import Extractor as NSIExtractor
from pikepdf import PasswordError as PDFPasswordError
from pikepdf import Pdf, PdfError

from extract.ext.office_extract import (
    ExtractionError,
    PasswordError,
    extract_office_docs,
)
from extract.ext.repair_zip import BadZipfile, RepairZip
from extract.ext.xxuudecode import decode_from_file as xxuu_decode_from_file
from extract.ext.xxuudecode import uu_character, xx_character
from extract.ext.xxxswf import xxxswf

EVBE_REGEX = re.compile(r"#@~\^......==(.+)......==\^#~@")


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
        ".url",  # Windows URL Shortcut
        ".vb",  # VB Script
        ".vbe",  # Encrypted VB script
        ".vbs",  # VB Script
        ".vxd",
        ".wsc",
        ".wsf",
        ".wsh",
    ]

    LAUNCHABLE_TYPE = [
        "code/batch",
        "code/ps1",
        "code/python",
        "code/vbs",
    ]

    LAUNCHABLE_TYPE_SW = ["executable/", "shortcut/"]

    LAUNCHABLE_TYPE_FP = [
        "executable/windows/com",
        "executable/windows/dos",
    ]

    def __init__(self, config=None):
        super().__init__(config)
        self.password_used = []
        self.identify = forge.get_identify(use_cache=os.environ.get("PRIVILEGED", "false").lower() == "true")

    def execute(self, request: ServiceRequest):
        result = Result()
        request.result = result
        self.password_used = []
        password_protected = False
        safelisted_extracted = []
        symlinks = []
        extracted = []
        summary_section_heuristic = None

        if request.file_type == "archive/nsis":
            extracted = self.extract_nsis(request)
            summary_section_heuristic = 1
        elif request.file_type == "archive/tnef":
            extracted = self.extract_tnef(request)
            summary_section_heuristic = 1
        elif request.file_type == "archive/ace":
            extracted = self.extract_ace(request)
            summary_section_heuristic = 1

            new_section = ResultSection("Uncommon format: archive/ace")
            new_section.set_heuristic(14)
            new_section.add_tag("file.behavior", "Uncommon format: archive/ace")
            request.result.add_section(new_section)
        elif request.file_type == "archive/audiovisual/flash":
            extracted = self.extract_swf(request)
            summary_section_heuristic = 8
        elif request.file_type == "archive/xxe":
            extracted = self.extract_xxe(request)
            summary_section_heuristic = 1
        elif request.file_type == "archive/uue":
            extracted = self.extract_uue(request)
            summary_section_heuristic = 1
        elif request.file_type == "code/vbe":
            extracted = self.extract_vbe(request)
            summary_section_heuristic = 11
        elif request.file_type == "document/office/onenote":
            extracted = self.extract_onenote(request)
        elif request.file_type == "document/office/passwordprotected":
            extracted, password_protected = self.extract_office(request)
            if password_protected:
                summary_section_heuristic = 6
        elif request.file_type == "document/pdf/passwordprotected":
            extracted, password_protected = self.extract_pdf_passwordprotected(request)
            summary_section_heuristic = 7
        elif request.file_type == "document/pdf":
            extracted = self.extract_pdf(request)
            summary_section_heuristic = 7
        elif request.file_type in ["code/hta", "code/html"]:
            extracted = self.extract_jscript(request)
        elif request.file_type == "code/wsf":
            extracted = self.extract_wsf(request)
        elif request.file_type == "archive/cart" and cart_ident(request.file_path) != "corrupted/cart":
            extracted = self.extract_cart(request)
            summary_section_heuristic = 1
        elif request.file_type == "archive/rar":
            extracted, password_protected = self.extract_zip(request)
            summary_section_heuristic = 1
        elif request.file_type in ["archive/zip", "archive/7-zip"]:
            extracted, password_protected = self.extract_zip(request)
            summary_section_heuristic = 1
        elif request.file_type == "archive/zlib":
            extracted = self.extract_zlib(request)
            summary_section_heuristic = 1
        elif request.file_type == "ios/ipa":
            extracted, password_protected = self.extract_zip(request)
            summary_section_heuristic = 9
            if extracted and request.get_param("use_custom_safelisting"):
                extracted, safelisted_extracted = self.ipa_safelisting(extracted, safelisted_extracted)
        elif request.file_type.startswith("java/"):
            extracted, password_protected = self.extract_zip(request)
            summary_section_heuristic = 3
            if request.file_type == "java/jar" and extracted and request.get_param("use_custom_safelisting"):
                extracted, safelisted_extracted = self.jar_safelisting(extracted, safelisted_extracted)
        elif request.file_type.startswith("android"):
            extracted, password_protected = self.extract_zip(request)
            summary_section_heuristic = 4
            if request.file_type == "android/apk" and extracted and request.get_param("use_custom_safelisting"):
                extracted, safelisted_extracted = self.jar_safelisting(extracted, safelisted_extracted)
        elif request.file_type.startswith("archive/"):
            extracted, password_protected = self.extract_zip(request)
            summary_section_heuristic = 1
        elif request.file_type.startswith("executable/"):
            strip_overlay_result = self.strip_overlay(request.file_path)
            if strip_overlay_result:
                temp_path, overlay_size, entropy = strip_overlay_result
                added = request.add_extracted(
                    temp_path,
                    os.path.basename(request.file_path),
                    f"Executable bloat stripped from original file {os.path.basename(request.file_path)}",
                    safelist_interface=self.api_interface,
                )

                heur = Heuristic(22)
                heur_section = ResultSection(heur.name, heuristic=heur, parent=request.result)
                heur_section.add_line(f"Overlay Size: {overlay_size}")
                heur_section.add_line(f"Overlay Entropy: {entropy}")
                if not added:
                    heur_section.add_line(f"{os.path.basename(request.file_path)} is safelisted once de-bloated")
                # Drop the request so that no other module are going to analyze it.
                request.drop()
                return
            extracted, password_protected = self.extract_zip(request)
            summary_section_heuristic = 2
        else:
            extracted, password_protected = self.extract_zip(request)
            summary_section_heuristic = 19

        # For the time being, always try repair_zip, and see if we have any results
        if not extracted:
            extracted = self.repair_zip(request)

        extracted_files = []
        for child in sorted(extracted, key=lambda x: x[1]):
            try:
                file_path = child[0]
                if os.path.islink(file_path):
                    link_desc = f"{child[1]} -> {os.readlink(file_path)}"
                    symlinks.append(link_desc)
                else:
                    # Start by stripping the file.
                    if os.path.getsize(file_path) > self.config.get("heur22_min_overlay_size", 31457280):
                        extracted_file_info = self.identify.fileinfo(file_path)
                        # TODO: KEEP THE ORIGINAL FILE HASH
                        if extracted_file_info["type"].startswith("executable/windows"):
                            strip_overlay_result = self.strip_overlay(file_path)
                            if strip_overlay_result:
                                file_path, overlay_size, entropy = strip_overlay_result
                                heur = Heuristic(22)
                                heur_section = ResultOrderedKeyValueSection(
                                    heur.name, heuristic=heur, parent=request.result
                                )
                                heur_section.add_item("Target file", child[1])
                                heur_section.add_item("Overlay Size", overlay_size)
                                heur_section.add_item("Overlay Entropy", entropy)
                                heur_section.add_item("SHA256", extracted_file_info["sha256"])
                                heur_section.add_item("SHA1", extracted_file_info["sha1"])
                                heur_section.add_item("MD5", extracted_file_info["md5"])
                                heur_section.add_item("SSDEEP", extracted_file_info["ssdeep"])
                                heur_section.add_item("Total Size", extracted_file_info["size"])
                        else:
                            # Reuse the target overlay size to check for general bloating
                            calculator = BufferedCalculator()
                            with open(file_path, "rb") as f:
                                f.seek(os.path.getsize(file_path) // 2)
                                while True:
                                    data = f.read(1024)
                                    if not data:
                                        break
                                    calculator.update(data)
                            entropy = calculator.entropy()

                            if entropy < self.config.get("heur22_min_general_bloat_entropy", 0.2):
                                # Padding detected in a general file, determine byte-padding
                                with open(file_path, "rb") as f:
                                    f.seek(-1024, os.SEEK_END)
                                    last_data = f.read(1024)
                                    last_position_jumps = 2
                                    f.seek(-1024 * last_position_jumps, os.SEEK_END)
                                    while f.read(1024) == last_data:
                                        last_position_jumps += 1
                                        f.seek(-1024 * last_position_jumps, os.SEEK_END)
                                    # Time to find exactly where to stop the stripping
                                    precise_offset = 1024
                                    while precise_offset >= 0:
                                        f.seek(-1024 * last_position_jumps + precise_offset, os.SEEK_END)
                                        data = f.read(1)
                                        if data and data[0] != last_data[0]:
                                            break
                                        precise_offset -= 1
                                    overlay_size = 1024 * last_position_jumps - precise_offset - 1

                                    f.seek(0)
                                    data = f.read(os.path.getsize(file_path) - overlay_size)

                                sha256hash = hashlib.sha256(data).hexdigest()
                                file_path = os.path.join(self.working_directory, sha256hash)
                                with open(file_path, "wb") as f:
                                    f.write(data)

                                heur = Heuristic(22)
                                heur_section = ResultOrderedKeyValueSection(
                                    heur.name, heuristic=heur, parent=request.result
                                )
                                heur_section.add_item("Target file", child[1])
                                heur_section.add_item("Overlay Size", overlay_size)
                                heur_section.add_item("Overlay Entropy", entropy)
                                heur_section.add_item("SHA256", extracted_file_info["sha256"])
                                heur_section.add_item("SHA1", extracted_file_info["sha1"])
                                heur_section.add_item("MD5", extracted_file_info["md5"])
                                heur_section.add_item("SSDEEP", extracted_file_info["ssdeep"])
                                heur_section.add_item("Total Size", extracted_file_info["size"])

                    if request.add_extracted(
                        path=file_path,
                        name=child[1],
                        description=f"Extracted using {child[2]}",
                        safelist_interface=self.api_interface,
                    ):
                        extracted_files.append(child[1])
                    else:
                        safelisted_extracted.append(child[1])
            except MaxExtractedExceeded:
                request.result.add_section(
                    ResultSection(
                        f"This file contains a total of {len(extracted)} extracted files, "
                        f"exceeding the maximum of {request.max_extracted} extracted files allowed. "
                        "Some files where not extracted."
                    )
                )
                break

        if extracted_files:
            if password_protected:
                if summary_section_heuristic == 1:
                    summary_section_heuristic = 10

                # If successful known password
                if self.password_used:
                    pw_list = " | ".join(self.password_used)
                    section = ResultSection(
                        f"Successfully extracted {len(extracted_files)} "
                        f"file{'s' if len(extracted_files) > 1 else ''} "
                        f"using password{'s' if len(self.password_used) > 1 else ''}: {pw_list}",
                        parent=request.result,
                    )
                    for p in self.password_used:
                        section.add_tag("info.password", p)

                # If successful unknown password ### Can this ever happen?
                else:
                    pw_list = " | ".join(self.get_passwords(request))
                    section = ResultSection(
                        f"Successfully extracted {len(extracted_files)} "
                        f"file{'s' if len(extracted_files) > 1 else ''} "
                        f"using one or more of the following passwords: {pw_list}",
                        parent=request.result,
                    )

            else:
                section = ResultTextSection(
                    f"Successfully extracted {len(extracted_files)} file{'s' if len(extracted_files) > 1 else ''}",
                    parent=request.result,
                )

            if summary_section_heuristic:
                section.set_heuristic(summary_section_heuristic)

            for extracted_file in extracted_files:
                section.add_line(extracted_file)
                section.add_tag("file.name.extracted", extracted_file)

        if safelisted_extracted:
            MAX_SAFELISTED_SHOW = 25
            section = ResultSection(
                f"Successfully extracted {len(safelisted_extracted)} "
                f"file{'s' if len(safelisted_extracted) > 1 else ''} "
                f"that {'were' if len(safelisted_extracted) > 1 else 'was'} safelisted.",
                parent=request.result,
            )
            for f in sorted(safelisted_extracted)[:MAX_SAFELISTED_SHOW]:
                section.add_line(f)
            if len(safelisted_extracted) > MAX_SAFELISTED_SHOW:
                section.add_line("...")

        if symlinks:
            section = ResultTextSection(f"{len(symlinks)} Symlink(s) Found")
            section.add_lines(symlinks)
            section.set_heuristic(15)

        big_file = os.path.getsize(request.file_path) > self.config.get("small_size_bypass_drop", 10485760)
        few_files_extracted = len(extracted_files) <= self.config.get("max_file_count_bypass_drop", 5)
        big_file_with_few_extracted_files_only = big_file and few_files_extracted

        if (
            not big_file_with_few_extracted_files_only
            and not request.file_type.startswith("executable")
            and not request.file_type.startswith("java")
            and not request.file_type.startswith("android")
            and not request.file_type.startswith("document")
            and request.file_type != "ios/ipa"
            and request.file_type != "code/html"
            and request.file_type != "code/hta"
            and request.file_type != "archive/iso"
            and request.file_type != "archive/udf"
            and request.file_type != "archive/vhd"
            and not request.get_param("continue_after_extract")
        ):
            request.drop()

        self.archive_with_executables(request)

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

    def repair_zip(self, request: ServiceRequest):
        """Attempts to use modules in repair_zip.py when a possible corruption of ZIP archive has been detected.

        Args:
            request AL request object.

        Returns:
            List containing repaired zip path, and display name "repaired_zip_file.zip", or a blank list if
            repair failed
        """
        try:
            with RepairZip(request.file_path, strict=False) as rz:
                if not (rz.is_zip and rz.broken):
                    return []
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
                                except BadZipfile as e:
                                    # Corrupted zip file, also expected
                                    self.log.debug(f"The zip file is corrupted due to '{e}'")
                                    pass
                                except EOFError:
                                    # Unable to read path
                                    pass

                return [[out_name, "repaired_zip_file.zip", sys._getframe().f_code.co_name]]
        except ValueError:
            return []
        except NotImplementedError:
            # Compression type 99 is not implemented in python zipfile
            return []
        except RuntimeError:
            # Probably a corrupted passworded file.
            # Since we have no examples of good usage of repair_zip, we'll just make sure it won't error out.
            # We won't support repairing corrupted passworded files for now.
            self.log.warning(
                "RuntimeError detected. Is the corrupted file password protected? That is usually the cause."
            )
            return []

    def extract_office(self, request: ServiceRequest):
        """Will attempt to use modules in office_extract.py to extract a document from an encrypted Office file.

        Args:
            request: AL request object.

        Returns:
            List containing decoded file path and display name "[orig FH name]", or a blank list if decryption failed
            Boolean if encryption successful (indicating encryption detected).
        """

        passwords = self.get_passwords(request)
        try:
            res = extract_office_docs(request.file_path, passwords, self.working_directory)

            if res is None:
                raise ValueError()
        except (ValueError, OSError, msoffcryptoexceptions.FileFormatError):
            # Not a valid supported/valid file
            return [], False
        except (PasswordError, ExtractionError):
            # Could not guess password
            self.raise_failed_passworded_extraction(request, [], [], passwords)
            return [], True

        out_name, password = res
        self.password_used.append(password)
        return [[out_name, request.file_name, sys._getframe().f_code.co_name]], True

    def _submit_extracted(self, request: ServiceRequest, folder_path: str, caller: str):
        """Go over a folder, sanitize file/folder names and return a list of filtered files

        Args:
            request AL request object.
            folder_path: Folder to look into.
            caller: the function calling this

        Returns:
            List containing extracted file information, including: extracted path and display name
            or a blank list if extraction failed.
        """

        if not any(os.path.getsize(os.path.join(folder_path, file)) for file in os.listdir(folder_path)):
            # No non-empty file found
            return []
        # If we extract anything into the destination directory, we consider it of interest

        extract_executable_sections = request.get_param("extract_executable_sections")
        extracted_children = []

        # Fix problems with directory
        changes_made = True
        while changes_made:
            changes_made = False
            for root, _, files in os.walk(folder_path):
                # Sanitize root
                new_root = safe_str(root)
                if new_root != root:
                    # Implies there was a correction made to path, copy contents to new directory
                    shutil.copytree(root, new_root)
                    shutil.rmtree(root)
                    changes_made = True
                    break
                for f in files:
                    file_path = os.path.join(root, f)
                    # Sanitize filename
                    new_file_path = safe_str(file_path)
                    if file_path != new_file_path:
                        if os.path.exists(new_file_path):
                            raise FileExistsError(
                                f"Trying to move {file_path} to {new_file_path}, but file exists already"
                            )
                        shutil.move(file_path, new_file_path)

        # Add Extracted
        extracted_path = os.path.join(self.working_directory, "extracted_files")
        if not os.path.exists(extracted_path):
            os.mkdir(extracted_path)

        for root, _, files in os.walk(folder_path):
            for f in files:
                if not os.path.getsize(os.path.join(root, f)):
                    continue

                skip = False
                filename = safe_str(os.path.join(root, f).replace(folder_path, ""))
                if filename.startswith("/"):
                    filename = filename[1:]
                if not extract_executable_sections and request.file_type.startswith("executable"):
                    if "windows" in request.file_type:
                        for forbidden in self.FORBIDDEN_WIN:
                            if filename.startswith(forbidden):
                                skip = True
                                break

                    elif "linux" in request.file_type:
                        if filename in self.FORBIDDEN_ELF:
                            skip = True
                        for forbidden in self.FORBIDDEN_ELF_SW:
                            if filename.startswith(forbidden):
                                skip = True
                                break

                    elif "mach-o" in request.file_type:
                        for forbidden in self.FORBIDDEN_MACH:
                            if filename.startswith(forbidden):
                                skip = True
                                break
                if not skip:
                    target_folder = os.path.join(extracted_path, root.lstrip(folder_path))
                    os.makedirs(target_folder, exist_ok=True)
                    target_path = os.path.join(target_folder, f)
                    shutil.move(os.path.join(root, f), target_path)
                    extracted_children.append([target_path, safe_str(filename), caller])
                else:
                    self.log.debug(f"File '{filename}' skipped because extract_executable_sections is turned off")

        return extracted_children

    def extract_ace(self, request: ServiceRequest):
        """Will attempt to use command-line tool unace to extract content from an ACE archive.

        Args:
            request: AL request object.

        Returns:
            List containing extracted file information, including: extracted path, encoding, and display name,
            or a blank list if extraction failed
        """

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                with tempfile.NamedTemporaryFile(suffix=".ace", dir=temp_dir) as tf:
                    # unace needs the .ace file extension
                    with open(request.file_path, "rb") as fh:
                        tf.write(fh.read())
                        tf.flush()

                    subprocess.run(
                        f"/usr/bin/unace e -y {tf.name}",
                        timeout=2 * self.service_attributes.timeout / 3,
                        capture_output=True,
                        cwd=temp_dir,
                        env=os.environ,
                        shell=True,
                        preexec_fn=set_death_signal(),
                    )
                return self._submit_extracted(request, temp_dir, sys._getframe().f_code.co_name)
        except Exception:
            self.log.exception(f"While extracting {request.sha256} with unace")

        return []

    def extract_pdf_passwordprotected(self, request: ServiceRequest):
        """Will attempt to use pikepdf to extract embedded files from a passwordprotected PDF sample.

        Args:
            request: AL request object.

        Returns:
            List containing extracted file information, including: extracted path and display name,
            or a blank list if extraction failed or no embedded files are detected; and False as no passwords will
            ever be detected.
        """

        pdf_content = request.file_contents[request.file_contents.find(b"%PDF-") :]
        for password in self.get_passwords(request):
            try:
                pdf = Pdf.open(BytesIO(pdf_content), password=password)
                # If we're able to unlock the PDF, drop the unlocked version for analysis
                fd = tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False)
                # We can't re-use the original IDs, but we'll use a static one (PI) for the last modified timestamp
                pdf.save(fd, static_id=True)
                fd.seek(0)
                self.password_used.append(password)
                return [[fd.name, request.file_name, sys._getframe().f_code.co_name]], True
            except PDFPasswordError:
                continue
            except PdfError as e:
                if "unsupported encryption filter" in str(e):
                    # Known limitation of QPDF for signed documents: https://github.com/qpdf/qpdf/issues/53
                    break
                # Damaged PDF, typically extracted from another service like OLETools
                self.log.warning(e)

        return [], False

    def extract_pdf(self, request: ServiceRequest):
        """Will attempt to use pikepdf to extract embedded files from a PDF sample.

        Args:
            request: AL request object.

        Returns:
            List containing extracted file information, including: extracted path and display name,
            or a blank list if extraction failed or no embedded files are detected; and False as no passwords will
            ever be detected.
        """
        pdf_content = request.file_contents[request.file_contents.find(b"%PDF-") :]

        try:
            extracted_children = []
            pdf = Pdf.open(BytesIO(pdf_content))
            # Extract embedded contents in PDF
            for key in pdf.attachments.keys():
                if pdf.attachments.get(key):
                    fd = tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False)
                    attachment = pdf.attachments[key]
                    if not attachment.filename:
                        continue
                    fd.write(attachment.get_file().read_bytes())
                    fd.seek(0)
                    extracted_children.append([fd.name, key, sys._getframe().f_code.co_name])
        except PdfError as e:
            # Damaged PDF, typically extracted from another service like OLETools
            self.log.warning(e)

        return extracted_children

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

    def extract_vbe(self, request: ServiceRequest):
        """Will attempt to decode VBA code data from a VBE container.

        Args:
            request: AL request object.

        Returns:
            List containing decoded file information, including: decoded file path, encoding, and display name,
            or a blank list if decode failed
        """
        with open(request.file_path, "r") as fh:
            text = fh.read()
        try:
            # Ensure file format is correct via regex
            evbe_present = re.search(EVBE_REGEX, text)
            evbe_res = self.decode_vbe(evbe_present.groups()[0])
            if evbe_res and evbe_present != text:
                path = os.path.join(self.working_directory, "extracted_vbe")
                with open(path, "w") as f:
                    f.write(evbe_res)
                return [[path, "vbe_decoded", sys._getframe().f_code.co_name]]
        except Exception as e:
            self.log.warning(f"Error during vbe decoding: {str(e)}")
        return []

    def extract_zlib(self, request: ServiceRequest):
        with open(request.file_path, "rb") as fh:
            data = fh.read()

        try:
            decoder = zlib.decompressobj()
            uncompress_data = decoder.decompress(data)
            sha256hash = hashlib.sha256(uncompress_data).hexdigest()
            path = os.path.join(self.working_directory, sha256hash)
            with open(path, "wb") as f:
                f.write(uncompress_data)
            return [[path, sha256hash, sys._getframe().f_code.co_name]]
        except Exception:
            pass

        return []

    def extract_zip(self, request: ServiceRequest):
        """Will attempt to use 7zip (or zipfile) and then unrar to extract content from an archive,
        or sections from a Windows executable file.

        Args:
            request: AL request object.

        Returns:
            List containing extracted file information, including: extracted path and display name,
            or a blank list if extraction failed; and True if encryption detected.
        """

        extracted_files = []
        password_protected = False

        try:
            # Attempt extraction of zip
            try:
                # with 7z
                extracted_files, password_protected = self.extract_zip_7zip(request)
                if extracted_files:
                    return extracted_files, password_protected
            except (UnicodeDecodeError, UnicodeEncodeError) as e:
                self.log.debug(f"While extracting {request.sha256} with 7zip: {str(e)}")
                # with zipfile
                extracted_files, password_protected = self.extract_zip_zipfile(request)
                if extracted_files:
                    return extracted_files, password_protected
            except TypeError:
                pass

            # Try unrar if 7zip fails for rar archives
            if request.file_type == "archive/rar":
                extracted_files, password_protected = self.extract_zip_unrar(request)
                if extracted_files:
                    return extracted_files, password_protected
            # If we cannot extract the tar file, try a custom method
            elif request.file_type == "archive/tar":
                extracted_files, password_protected = self.extract_tarfile(request)
                if extracted_files:
                    return extracted_files, password_protected
        except Exception as e:
            self.log.exception(f"While extracting {request.sha256} with 7zip or zipfile: {str(e)}")

        return extracted_files, password_protected

    def parse_archive_listing(self, popenargs, env, first_header_title):
        p = subprocess.run(popenargs, env=env, capture_output=True)
        separator = None
        header = None
        data = []
        for line in p.stdout.split(b"\n"):
            if line.lstrip().startswith(first_header_title):
                header = line
                continue
            if header is not None and separator is None:
                separator = line
                continue
            if line == separator:
                break
            if separator:
                data.append(line)

        if separator is None:
            # The command probably returned without being able to parse the listing
            return [], []

        # Now that we have headers and data, we need to parse them
        col_len = [(m.start(), m.end()) for m in re.finditer(rb"\S+", separator)]

        header = [b" ".join(header[c[0] : c[1]].split()).decode() for c in col_len]
        parsed_data = []
        for d in data:
            parsed_data.append([d[c[0] : c[1]].strip().decode() for c in col_len])
            if len(separator) < len(d):
                parsed_data[-1][-1] = f"{parsed_data[-1][-1]}{d[len(separator) :].decode()}"
            parsed_data[-1] = [x.strip() for x in parsed_data[-1]]

        return header, parsed_data

    def raise_failed_passworded_extraction(
        self, request: ServiceRequest, extracted_files, expected_files, password_tested
    ):
        section = ResultTextSection(
            "Failed to extract password protected file.", heuristic=Heuristic(12), parent=request.result
        )
        if request.get_param("score_failed_password"):
            section.heuristic.add_signature_id("raise_score")
        section.add_tag("file.behavior", "Archive Unknown Password")
        if expected_files:
            section.add_line("Unextracted files in password protected archive:")
            extracted_file_names = [x[1] for x in extracted_files]
            for name in expected_files:
                if name not in extracted_file_names:
                    section.add_line(name)
                    section.add_tag("file.name.extracted", name)

        if not request.file_type.startswith("executable"):
            # Don't drop executables that contain password protected zip sections
            request.drop()

        # Add the list of password tested as supplementary, for information to the user and debugging
        if password_tested:
            password_tested_path = os.path.join(self.working_directory, "password_tested.json")
            with open(password_tested_path, "w") as f:
                json.dump(password_tested, f)
            request.add_supplementary(password_tested_path, "password_tested.json", "Passwords used that failed")

    def extract_zip_7zip(self, request: ServiceRequest):
        password_protected = False
        password_list = []

        env = os.environ.copy()
        env["LANG"] = "C.UTF-8"

        with tempfile.TemporaryDirectory() as temp_dir:
            extracted_files = []

            popenargs = ["7zzs", "x", "-p", "-y", request.file_path, f"-o{temp_dir}"]
            # Some UDF samples were wrongly identified as plain ISO by 7z.
            # By adding the .iso extension, it somehow made 7z identify it as UDF.
            # Our Identify was also identifying it as "iso", so we can't only rely on "archive/udf".
            if request.file_type in ["archive/iso", "archive/udf"]:
                temp_path = os.path.join(self.working_directory, "renamed_iso.iso")
                shutil.copy2(request.file_path, temp_path)
                popenargs[4] = temp_path

            try:
                p = subprocess.run(popenargs, env=env, capture_output=True)
                stdoutput, stderr = p.stdout, p.stderr

                extracted_files.extend(self._submit_extracted(request, temp_dir, sys._getframe().f_code.co_name))

                if b"Wrong password" in stderr:
                    password_protected = True
                    password_list = self.get_passwords(request)
                    for password in password_list:
                        try:
                            popenargs[2] = f"-p{password}"
                            shutil.rmtree(temp_dir, ignore_errors=True)
                            p = subprocess.run(popenargs, env=env, capture_output=True)
                            stdoutput = p.stdout + p.stderr
                            extracted_children = self._submit_extracted(
                                request, temp_dir, sys._getframe().f_code.co_name
                            )
                            if extracted_children:
                                self.password_used.append(password)
                                extracted_files.extend(extracted_children)
                            if stdoutput and b"\nEverything is Ok\n" in stdoutput:
                                break
                        except OSError:
                            pass
                elif b"Can not open the file as archive" in stdoutput:
                    raise TypeError

                error_res = None
                for line in itertools.chain(stdoutput.split(b"\n"), stderr.split(b"\n")):
                    if line.startswith(b"ERROR:") and not line.startswith(b"ERROR: Wrong password :"):
                        if error_res is None:
                            error_res = ResultTextSection("Errors in 7z", parent=request.result)
                        error_res.add_line(line)

                popenargs[1] = "l"  # Change the command to list
                popenargs = popenargs[:-1]  # Drop the destination output
                header, data = self.parse_archive_listing(popenargs, env, b"Date")
                if not data and request.file_type != "archive/rar":
                    # No listing could be extracted.
                    heur = Heuristic(24)
                    _ = ResultTextSection(heur.name, heuristic=heur, parent=request.result, body=heur.description)
                else:
                    # Data should be:
                    # Date Time, Attr, Size, Compressed, Name

                    hidden_files = [x for x in data if x[1][2] == "H"]
                    if hidden_files:
                        heur = Heuristic(18)
                        res = ResultTableSection(heur.name, heuristic=heur, parent=request.result)
                        for hf in hidden_files:
                            res.add_row(TableRow(dict(zip(header, hf))))
                            # Do not add Directories to filename extracted
                            if hf[1][0] != "D":
                                res.add_tag("file.name.extracted", hf[-1])

                    # x[2] is the size, so ignore empty files/folders
                    expected_files = [x[4] for x in data if x[2] != "0"]
                    if password_protected and len(extracted_files) != len(expected_files):
                        # If we extracted no files, and it is an archive/rar,
                        # we'll rely on unrar to populate the section
                        if extracted_files or request.file_type != "archive/rar":
                            self.raise_failed_passworded_extraction(
                                request, extracted_files, expected_files, password_list
                            )

                    # Only trigger on certain conditions, else rely on checking the
                    # actual file to determine if it is bloated
                    if error_res or (password_protected and len(extracted_files) != len(expected_files)):
                        very_compressed = []
                        for x in data:
                            if (
                                x[2] not in ["0", ""]
                                and x[3] != ""
                                and int(x[2]) > self.config.get("heur22_min_overlay_size", 31457280)
                                and int(x[3]) / int(x[2]) < self.config.get("heur22_max_compression_ratio", 0.1)
                            ):
                                very_compressed.append(x)
                        if very_compressed:
                            heur = Heuristic(22)
                            res = ResultSection(heur.name, heuristic=heur, parent=request.result)
                            for vcf in very_compressed:
                                res.add_line(
                                    (
                                        f"{vcf[-1]} has a compression ratio of "
                                        f"{int(vcf[3]) / int(vcf[2]):0.02%} ({vcf[3]}/{vcf[2]})"
                                    )
                                )

            except UnicodeEncodeError:
                raise
            finally:
                if request.file_type in ["archive/iso", "archive/udf"] and os.path.exists(temp_path):
                    os.remove(temp_path)

        return extracted_files, password_protected

    def extract_zip_zipfile(self, request: ServiceRequest):
        password_protected = False
        password_list = []

        with tempfile.TemporaryDirectory() as temp_dir:
            extracted_files = []

            try:
                with zipfile.ZipFile(request.file_path, "r") as zipped_file:
                    zipped_file.extractall(path=temp_dir)
                extracted_files.extend(self._submit_extracted(request, temp_dir, sys._getframe().f_code.co_name))
            except RuntimeError as e:
                if any("password required for extraction" in event for event in e.args):
                    # Try with available passwords
                    password_protected = True
                    password_list = self.get_passwords(request)
                    for password in password_list:
                        try:
                            shutil.rmtree(temp_dir, ignore_errors=True)
                            with zipfile.ZipFile(request.file_path, "r") as zipped_file:
                                zipped_file.extractall(path=temp_dir, pwd=password.encode())
                            extracted_children = self._submit_extracted(
                                request, temp_dir, sys._getframe().f_code.co_name
                            )
                            if extracted_children:
                                self.password_used.append(password)
                                extracted_files.extend(extracted_children)
                            break
                        except RuntimeError:
                            pass

                    with zipfile.ZipFile(request.file_path, "r") as zipped_file:
                        namelist = zipped_file.namelist()
                    if len(extracted_files) != len(namelist):
                        self.raise_failed_passworded_extraction(request, extracted_files, namelist, password_list)
            except BadZipfile:
                self.log.warning("A non-zip file was passed to zipfile library")

        return extracted_files, password_protected

    def extract_zip_unrar(self, request: ServiceRequest):
        password_protected = False
        password_list = []

        env = os.environ.copy()
        env["LANG"] = "C.UTF-8"

        with tempfile.TemporaryDirectory() as temp_dir:
            extracted_files = []

            try:
                p = subprocess.run(
                    ["unrar", "x", "-y", "-p-", request.file_path, temp_dir], env=env, capture_output=True
                )
                stdout_rar, stderr_rar = p.stdout, p.stderr
            except OSError:
                self.log.warning(f"Error running unrar on sample {request.sha256}. Extract service may be out of date.")
                return extracted_files, password_protected

            if b"All OK" in stdout_rar:
                extracted_files.extend(self._submit_extracted(request, temp_dir, sys._getframe().f_code.co_name))
            # "password is incorrect" in unrar 5.6.6, "Incorrect password" in unrar 6.0.3
            elif b"password is incorrect" in stderr_rar or b"Incorrect password" in stderr_rar:
                password_protected = True
                password_list = self.get_passwords(request)
                for password in password_list:
                    try:
                        shutil.rmtree(temp_dir, ignore_errors=True)
                        os.mkdir(temp_dir)
                        stdout = subprocess.run(
                            ["unrar", "x", "-y", f"-p{password}", request.file_path, temp_dir],
                            env=env,
                            capture_output=True,
                        ).stdout
                        if b"All OK" in stdout:
                            extracted_children = self._submit_extracted(
                                request, temp_dir, sys._getframe().f_code.co_name
                            )
                            if extracted_children:
                                self.password_used.append(password)
                                extracted_files.extend(extracted_children)
                    except OSError:
                        pass

        if password_protected:
            if self.password_used:
                popenargs = ["unrar", "l", "-y", f"-p{self.password_used[-1]}", request.file_path]
            else:
                popenargs = ["unrar", "l", "-y", "-p-", request.file_path]
            header, data = self.parse_archive_listing(popenargs, env, b"Attributes")
            if not data:
                # No listing could be extracted.
                heur = Heuristic(24)
                _ = ResultTextSection(heur.name, heuristic=heur, parent=request.result, body=heur.description)
            else:
                # x[1] is the size, so ignore empty files/folders
                expected_files = [x[4] for x in data if x[1] != "0"]
                if len(extracted_files) != len(expected_files):
                    self.raise_failed_passworded_extraction(request, extracted_files, expected_files, password_list)

        return extracted_files, password_protected

    def extract_tarfile(self, request: ServiceRequest):
        password_protected = False

        with tempfile.TemporaryDirectory() as temp_dir:
            extracted_files = []

            try:
                tar_obj = tarfile.open(request.file_path)
                tar_obj.extractall(temp_dir)
                tar_obj.close()

            except Exception as e:
                self.log.exception(f"Error using tarfile to extract sample {request.sha256}: {str(e)}.")
                return extracted_files, password_protected

            extracted_files.extend(self._submit_extracted(request, temp_dir, sys._getframe().f_code.co_name))

        return extracted_files, password_protected

    def extract_swf(self, request: ServiceRequest):
        """Will attempt to extract compressed SWF files.

        Args:
            request: AL request object.

        Returns:
            List containing extracted file information, including: extracted path and display name,
            or a blank list if extract failed
        """

        extracted_children = []

        output_path = os.path.join(self.working_directory, "extracted_swf")
        if not os.path.exists(output_path):
            os.makedirs(output_path)

        files_found = []
        # noinspection PyBroadException
        try:
            swf = xxxswf(self.log)
            files_found = swf.extract(request.file_path, output_path)
        except Exception:
            self.log.exception("Error occurred while trying to decompress swf...")

        for child in files_found:
            extracted_children.append([output_path + "/" + child, child, sys._getframe().f_code.co_name])

        return extracted_children

    def extract_nsis(self, request: ServiceRequest):
        """Will attempt to extract data from a NSIS container.

        Args:
            request: AL request object.

        Returns:
            List containing extracted file information, including: extracted path and display name,
            or a blank list if extract failed
        """

        output_path = os.path.join(self.working_directory, "SETUP.nsi")
        try:
            extractor = NSIExtractor.from_path(request.file_path)
            extractor.generate_setup_file()
            extractor.save_setup_file(output_path)
        except Exception:
            # The NSIS Setup.nsi file extraction is a best effort
            return []

        return [[output_path, "SETUP.nsi", sys._getframe().f_code.co_name]]

    def extract_tnef(self, request: ServiceRequest):
        """Will attempt to extract data from a TNEF container.

        Args:
            request: AL request object.

        Returns:
            List containing extracted file information, including: extracted path and display name,
            or a blank list if extract failed
        """

        children = []

        # noinspection PyBroadException
        try:
            # noinspection PyUnresolvedReferences
            from tnefparse import tnef

            tnef_logger = logging.getLogger("tnef-decode")
            tnef_logger.setLevel(60)  # This completely turns off the TNEF logger

            count = 0
            with open(request.file_path, "rb") as f:
                content = f.read()
            if not content:
                return children
            parsed_tnef = tnef.TNEF(content)
            if parsed_tnef.body:
                temp_data_email_body = request.temp_submission_data.get("email_body", [])
                temp_data_email_body.extend(parsed_tnef.body.split())
                request.temp_submission_data["email_body"] = temp_data_email_body

            tnef_dump = parsed_tnef.dump()
            kv_section = ResultKeyValueSection("Attributes", parent=request.result)
            for k, v in tnef_dump["attributes"].items():
                if isinstance(v, datetime):
                    v = v.isoformat()
                kv_section.set_item(k, str(v))

            kv_section = ResultKeyValueSection("Extended Attributes", parent=request.result)
            for k, v in tnef_dump["extended_attributes"].items():
                if isinstance(v, datetime):
                    v = v.isoformat()
                kv_section.set_item(k, str(v))

            if "0x851f" in tnef_dump["extended_attributes"] and str(
                tnef_dump["extended_attributes"]["0x851f"]
            ).startswith("\\\\"):
                heur_section = ResultKeyValueSection("CVE-2023-23397", parent=request.result)
                heur_section.add_tag("attribution.exploit", "CVE-2023-23397")
                heur_section.add_tag("network.static.unc_path", tnef_dump["extended_attributes"]["0x851f"])
                heur_section.set_heuristic(25)
                heur_section.set_item("extended_attributes 0x851f", tnef_dump["extended_attributes"]["0x851f"])

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
                children.append([tmp_f.name, name, sys._getframe().f_code.co_name])
        except ImportError:
            self.log.exception("Import error: tnefparse library not installed:")
        except Exception:
            self.log.exception("Error extracting from tnef file:")

        return children

    def ipa_safelisting(self, extracted, safelisted_extracted):
        """Filters file paths that are considered safelisted from a list of extracted IPA files.

        Args:
            extracted: List of extracted file information, including: extracted path, encoding, and display name.
            safelisted_count: Current safelist count.

        Returns:
            List of filtered file names and updated count of safelisted files.
        """

        safelisted_fname_regex = [
            re.compile(r".app/.*\.plist$"),
            re.compile(r".app/.*\.nib$"),
            re.compile(r".app/.*/PkgInfo$"),
        ]

        tmp_new_files = []

        for cur_file in extracted:
            to_add = True
            for ext in safelisted_fname_regex:
                if ext.search(cur_file[0]):
                    to_add = False
                    safelisted_extracted.append(cur_file[1])

            if to_add:
                tmp_new_files.append(cur_file)

        return tmp_new_files, safelisted_extracted

    def jar_safelisting(self, extracted, safelisted_extracted):
        """Filters file paths that are considered safelisted from a list of extracted JAR files.

        Args:
            extracted: List of extracted file information, including: extracted path, encoding, and display name.
            safelisted_count: Current safelist count.

        Returns:
            List of filtered file names and updated count of safelisted files.
        """

        safelisted_tags_re = [
            re.compile(r"android/(xml|resource)"),
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

        tmp_new_files = []

        for cur_file in extracted:
            to_add = True
            file_info = self.identify.fileinfo(cur_file[0])
            for exp in safelisted_tags_re:
                if exp.search(file_info["type"]):
                    to_add = False
                    safelisted_extracted.append(cur_file[1])

            if to_add and file_info["mime"]:
                for exp in safelisted_mime_re:
                    if exp.search(file_info["mime"]):
                        to_add = False
                        safelisted_extracted.append(cur_file[1])

            if to_add:
                for ext in safelisted_fname_regex:
                    if ext.search(cur_file[0]):
                        to_add = False
                        safelisted_extracted.append(cur_file[1])

            if to_add:
                tmp_new_files.append(cur_file)

        return tmp_new_files, safelisted_extracted

    def archive_with_executables(self, request: ServiceRequest):
        """Detects executable files contained in an archive using the service's LAUNCHABLE_EXTENSIONS list.

        Args:
            request: AL request object.

        Returns:
            Al result object scoring VHIGH if executables detected in container, or None.
        """

        def is_launchable(file):
            if os.path.splitext(file["name"])[1].lower() in Extract.LAUNCHABLE_EXTENSIONS:
                return True
            file_type = self.identify.fileinfo(file["path"])["type"]
            if file_type in Extract.LAUNCHABLE_TYPE or any(file_type.startswith(x) for x in Extract.LAUNCHABLE_TYPE_SW):
                return file_type not in Extract.LAUNCHABLE_TYPE_FP
            return False

        if len(request.extracted) == 1 and is_launchable(request.extracted[0]):
            new_section = ResultTextSection("Archive file with single executable inside. Potentially malicious...")
            new_section.add_line(request.extracted[0]["name"])
            new_section.add_tag("file.name.extracted", request.extracted[0]["name"])
            new_section.set_heuristic(13)
            new_section.add_tag("file.behavior", "Archived Single Executable")
            request.result.add_section(new_section)
        else:
            launchable_extracted = []
            for extracted in request.extracted:
                if is_launchable(extracted):
                    launchable_extracted.append(extracted)
            if launchable_extracted:
                new_section = ResultTextSection("Executable Content in Archive. Potentially malicious...")
                new_section.add_tag("file.behavior", "Executable Content in Archive")
                for extracted in launchable_extracted:
                    new_section.add_line(extracted["name"])
                    new_section.add_tag("file.name.extracted", extracted["name"])
                if len(request.extracted) <= self.config.get("heur16_max_file_count", 5):
                    new_section.set_heuristic(16)

                if request.file_type.startswith("document/office/"):
                    heur = Heuristic(23)
                    _ = ResultTextSection(heur.name, heuristic=heur, parent=request.result, body=heur.description)

                request.result.add_section(new_section)

    def extract_onenote(self, request: ServiceRequest):
        """Extract embedded files from OneNote (.one) files

        Args:
            request: AL request object.

        Returns:
            List containing extracted attachment information, including: extracted path and display name
        """

        with open(request.file_path, "rb") as f:
            data = f.read()
        # From MS-ONESTORE FileDataStoreObject definition
        # https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-onestore/8806fd18-6735-4874-b111-227b83eaac26
        # guidHeader:  {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}
        # guidFooter:  {71FBA722-0F79-4A0B-BB13-899256426B24}
        # Note: the first 3 fields are stored little-endian so the bytes are in reverse order in the document.
        embedded_files: list[tuple[bytes, bytes]] = re.findall(
            b"(?s)\xE7\x16\xE3\xBD\x65\x26\x11\x45\xA4\xC4\x8D\x4D\x0B\x7A\x9E\xAC"
            b"(.{8}).{12}(.*?)\x22\xA7\xFB\x71\x79\x0F\x0B\x4A\xBB\x13\x89\x92\x56\x42\x6B\\\x24",
            data,
        )
        extracted = []
        for cb_length_bytes, embedded in embedded_files:
            cb_length = int.from_bytes(cb_length_bytes, "little")
            embedded = embedded[:cb_length]  # Remove padding
            with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False) as out:
                out.write(embedded)
            extracted.append([out.name, hashlib.sha256(embedded).hexdigest(), sys._getframe().f_code.co_name])
        return extracted

    def extract_jscript(self, request: ServiceRequest):
        """Extract embedded content from HTML documents

        Args:
            request: AL request object.

        Returns:
            List containing extracted script information, including: extracted path and display name
        """

        with open(request.file_path, "rb") as f:
            data = f.read()

        soup = BeautifulSoup(data, features="html5lib")
        scripts = soup.findAll("script")
        extracted = []
        for script in scripts:
            # Make sure there is actually a body to the script
            body = script.string
            if body is None:
                continue
            body = str(body).strip()  # Remove whitespace
            if len(body) <= 2:  # We can treat 2 character scripts as empty
                continue

            if script.get("language", "").lower() == "jscript.encode":
                try:
                    # The encoded VB technique can be used to encode javascript
                    evbe_present = re.search(EVBE_REGEX, body)
                    evbe_res = self.decode_vbe(evbe_present.groups()[0])
                    if evbe_res and evbe_present != body:
                        encoded_evbe_res = evbe_res.encode()
                        with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False) as out:
                            out.write(encoded_evbe_res)
                        file_hash = hashlib.sha256(encoded_evbe_res).hexdigest()
                        extracted.append([out.name, file_hash, sys._getframe().f_code.co_name])
                        heur = Heuristic(17)
                        heur_section = ResultTextSection(heur.name, heuristic=heur, parent=request.result)
                        heur_section.add_line(f"{file_hash}")
                except Exception as e:
                    self.log.warning(f"Exception during jscript.encode decoding: {str(e)}")
                    # Something went wrong, still add the file as is
                    encoded_script = body.encode()
                    with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False) as out:
                        out.write(encoded_script)
                    file_hash = hashlib.sha256(encoded_script).hexdigest()
                    extracted.append([out.name, file_hash, sys._getframe().f_code.co_name])
            elif script.get("type", "").lower() not in ["", "text/javascript"]:
                # If there is no "type" attribute specified in a script element, then the default assumption is
                # that the body of the element is Javascript
                # We don't want to handle those, but any other special type, we can extract
                encoded_script = body.encode()
                with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False) as out:
                    out.write(encoded_script)
                extracted.append([out.name, hashlib.sha256(encoded_script).hexdigest(), sys._getframe().f_code.co_name])

        # Extraction of passwords was previously done in JsJaws, the analyzer for HTML/Javascript.
        # To speed up processing, Assemblyline is running services in phases. Each services from the same phase are
        # running concurrently. This is causing a situation where another service could extract a zip file that needs
        # the list of passwords from the html page, before the html page is completely analyzed by JsJaws. The new
        # analysis would start on the new zip file too fast, and Extract would not have the full list of passwords.
        # Bringing the extraction of passwords in a module from an earlier phase should solve those specific cases.

        # Extract password from visible text, taken from https://stackoverflow.com/a/1983219
        def tag_visible(element):
            if element.parent.name in ["style", "script", "head", "title", "meta", "[document]"]:
                return False
            if isinstance(element, Comment):
                return False
            return True

        visible_texts = [x for x in filter(tag_visible, soup.findAll(text=True))]

        if any(any(WORD in line.lower() for WORD in PASSWORD_WORDS) for line in visible_texts):
            new_passwords = set()

            for line in visible_texts:
                for password in extract_passwords(line):
                    if len(password) > 30:
                        # We assume that passwords won't be that long.
                        continue
                    new_passwords.add(password)

            if new_passwords:
                self.log.debug(f"Found password(s) in the HTML doc: {new_passwords}")
                # It is technically not required to sort them, but it makes the output of the module predictable
                if "passwords" in request.temp_submission_data:
                    new_passwords.update(set(request.temp_submission_data["passwords"]))
                request.temp_submission_data["passwords"] = sorted(list(new_passwords))

        return extracted

    def extract_wsf(self, request: ServiceRequest):
        with open(request.file_path, "rb") as f:
            data = f.read()

        soup = BeautifulSoup(data, features="lxml")
        scripts = soup.findAll("script")
        languages = sorted(list(set([script.get("language", "").lower() for script in scripts])))
        if len(languages) > 1:
            heur = Heuristic(20)
            heur_section = ResultTextSection(heur.name, heuristic=heur, parent=request.result)
            heur_section.add_line(", ".join(languages))
            return []

        extracted = []
        aggregated_script = b""
        external_loaded_script = []
        for script in scripts:
            # Make sure there is actually a body to the script
            src = script.get("src", "")
            if src:
                external_loaded_script.append(src)
            body = script.string
            if body is None:
                continue
            body = str(body).strip()  # Remove whitespace
            if len(body) <= 2:  # We can treat 2 character scripts as empty
                continue

            if script.get("language", "").lower() == "jscript.encode":
                try:
                    # The encoded VB technique can be used to encode javascript
                    evbe_present = re.search(EVBE_REGEX, body)
                    evbe_res = self.decode_vbe(evbe_present.groups()[0])
                    if evbe_res and evbe_present != body:
                        encoded_evbe_res = evbe_res.encode()
                        with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False) as out:
                            out.write(encoded_evbe_res)
                        file_hash = hashlib.sha256(encoded_evbe_res).hexdigest()
                        extracted.append([out.name, file_hash, sys._getframe().f_code.co_name])
                        heur = Heuristic(17)
                        heur_section = ResultTextSection(heur.name, heuristic=heur, parent=request.result)
                        heur_section.add_line(f"{file_hash}")
                except Exception as e:
                    self.log.warning(f"Exception during jscript.encode decoding: {str(e)}")
                    # Something went wrong, still add the file as is
                    encoded_script = body.encode()
                    with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False) as out:
                        out.write(encoded_script)
                    file_hash = hashlib.sha256(encoded_script).hexdigest()
                    extracted.append([out.name, file_hash, sys._getframe().f_code.co_name])
            elif script.get("language", "").lower() not in ["", "javascript", "jscript"]:
                # If there is no "type" attribute specified in a script element, then the default assumption is
                # that the body of the element is Javascript
                # We don't want to handle those, but any other special type, we can extract
                encoded_script = body.encode()
                if aggregated_script:
                    aggregated_script += b"\n\n"

                aggregated_script += encoded_script

        if aggregated_script:
            file_hash = hashlib.sha256(aggregated_script).hexdigest()
            with open(os.path.join(self.working_directory, file_hash), "wb") as f:
                f.write(aggregated_script)
            extracted.append(
                [os.path.join(self.working_directory, file_hash), file_hash, sys._getframe().f_code.co_name]
            )

        if external_loaded_script:
            local = None
            web = None
            for src in external_loaded_script:
                if src.startswith("http://") or src.startswith("https://"):
                    if web is None:
                        heur = Heuristic(21)
                        heur.add_signature_id("web")
                        web = ResultTextSection(heur.name, heuristic=heur, parent=request.result)
                    web.add_line(f"{src}")
                else:
                    if local is None:
                        heur = Heuristic(21)
                        heur.add_signature_id("local")
                        local = ResultTextSection(heur.name, heuristic=heur, parent=request.result)
                    local.add_line(f"{src}")
        return extracted

    def extract_xxe(self, request: ServiceRequest):
        """Extract embedded scripts from XX encoded archives

        Args:
            request: AL request object.

        Returns:
            List containing extracted information, including: extracted path, display name
        """

        files = xxuu_decode_from_file(request.file_path, xx_character)
        extracted = []
        for output_file, ans in files:
            output_file = output_file.lstrip("/")
            with open(os.path.join(self.working_directory, output_file), "wb") as f:
                f.write(bytes(ans))
            extracted.append(
                [os.path.join(self.working_directory, output_file), output_file, sys._getframe().f_code.co_name]
            )
        return extracted

    def extract_uue(self, request: ServiceRequest):
        """Extract embedded scripts from UU encoded archives

        Args:
            request: AL request object.

        Returns:
            List containing extracted information, including: extracted path, display name
        """

        files = xxuu_decode_from_file(request.file_path, uu_character)
        extracted = []
        for output_file, ans in files:
            output_file = output_file.lstrip("/")
            with open(os.path.join(self.working_directory, output_file), "wb") as f:
                f.write(bytes(ans))
            extracted.append(
                [os.path.join(self.working_directory, output_file), output_file, sys._getframe().f_code.co_name]
            )
        return extracted

    def extract_cart(self, request: ServiceRequest):
        cart_name = get_metadata_only(request.file_path)["name"]
        output_path = os.path.join(self.working_directory, cart_name.lstrip("/"))
        with open(request.file_path, "rb") as ifile, open(output_path, "wb") as ofile:
            unpack_stream(ifile, ofile)

        return [[output_path, cart_name, sys._getframe().f_code.co_name]]

    def strip_overlay(self, file_path):
        try:
            binary = pefile.PE(file_path, fast_load=True)
        except Exception:
            return False

        file_size = os.path.getsize(file_path)
        overlay_offset = binary.get_overlay_data_start_offset()
        if overlay_offset is None or overlay_offset == 0:
            return False
        overlay_size = file_size - overlay_offset
        if overlay_size < self.config.get("heur22_min_overlay_size", 31457280):
            return False

        calculator = BufferedCalculator()
        with open(file_path, "rb") as f:
            f.seek(overlay_offset)
            while True:
                data = f.read(1024)
                if not data:
                    break
                calculator.update(data)
        entropy = calculator.entropy()

        if entropy < self.config.get("heur22_min_overlay_entropy", 0.5):
            with open(file_path, "rb") as f:
                data = f.read(overlay_offset)
            sha256hash = hashlib.sha256(data).hexdigest()
            temp_path = os.path.join(self.working_directory, sha256hash)
            with open(temp_path, "wb") as f:
                f.write(data)

            return (temp_path, overlay_size, entropy)

        return False
