#!/usr/bin/env python3.7
# Note:
# PKZIP format taken from:
#    https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html
# Constants taken from zipfile.py, part of Python, which in turn sources:
#    http://www.pkware.com/documents/casestudies/APPNOTE.TXT
import mmap
import struct
import threading
import zlib
from zipfile import BadZipfile, ZipFile, ZipInfo

# Based on zipfile.py:

# Below are some formats and associated data for reading/writing headers using
# the struct module.  The names and structures of headers/records are those used
# in the PKWARE description of the ZIP file format:
#     http://www.pkware.com/documents/casestudies/APPNOTE.TXT
# (URL valid as of January 2008)

# The "end of central directory" structure, magic number, size, and indices
# (section V.I in the format document)
structEndArchive = "<4s4H2LH"
stringEndArchive = b"PK\005\006"
sizeEndCentDir = struct.calcsize(structEndArchive)

_ECD_SIGNATURE = 0
_ECD_DISK_NUMBER = 1
_ECD_DISK_START = 2
_ECD_ENTRIES_THIS_DISK = 3
_ECD_ENTRIES_TOTAL = 4
_ECD_SIZE = 5
_ECD_OFFSET = 6
_ECD_COMMENT_SIZE = 7
# These last two indices are not part of the structure as defined in the
# spec, but they are used internally by this module as a convenience
_ECD_COMMENT = 8
_ECD_LOCATION = 9

# The "central directory" structure, magic number, size, and indices
# of entries in the structure (section V.F in the format document)
structCentralDir = "<4s4B4HL2L5H2L"
stringCentralDir = b"PK\001\002"
sizeCentralDir = struct.calcsize(structCentralDir)

# indexes of entries in the central directory structure
_CD_SIGNATURE = 0
_CD_CREATE_VERSION = 1
_CD_CREATE_SYSTEM = 2
_CD_EXTRACT_VERSION = 3
_CD_EXTRACT_SYSTEM = 4
_CD_FLAG_BITS = 5
_CD_COMPRESS_TYPE = 6
_CD_TIME = 7
_CD_DATE = 8
_CD_CRC = 9
_CD_COMPRESSED_SIZE = 10
_CD_UNCOMPRESSED_SIZE = 11
_CD_FILENAME_LENGTH = 12
_CD_EXTRA_FIELD_LENGTH = 13
_CD_COMMENT_LENGTH = 14
_CD_DISK_NUMBER_START = 15
_CD_INTERNAL_FILE_ATTRIBUTES = 16
_CD_EXTERNAL_FILE_ATTRIBUTES = 17
_CD_LOCAL_HEADER_OFFSET = 18

# The "local file header" structure, magic number, size, and indices
# (section V.A in the format document)
structFileHeader = "<4s2B4HL2L2H"
stringFileHeader = b"PK\003\004"
sizeFileHeader = struct.calcsize(structFileHeader)

_FH_SIGNATURE = 0
_FH_EXTRACT_VERSION = 1
_FH_EXTRACT_SYSTEM = 2
_FH_GENERAL_PURPOSE_FLAG_BITS = 3
_FH_COMPRESSION_METHOD = 4
_FH_LAST_MOD_TIME = 5
_FH_LAST_MOD_DATE = 6
_FH_CRC = 7
_FH_COMPRESSED_SIZE = 8
_FH_UNCOMPRESSED_SIZE = 9
_FH_FILENAME_LENGTH = 10
_FH_EXTRA_FIELD_LENGTH = 11

# The "Zip64 end of central directory locator" structure, magic number, and size
structEndArchive64Locator = "<4sLQL"
stringEndArchive64Locator = "PK\x06\x07"
sizeEndCentDir64Locator = struct.calcsize(structEndArchive64Locator)

# The "Zip64 end of central directory" record, magic number, size, and indices
# (section V.G in the format document)
structEndArchive64 = "<4sQ2H2L4Q"
stringEndArchive64 = "PK\x06\x06"
sizeEndCentDir64 = struct.calcsize(structEndArchive64)

_CD64_SIGNATURE = 0
_CD64_DIRECTORY_RECSIZE = 1
_CD64_CREATE_VERSION = 2
_CD64_EXTRACT_VERSION = 3
_CD64_DISK_NUMBER = 4
_CD64_DISK_NUMBER_START = 5
_CD64_NUMBER_ENTRIES_THIS_DISK = 6
_CD64_NUMBER_ENTRIES_TOTAL = 7
_CD64_DIRECTORY_SIZE = 8
_CD64_OFFSET_START_CENTDIR = 9


class RepairZip(ZipFile):
    # constants for Zip file compression methods
    ZIP_STORED = 0
    ZIP_DEFLATED = 8

    # noinspection PyMissingConstructor,PyPep8Naming
    def __init__(self, filename, mode="r", compression=ZIP_STORED, allowZip64=False, compresslevel=None, strict=True):
        """Open the ZIP file with mode read "r", write "w" or append "a"."""
        # Mostly from zipfile.py
        if mode not in ("r", "w", "a"):
            raise RuntimeError('ZipFile() requires mode "r", "w", or "a"')

        if compression == self.ZIP_STORED:
            pass
        elif compression == self.ZIP_DEFLATED:
            if not zlib:
                raise RuntimeError("Compression requires the (missing) zlib module")

        else:
            raise RuntimeError("That compression method is not supported")

        self._allowZip64 = allowZip64
        self._didModify = False
        self.debug = 0  # Level of printing: 0 through 3
        self.NameToInfo = {}  # Find file info given name
        self.filelist = []  # List of ZipInfo instances for archive
        self.compression = compression  # Method of compression
        self.compresslevel = compresslevel
        self.mode = key = mode.replace("b", "")[0]
        self.pwd = None
        self._comment = b""
        self.is_zip = True

        self._fileRefCnt = 1
        self._lock = threading.RLock()
        self._seekable = True
        self._writing = False
        self._strict_timestamps = True
        self.metadata_encoding = None

        # Check that we don't try to write with nonconforming codecs
        if self.metadata_encoding and mode != "r":
            raise ValueError("metadata_encoding is only supported for reading files")

        # Check if we were passed a file-like object
        if isinstance(filename, str):
            self._filePassed = 0
            self.filename = filename
            mode_dict = {"r": "rb", "w": "wb", "a": "r+b"}
            try:
                self.fp = open(filename, mode_dict[mode])
            except IOError:
                if mode == "a":
                    mode = key = "w"
                    self.fp = open(filename, mode_dict[mode])
                else:
                    raise
        else:
            self._filePassed = 1
            self.fp = filename
            self.filename = getattr(filename, "name", None)

        # noinspection PyBroadException
        try:
            if key == "r":
                self.fp.seek(0)
                if stringFileHeader not in self.fp.read(1024):
                    self.is_zip = False
                self._RealGetContents()
            elif key == "w":
                # set the modified flag so central directory gets written
                # even if no files are added to the archive
                self._didModify = True
                try:
                    self.start_dir = self.fp.tell()
                except (AttributeError, OSError):
                    # self.fp = _Tellable(self.fp)
                    self.start_dir = 0
                    self._seekable = False
                else:
                    # Some file-like objects can provide tell() but not seek()
                    try:
                        self.fp.seek(self.start_dir)
                    except (AttributeError, OSError):
                        self._seekable = False

            elif key == "a":
                try:
                    # See if file is a zip file
                    self._RealGetContents()
                    # seek to start of directory and overwrite
                    self.fp.seek(self.start_dir, 0)
                except BadZipfile:
                    # file is not a zip file, just append
                    self.fp.seek(0, 2)

                    # set the modified flag so central directory gets written
                    # even if no files are added to the archive
                    self._didModify = True
            else:
                raise RuntimeError('Mode must be "r", "w" or "a"')
            self.broken = False
        except Exception:
            if strict:
                if not self._filePassed:
                    self.fp.close()
                self.fp = None
                raise
            else:
                self.broken = True

    def fix_zip(self):
        if not self.broken:
            return False
        self.fp.seek(0, 2)
        file_len = self.fp.tell()
        mm = mmap.mmap(self.fp.fileno(), 0, access=mmap.ACCESS_READ)
        offset = 0
        file_list = {}
        cd_list = {}

        try:
            # pass one, parse the zip file
            while offset + 4 < file_len:
                hdr_off = mm.find(b"PK", offset)
                if hdr_off == -1:
                    break
                hdr_type = mm[hdr_off : hdr_off + 4]
                if hdr_type == stringFileHeader:
                    # local file header
                    if hdr_off + sizeFileHeader > file_len:
                        break
                    fheader = mm[hdr_off : hdr_off + sizeFileHeader]
                    fheader = struct.unpack(structFileHeader, fheader)
                    start = hdr_off
                    size = (
                        sizeFileHeader
                        + fheader[_FH_COMPRESSED_SIZE]
                        + fheader[_FH_FILENAME_LENGTH]
                        + fheader[_FH_EXTRA_FIELD_LENGTH]
                    )
                    name = mm[hdr_off + sizeFileHeader : hdr_off + sizeFileHeader + fheader[_FH_FILENAME_LENGTH]]
                    file_list[name] = [start, size, fheader]
                    offset = hdr_off + size
                elif hdr_type == stringCentralDir:
                    if hdr_off + sizeCentralDir > file_len:
                        break
                    centdir = mm[hdr_off : hdr_off + sizeCentralDir]
                    centdir = struct.unpack(structCentralDir, centdir)
                    start = hdr_off
                    size = (
                        sizeCentralDir
                        + centdir[_CD_FILENAME_LENGTH]
                        + centdir[_CD_EXTRA_FIELD_LENGTH]
                        + centdir[_CD_COMMENT_LENGTH]
                    )
                    name = mm[hdr_off + sizeCentralDir : hdr_off + sizeCentralDir + centdir[_CD_FILENAME_LENGTH]]
                    cd_list[name] = [start, size, centdir]
                    offset = hdr_off + size
                elif hdr_type == stringEndArchive:
                    offset = hdr_off + sizeEndCentDir
                else:
                    offset = hdr_off + 1

            # Guesses
            last_cv = 20
            last_ea = 0
            last_cs = 0
            last_dt = (0, 0)

            # Pass two, repair
            for filename, (start, end, centdir) in cd_list.items():
                if filename not in file_list:
                    continue

                if isinstance(filename, bytes):
                    x = ZipInfo(filename.decode("utf-8", "backslashreplace"))
                else:
                    x = ZipInfo(filename)
                extra_off = start + sizeCentralDir
                x.extra = mm[extra_off : extra_off + centdir[_CD_EXTRA_FIELD_LENGTH]]
                extra_off += centdir[_CD_EXTRA_FIELD_LENGTH]
                x.comment = mm[extra_off : extra_off + centdir[_CD_EXTRA_FIELD_LENGTH]]

                x.header_offset = file_list[filename][0]

                (
                    x.create_version,
                    x.create_system,
                    x.extract_version,
                    x.reserved,
                    x.flag_bits,
                    x.compress_type,
                    t,
                    d,
                    x.CRC,
                    x.compress_size,
                    x.file_size,
                ) = centdir[1:12]
                x.volume, x.internal_attr, x.external_attr = centdir[15:18]
                # Convert date/time code to (year, month, day, hour, min, sec)
                x._raw_time = t
                x.date_time = ((d >> 9) + 1980, (d >> 5) & 0xF, d & 0x1F, t >> 11, (t >> 5) & 0x3F, (t & 0x1F) * 2)

                last_ea = x.external_attr
                last_cs = x.create_system
                last_cv = x.create_version
                last_dt = (d, t)

                try:
                    x._decodeExtra()
                except TypeError:
                    # This internal function changed between Python 3.11 and 3.12
                    # It now takes an additional filename_crc parameter
                    # TODO: Delete this try/except once moved to 3.12
                    filename = mm.read(centdir[_CD_FILENAME_LENGTH])
                    x._decodeExtra(zlib.crc32(filename))

                # x.filename = x._decodeFilename()
                self.filelist.append(x)
                self.NameToInfo[x.filename] = x

            for filename, (start, end, fheader) in file_list.items():
                if filename in cd_list:
                    continue

                x = ZipInfo(filename.decode("utf-8", "backslashreplace"))
                x.extra = ""
                x.comment = ""

                x.header_offset = file_list[filename][0]

                x.create_version = last_cv
                x.create_system = last_cs
                x.extract_version = fheader[_FH_EXTRACT_VERSION]
                x.reserved = 0
                x.flag_bits = fheader[_FH_GENERAL_PURPOSE_FLAG_BITS]
                x.compress_type = fheader[_FH_COMPRESSION_METHOD]
                d, t = last_dt
                x.CRC = fheader[_FH_CRC]
                x.compress_size = fheader[_FH_COMPRESSED_SIZE]
                x.file_size = fheader[_FH_UNCOMPRESSED_SIZE]

                x.volume = 0
                x.internal_attr = 0
                x.external_attr = last_ea

                # Convert date/time code to (year, month, day, hour, min, sec)
                x._raw_time = t
                x.date_time = ((d >> 9) + 1980, (d >> 5) & 0xF, d & 0x1F, t >> 11, (t >> 5) & 0x3F, (t & 0x1F) * 2)

                # noinspection PyProtectedMember
                x._decodeExtra()
                # x.filename = x._decodeFilename()
                self.filelist.append(x)
                self.NameToInfo[x.filename] = x
        finally:
            mm.close()
