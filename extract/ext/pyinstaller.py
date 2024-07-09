"""Logic around identifcation and extraction of PyInstaller generated files.


* Package, Cookie and TOC structures are taken directly from PyInstaller source.
* Package, Cookie and TOC parsing based from PyInstaller reader:
  https://github.com/pyinstaller/pyinstaller/blob/develop/PyInstaller/archive/readers.py

"""

import struct
import zlib

import xdis.magics
from assemblyline.common.str_utils import safe_str

PYZ_MAGIC: bytes = b"PYZ\x00"
ZLIB_HEADERS: list[bytes] = [
    b"\x78\xDA",
    b"\x78\x9C",
]

COOKIE_MAGIC: bytes = b"MEI\014\013\012\013\016"
COOKIE_FORMATS = {
    "!8sIIii64s": ["magic", "size", "toc_index", "toc_size", "py_version", "py_lib"],  # introduced in 2021.03
    # "!8siiii64s": ["magic", "size", "toc_index", "toc_size", "py_version", "py_lib"]  # introduced in 2012.08
    "!8siiii": ["magic", "size", "toc_index", "toc_size", "py_version"],  # introduced in 2005.09
}

TOC_RECORD_FORMAT = "!iIIIBc"  # (structlen, dpos, dlen, ulen, flag, typcd) followed by name
TOC_RECORD_LENGTH = struct.calcsize(TOC_RECORD_FORMAT)

# Type codes for CArchive TOC entries
PKG_ITEM_BINARY = b"b"  # binary
PKG_ITEM_DEPENDENCY = b"d"  # runtime option
PKG_ITEM_PYZ = b"z"  # zlib (pyz) - frozen Python code
PKG_ITEM_ZIPFILE = b"Z"  # zlib (pyz) - frozen Python code
PKG_ITEM_PYPACKAGE = b"M"  # Python package (__init__.py)
PKG_ITEM_PYMODULE = b"m"  # Python module
PKG_ITEM_PYSOURCE = b"s"  # Python script (v3)
PKG_ITEM_DATA = b"x"  # data
PKG_ITEM_RUNTIME_OPTION = b"o"  # runtime option
PKG_ITEM_SPLASH = b"l"  # splash resources


class Invalid(Exception):
    """Not a PyInstaller file."""


def find_carchive(contents: bytes) -> tuple[bytes, bytes]:
    """Find and return the CArchive package from a PyInstaller file.

    Args:
        contents: PyInstaller file

    Returns:
        (package content, cookie)
    """
    # magic is the start of TOC
    cookie_loc = contents.rfind(COOKIE_MAGIC)

    if cookie_loc == -1:
        raise Invalid

    # given possible formats, this could technically be "i" instead of "I"...
    pkg_size = struct.unpack(">I", contents[cookie_loc + 8 : cookie_loc + 12])[0]

    # possible cookie size depending on pyinstaller version and platform
    cookie_size = [struct.calcsize(fmt) for fmt in COOKIE_FORMATS]

    # find the start of the python package by trial and error with known cookie sizes
    # then return the package by removing the headers
    for csize in cookie_size:
        start = cookie_loc + csize - pkg_size
        matched_zlib = any(contents[start : start + len(h)] == h for h in ZLIB_HEADERS)
        matched_pyz = contents[start : start + len(PYZ_MAGIC)] == PYZ_MAGIC
        if matched_zlib or matched_pyz:
            cookie = contents[cookie_loc : cookie_loc + csize]
            package = contents[start : start + pkg_size]
            return package, cookie

    raise Invalid


def find_scripts(package: bytes, toc: dict) -> list[tuple[str, bytes]]:
    """Find all python files within the package.

    Args:
        package: extracted PyInstaller package
        toc: table of contents

    Returns:
        [(filename, contents), ...]
    """
    scripts = []
    # ignore PyInstaller files
    pyi_files = ["pyi", "_pyi", "_"]
    for fname, entry in toc.items():
        if entry["entry_type"] == PKG_ITEM_PYSOURCE and not any(True for n in pyi_files if fname.startswith(n)):
            data = package[entry["offset"] : entry["offset"] + entry["compressed_size"]]
            if entry["compressed_flag"]:
                data = zlib.decompress(data)
            scripts.append((fname, data))

    return scripts


def parse_cookie(cookie: bytes) -> dict[str, bytes]:
    """Parse the cookie structure returning a dict of field values.

    Current cookie struct:
        format: '!8sIIii64s'

        typedef struct _cookie {
           char magic[8]; /* 'MEI\014\013\012\013\016' */
           uint32_t len;  /* len of entire package */
           uint32_t TOC;  /* pos (rel to start) of TableOfContents */
           int  TOClen;   /* length of TableOfContents */
           int  pyvers;   /* new in v4 */
           char pylibname[64];    /* Filename of Python dynamic library. */
        } COOKIE;


    Args:
        cookie: Cookie struct

    Returns:
        dict of parsed cookie
    """
    clen = len(cookie)
    for fmt, keys in COOKIE_FORMATS.items():
        if clen == struct.calcsize(fmt):
            values = struct.unpack(fmt, cookie)
            break
    else:  # no break
        raise Invalid

    results = dict(zip(keys, values))

    if "py_lib" in results:
        results["py_lib"] = results["py_lib"].rstrip(b"\x00")

    return results


def parse_toc(toc: bytes) -> dict[str, dict]:
    """Parse the table of contents into a list of files within the installer.

    TOC:
       format: '!iIIIBB'

       typedef struct _toc {
           int  structlen;  /* len of this one - including full len of name */
           uint32_t pos;    /* pos rel to start of concatenation */
           uint32_t len;    /* len of the data (compressed) */
           uint32_t ulen;   /* len of data (uncompressed) */
           char cflag;      /* is it compressed (really a byte) */
           char typcd;      /* type code -'b' binary, 'z' zlib, 'm' module,
                             * 's' script (v3),'x' data, 'o' runtime option  */
           char name[1];    /* the name to save it as */
                            /* starting in v5, we stretch this out to a mult of 16 */
       } TOC;

    Args:
        toc: Table of contents

    Returns:
        A map of filename to table of contents entries
    """
    toc_details = {}

    while len(toc) > 0:
        struct_len, offset, clen, ulen, cflag, tcode = struct.unpack(TOC_RECORD_FORMAT, toc[:TOC_RECORD_LENGTH])

        entry = toc[0:struct_len]
        name = entry[TOC_RECORD_LENGTH:].rstrip(b"\x00")
        try:
            name = name.decode("utf-8")
        except UnicodeDecodeError:
            # malformed pyinstaller file
            name = safe_str(name)

        toc_details[name] = {
            "size": struct_len,
            "offset": offset,
            "compressed_size": clen,
            "decompressed_size": ulen,
            "compressed_flag": cflag,
            "entry_type": tcode,
        }

        # move to next
        toc = toc[struct_len:]
    return toc_details


def generate_pyc_header(major: int, minor: int) -> bytes:
    """Create a fake header for pyc files.

    Scripts included by PyInstaller do not have a header attached.

    Args:
        major: major python version
        minor: minor python version

    Returns:
        A Zeroed out fake header of correct length
    """
    # attempt to match correct version
    v = xdis.magics.by_version.get(f"{major}.{minor}")
    if not v:
        # unknown, set blank
        v = b"\x00" * 4
    header = [v]

    # Check version for PEP552: https://peps.python.org/pep-0552/
    if major >= 3 and minor >= 7:
        header.append(b"\x00" * 4)  # bitfield
        header.append(b"\x00" * 8)  # modification date + size
    else:
        header.append(b"\x00" * 4)  # timestamp
        if major >= 3 and minor >= 3:
            header.append(b"\x00" * 4)  # size
    return b"".join(header)


def extract_pyc(contents: bytes) -> list[tuple[str, bytes]]:
    """Extract all scripts.

    Args:
        contents: PyInstaller file buffer

    Returns:
        extracted contents
    """
    package, cookie = find_carchive(contents)

    ck = parse_cookie(cookie)

    toc = parse_toc(package[ck["toc_index"] : ck["toc_index"] + ck["toc_size"]])
    if toc is None:
        raise Invalid

    results = []
    scripts = find_scripts(package, toc)
    for script in scripts:
        # pyc have nulls in first 16 bytes
        # PyInstaller bundles them without the header, so it must be generated and added.
        if script[1][:16].find(b"\x00") > -1:
            name = f"{script[0]}.pyc"
            # saved as int of string repr.
            # ie: 2.7 = 27, 3.9 = 39, 3.10 = 310
            vers = str(ck.get("py_version"))
            # don't append header if we don't know what version it is... we will just end up with an invalid file
            # this should only happen on older versions of PyInstaller
            if vers:
                s = generate_pyc_header(int(vers[0]), int(vers[1:])) + script[1]
            else:
                s = script[1]
        else:
            name = f"{script[0]}.py"
            s = script[1]
        results.append((name, s))

    return results
