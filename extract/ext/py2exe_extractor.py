"""Extract python bytecode from an executable compiled by py2exe.

references: https://github.com/mitre/pydecipher/blob/master/pydecipher/artifact_types/py2exe.py
"""

import io
import re
import struct
import tempfile
import zipfile
from pathlib import Path

import lief
import xdis.magics
import xdis.marsh
from xdis.unmarshal import load_code

from .pyinstaller import generate_pyc_header


PYTHON_DLL_RE = re.compile(b"python([0-9]{2,3})\.dll", re.IGNORECASE)
SCRIPT_MAGIC = b"\x12\x34\x56\x78"

# struct scriptinfo {
# 	int tag;
# 	int optimize;
# 	int unbuffered;
# 	int data_len;
#
# 	char zippath[0];
# };
SCRIPT_HEADER_FORMAT = "<iiii"
SCRIPT_HEADER_SIZE = struct.calcsize(SCRIPT_HEADER_FORMAT)

lief.logging.disable()


class Invalid(Exception):
    """Not a valid Py2EXE file."""


class NoVersion(Exception):
    """Cannot determine the compiled python version."""


def get_pyver_from_archive(binary: lief.PE.Binary) -> tuple[int, int]:
    """Parse the emedded zip archive if it is present and extract version information from files.

    Note: this could be extended to extract all embedded pyc files as well.

    Args:
        binary: parsed bianry object from lief.

    Returns:
        python version tuple
    """

    overlay = binary.overlay.tobytes()
    if not overlay or overlay[:4] != b"PK\x03\x04":
        return None

    try:
        compressed = zipfile.ZipFile(io.BytesIO(overlay))
    except zipfile.BadZipFile:
        return None

    for f in compressed.filelist:
        if f.filename.lower().endswith(".pyc"):
            pyc = compressed.open(f.filename)
            magic = pyc.read(4)
            vers = None
            try:
                major, minor, *_ = xdis.magics.magic_int2tuple(xdis.magics.magic2int(magic))
                vers = (major, minor)
            except KeyError:
                # possibly not a valid pyc file, or unknown magic. keep trying others.
                pass
            if vers:
                break
    return vers


def extract_script(content: bytes) -> tuple[bytes, tuple[int, int]]:
    """Extract the Py2EXE script resource.

    The python script is embedded in the .rsrc section of the PE.

    Returns:
        (extract PYTHONSCRIPT resource, detected python version)
    """

    binary = lief.parse(raw=content)
    if not binary or not isinstance(binary, lief.PE.Binary) or not binary.has_resources:
        raise Invalid

    # look for embedded PYTHONSCRIPT resource
    root = binary.resources
    # First level => Type (ResourceDirectory node)
    try:
        script_node = next(n for n in root.childs if n.has_name and n.name.upper() == "PYTHONSCRIPT")
    except StopIteration:
        raise Invalid

    try:
        # Second level => ID (ResourceDirectory node)
        id_node = script_node.childs[0]
        # Third level => Lang (ResourceData node)
        lang_node = id_node.childs[0]
    except IndexError:
        raise Invalid

    script = lang_node.content.tobytes()

    # determine py version.
    # check if python dll has been bundled in. (eg: resource name = PYTHON310.DLL)
    for node in root.childs:
        if node.has_name and (m := PYTHON_DLL_RE.search(node.name.encode("utf8"))):
            break
    else:  # no break
        # could not find a bundled version of python.dll, search content for a reference
        m = PYTHON_DLL_RE.search(content)

    if not m:
        # check if archive was bundled into overlay
        ver = get_pyver_from_archive(binary=binary)
        if not ver:
            raise NoVersion
    else:
        ver_str = m.groups()[0].decode("utf8")
        ver = (int(ver_str[0]), int(ver_str[1:]))

    return script, ver


def extract_code_objects(script: bytes, py_version: tuple[int, int], outdir: Path) -> dict[Path, str]:
    """Extract the code objects from the script resource.

    Args:
        script: extracted PYTHONSCRIPT resource
        py_version: python version tuple that the script was built on
        outdir: location to extract files to

    Returns:
        extracted file path to python script name mapping
    """
    (
        magic,
        _,
        _,
        code_len,
    ) = struct.unpack(SCRIPT_HEADER_FORMAT, script[:SCRIPT_HEADER_SIZE])
    if magic != int.from_bytes(SCRIPT_MAGIC, "little"):
        raise Invalid

    zip_path_len = script[SCRIPT_HEADER_SIZE:].find(b"\x00")
    # it's possible to extract the zip/archive path from this structure, which is the name of the bundle
    # containing all of the python dependencies that is required to be in the same dir as the exe to run.
    # should this name also be recorded?
    start_idx = SCRIPT_HEADER_SIZE + zip_path_len + 1
    pyscripts = script[start_idx : start_idx + code_len]

    # determine python magic
    try:
        ver = xdis.magics.version_tuple_to_str(py_version)
        magic = xdis.magics.by_version[ver]
    except KeyError:
        # xdis likely hasn't been updated with current python magics.
        # we can't unmarshal
        raise NoVersion(f"Unknown python version: {ver}")

    # py2exe stores all code objects in a list. Must unmarshal to separate out and extract what we are interested in.
    files = {}
    skip_names = ("boot_common.py",)
    for co in load_code(pyscripts, xdis.magics.magic2int(magic)):
        fname = co.co_filename
        # skip common, built in py2exe files
        if any(fname.endswith(skip_name) for skip_name in skip_names):
            continue
        # scripts can be named .py even though they are pyc files
        if fname.endswith(".py"):
            fname = f"{fname}c"
        elif not fname.endswith(".pyc"):
            continue

        # append pyc header to support possible decompilation later and save to disk
        try:
            dmp = xdis.marsh.dumps(co)
        except Exception:
            # lots could go wrong with xdis. just skip this file.
            raise Invalid
        pyc = generate_pyc_header(py_version[0], py_version[1]) + dmp
        with tempfile.NamedTemporaryFile(dir=outdir, delete=False) as f:
            f.write(pyc)
        files[Path(f.name)] = fname

    return files


def extract(content: bytes, outdir: Path = Path(tempfile.gettempdir())) -> dict[Path, str]:
    """Extract the pyc from the py2exe binary.

    Args:
        content: data bytes buffer of py2exe file.

    Returns:
        mapping of extracted filepath to embedded script name.
    """

    script, py_version = extract_script(content)
    return extract_code_objects(script, py_version, outdir)
