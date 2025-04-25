# Monkeypatch uncompyle6's print_doctstring function.
# Unfortunately we can't get in early enough due to way __init__ is structured, so each use case must be patched.
import uncompyle6
from uncompyle6.semantics import customize38
from uncompyle6.semantics.consts import TABLE_DIRECT

orig_customize_for_version38 = customize38.customize_for_version38


# TODO: Remove this when using a version of uncompyle6 newer than 3.9.1
# Fixed in https://github.com/rocky/python-uncompyle6/issues/498
def patched_customize_for_version38(self, version):
    orig_customize_for_version38(self, version)
    TABLE_DIRECT["whilestmt38"] = (
        "%|while %c:\n%+%c%-\n\n",
        (1, ("bool_op", "testexpr", "testexprc")),
        (2, ("l_stmts", "l_stmts_opt", "pass", "_stmts")),
    )


customize38.customize_for_version38 = patched_customize_for_version38


orig_print_docstring = uncompyle6.pysource.print_docstring


def patched_print_docstring(self, indent, docstring):
    """Function to monkey patch the handling of binary docstrings."""
    if isinstance(docstring, bytes):
        docstring = docstring.decode("utf8", errors="backslashreplace")
    return orig_print_docstring(self, indent, docstring)


uncompyle6.pysource.print_docstring = patched_print_docstring
from uncompyle6.semantics import helper

helper.print_docstring = patched_print_docstring
from uncompyle6.semantics import make_function1, make_function2, make_function3

make_function1.print_docstring = patched_print_docstring
make_function2.print_docstring = patched_print_docstring
make_function3.print_docstring = patched_print_docstring
# end monkeypatch

import os
import re
import sys
import tempfile
import traceback
from io import StringIO

import xdis.magics


class Invalid(Exception):
    """Not a valid pyc file"""


class XDisError(Exception):
    """The XDis library raised an error"""


def decompile_pyc(filepath: str, output_directory) -> str:
    """Decompile the given pyc file.

    Args:
        filepath: path to pyc file

    Returns:
        The filepath to the decompiled script.
    """
    script = None
    embedded_filename = None
    with open(filepath, "rb") as f:
        header = f.read(4)
    try:
        _ = xdis.magics.magic_int2tuple(xdis.magics.magic2int(header))
    except KeyError:
        # unknown magic, either xdis magic list needs updating or it's not a real pyc magic
        raise Invalid

    # uncompyle6 requires filename ends with pyc
    fname = os.path.basename(filepath)
    sym = False
    if not fname.endswith(".pyc"):
        fname = f"{fname}.pyc"
        sym = True
        os.link(filepath, f"{filepath}.pyc")

    # decompile to stdout so we can strip uncompyle's comments and be left with the actual source
    stdout = sys.stdout
    stderr = sys.stderr
    out = StringIO()
    err = StringIO()
    sys.stdout = out
    sys.stderr = err
    try:
        _ = uncompyle6.main.main(
            in_base=os.path.dirname(filepath),
            out_base=None,
            compiled_files=[fname],
            source_files=[],
            outfile=None,
        )
    except NameError as e:
        # TODO: Remove this when using a version of uncompyle6 newer than 3.9.1
        # Fixed in https://github.com/rocky/python-uncompyle6/commit/b0b67e9f34c53ad4a76d5c30d171f10d909f443b
        if str(e) != "name 'ParserError2' is not defined":
            raise
        return script, embedded_filename
    except AssertionError:
        # `xdis` has multiple `assert`s to validate that the code it is generating make sense.
        # if one of these `assert`s fails, then chances are the pyc was corrupt, malformed, protected
        # or there's a bug with `xdis`' parsing.
        raise Invalid
    except ImportError:
        # likely an incorrectly or unimplemented code by uncompyle:
        # bad marshal data (unknown type code)
        raise Invalid
    except IndexError as e:
        last_frame = traceback.extract_tb(sys.exc_info()[-1])[-1]
        if last_frame.filename.startswith(os.path.dirname(xdis.__file__)):
            raise XDisError() from e
        raise
    finally:
        sys.stdout = stdout
        sys.stderr = stderr
        if sym:
            os.unlink(f"{filepath}.pyc")

    err = err.getvalue()
    if err:
        # uncompyle6 only supports up to 3.8, we could check explicitly for this, but that then requires updating this.
        # instead, just attempt to decompile so if new versions are release, only a package update is needed.
        if re.search("^# Unsupported Python version, (.+), for decompilation$", err, re.MULTILINE):
            return script, embedded_filename

    out = out.getvalue()
    if out:
        m = re.search("^# Embedded file name: (.*)$", out, re.MULTILINE)
        if m:
            embedded_filename = m.groups()[0]
        with tempfile.NamedTemporaryFile("w", dir=output_directory, delete=False) as tf:
            script = tf.name
            for line in out.splitlines(keepends=True):
                if not line.startswith("#"):
                    tf.write(line)

    return script, embedded_filename
