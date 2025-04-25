import os
import subprocess
import tempfile

from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import ResultTextSection


def decompile_pyc(request: ServiceRequest, filepath: str, output_directory) -> str:
    encoded_input_filename = os.path.basename(filepath).encode()
    disass_file = tempfile.NamedTemporaryFile("w", suffix=".disass", dir=output_directory, delete=False)
    filtered_disass_file = tempfile.NamedTemporaryFile(
        "w", suffix=".filtered.disass", dir=output_directory, delete=False
    )
    embedded_filename = "UnknownFilename.py"
    p = subprocess.run(
        ["pycdas", filepath, "-o", disass_file.name],
        cwd=output_directory,
        capture_output=True,
        check=False,
    )
    with open(disass_file.name, "rb") as fin:
        with open(filtered_disass_file.name, "wb") as fout:
            for line in fin:
                if line.startswith(encoded_input_filename + b" (Python"):
                    line = line.replace(encoded_input_filename, b"INPUT.pyc")
                fout.write(line)
                if line.startswith(b"    File Name:"):
                    try:
                        embedded_filename = line[14:].strip().decode()
                    except Exception:
                        pass

    decompiled_file = tempfile.NamedTemporaryFile("w", suffix=".py", dir=output_directory, delete=False)
    filtered_decompiled_file = tempfile.NamedTemporaryFile(
        "w", suffix=".filtered.py", dir=output_directory, delete=False
    )
    p = subprocess.run(
        ["pycdc", filepath, "-o", decompiled_file.name],
        cwd=output_directory,
        capture_output=True,
        check=False,
    )
    if p.stderr:
        patched_pycdc = ResultTextSection("Fallback to patched pycdc")
        patched_pycdc.add_line("Error using normal pycdc:")
        error_lines = []
        for error_line in p.stderr.split(b"\n"):
            error_line = error_line.replace(filepath.encode(), b"/TMP_DIR/INPUT.pyc")
            if error_line not in error_lines:
                error_lines.append(error_line)
                patched_pycdc.add_line(error_line)
        request.result.add_section(patched_pycdc)
        p = subprocess.run(
            ["pycdc.patched", filepath, "-o", decompiled_file.name],
            cwd=output_directory,
            capture_output=True,
            check=False,
        )

    with open(decompiled_file.name, "rb") as fin:
        with open(filtered_decompiled_file.name, "wb") as fout:
            for line in fin:
                if line.startswith(b"# File: " + encoded_input_filename + b" (Python"):
                    line = line.replace(encoded_input_filename, b"INPUT.pyc")
                fout.write(line)

    return filtered_decompiled_file.name, embedded_filename, filtered_disass_file.name
