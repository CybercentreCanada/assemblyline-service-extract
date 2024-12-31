import subprocess
import tempfile

from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import ResultTextSection


def decompile_pyc(request: ServiceRequest, filepath: str, output_directory) -> str:
    disass_file = tempfile.NamedTemporaryFile("w", dir=output_directory, delete=False)
    embedded_filename = "UnknownFilename.py"
    p = subprocess.run(
        ["pycdas", filepath, "-o", disass_file.name],
        cwd=output_directory,
        capture_output=True,
        check=False,
    )
    with open(disass_file.name, "r") as f:
        for line in f:
            if line.startswith("    File Name:"):
                embedded_filename = line[14:].strip()

    decompiled_file = tempfile.NamedTemporaryFile("w", dir=output_directory, delete=False)
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

    return decompiled_file.name, embedded_filename, disass_file.name
