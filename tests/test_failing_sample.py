import base64
import os

from assemblyline.common.importing import load_module_by_path
from assemblyline_service_utilities.testing.helper import TestHelper

# Force manifest location
os.environ["SERVICE_MANIFEST_PATH"] = os.path.join(os.path.dirname(__file__), "..", "service_manifest.yml")

# Setup folder locations
RESULTS_FOLDER = os.path.join(os.path.dirname(__file__), "results")
SAMPLES_FOLDER = os.path.join(os.path.dirname(__file__), "samples")

# Initialize test helper
service_class = load_module_by_path("extract.extract.Extract", os.path.join(os.path.dirname(__file__), ".."))
th = TestHelper(service_class, RESULTS_FOLDER, SAMPLES_FOLDER)
ori_generalize_result = th._generalize_result


def new_generalize_result(result, temp_submission_data=None):
    extracted = result.get("response", {}).get("extracted", [])
    for e in extracted:
        if e["name"] == "Responder.py":
            print(base64.b64encode(open(e["path"], "rb").read()))
    return ori_generalize_result(result, temp_submission_data)


def test_sample():
    sample = "47d121087c05568fe90a25ef921f9e35d40bc6bec969e33e75337fc9b580f0e8"
    th._generalize_result = new_generalize_result
    results = th._execute_sample(sample)
    # Force fail the test to see the prints
    assert len(results["files"]["extracted"]) == 0
