import errno
import glob
import json
import os
from pathlib import Path

import pytest
from assemblyline.common import forge
from assemblyline.common.dict_utils import flatten
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline_v4_service.common import helper
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.task import Task
from cart import unpack_file

from extract.extract import Extract

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(TEST_DIR)
SELF_LOCATION = os.environ.get("FULL_SELF_LOCATION", ROOT_DIR)
SAMPLES_LOCATION = os.environ.get("FULL_SAMPLES_LOCATION", None)
identify = forge.get_identify(use_cache=False)
submission_params = helper.get_service_attributes().submission_params


def find_sample(locations, sample):
    # Assume samples are carted
    sample = f"{sample}.cart"

    for location in locations:
        p = [path for path in Path(location).rglob(sample)]
        if len(p) == 1:
            return p[0]

    raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), sample)


def list_results(location):
    return [f.rstrip(".json") for f in os.listdir(os.path.join(location, "tests", "results"))]


@pytest.fixture()
def sample(request):
    sample_path = find_sample(request.cls.locations, request.param)
    unpack_file(sample_path, os.path.join("/tmp", request.param))
    yield request.param
    os.remove(os.path.join("/tmp", request.param))


def create_service_task(sample):
    fileinfo_keys = ["magic", "md5", "mime", "sha1", "sha256", "size", "type"]

    return ServiceTask(
        {
            "sid": 1,
            "metadata": {},
            "deep_scan": False,
            "service_name": "Not Important",
            "service_config": {param.name: param.default for param in submission_params},
            "fileinfo": {k: v for k, v in identify.fileinfo(f"/tmp/{sample}").items() if k in fileinfo_keys},
            "filename": sample,
            "min_classification": "TLP:WHITE",
            "max_files": 501,
            "ttl": 3600,
        }
    )


def generalize_result(result):
    # At first we were comparing the full result and removing the random/unpredictable information.
    # Now we are only keeping the strict minimum to compare with.
    # supplementary/extracted sha256 + heuristics heur_id + tags
    trimed_result = {}
    if "response" in result:
        trimed_result["response"] = {}
        if "supplementary" in result["response"]:
            trimed_result["response"]["supplementary"] = sorted(
                [x["sha256"] for x in result["response"]["supplementary"]]
            )
        if "extracted" in result["response"]:
            trimed_result["response"]["extracted"] = sorted(
                [{"name": x["name"], "sha256": x["sha256"]} for x in result["response"]["extracted"]],
                key=lambda x: x["sha256"],
            )

    if "result" in result:
        trimed_result["result"] = {}
        if "sections" in result["result"]:
            trimed_result["result"] = {"heuristics": [], "tags": {}}
            for section in result["result"]["sections"]:
                if "heuristic" in section:
                    if section["heuristic"] is not None:
                        if "heur_id" in section["heuristic"]:
                            trimed_result["result"]["heuristics"].append(section["heuristic"]["heur_id"])
                if "tags" in section:
                    if section["tags"]:
                        for k, v in flatten(section["tags"]).items():
                            if k in trimed_result["result"]["tags"]:
                                trimed_result["result"]["tags"][k].extend(v)
                            else:
                                trimed_result["result"]["tags"][k] = v

            # Sort the heur_id and tags lists so they always appear in the same order even if
            # the result sections where moved around.
            trimed_result["result"]["heuristics"] = sorted(trimed_result["result"]["heuristics"])
            for k, v in trimed_result["result"]["tags"].items():
                trimed_result["result"]["tags"][k] = sorted(v)

    return trimed_result


class TestService:
    @classmethod
    def setup_class(cls):
        # Setup where the samples can be found
        cls.locations = [SELF_LOCATION, SAMPLES_LOCATION]

    @staticmethod
    @pytest.mark.parametrize("sample", list_results(SELF_LOCATION), indirect=True)
    # @pytest.mark.skip() # Can remove the skip since there is no test pipeline.
    def test_service(sample):
        overwrite_results = False  # Used temporarily to mass-correct tests

        cls = Extract()
        cls.start()

        task = Task(create_service_task(sample=sample))
        service_request = ServiceRequest(task)

        cls.execute(service_request)

        result_dir_files = [
            os.path.basename(x) for x in glob.glob(os.path.join(SELF_LOCATION, "tests", "results", sample, "*"))
        ]

        # Get the result of execute() from the test method
        test_result = task.get_service_result()

        result_dir_files.remove("result.json")
        # Get the assumed "correct" result of the sample
        correct_path = os.path.join(SELF_LOCATION, "tests", "results", sample, "result.json")
        with open(correct_path, "r") as f:
            correct_result = json.load(f)

        test_result = generalize_result(test_result)

        if overwrite_results:
            if test_result != correct_result:
                with open(correct_path, "w") as f:
                    json.dump(test_result, f)
        else:
            assert test_result == correct_result

        assert not result_dir_files


class TestServiceWithCustomConfig:
    @classmethod
    def setup_class(cls):
        # Setup where the samples can be found
        cls.locations = [SELF_LOCATION, SAMPLES_LOCATION]

    @staticmethod
    @pytest.mark.parametrize(
        "sample", ["5d94d263cdc7d64aae798d93e14d06c633b8967f137ab83c78d41387271326dd"], indirect=True
    )
    # @pytest.mark.skip() # Can remove the skip since there is no test pipeline.
    def test_passworded_zip_file(sample):
        cls = Extract()
        cls.start()

        task = Task(create_service_task(sample=sample))
        task.service_config["password"] = "rekings.com"
        service_request = ServiceRequest(task)

        cls.execute(service_request)

        # Get the result of execute() from the test method
        test_result = task.get_service_result()

        print(test_result)
        assert len(test_result["response"]["supplementary"]) == 0
        assert len(test_result["response"]["extracted"]) == 11
        heuristics = []
        tags = {}
        for section in test_result["result"]["sections"]:
            if "heuristic" in section:
                if section["heuristic"] is not None:
                    if "heur_id" in section["heuristic"]:
                        heuristics.append(section["heuristic"]["heur_id"])
            if "tags" in section:
                if section["tags"]:
                    for k, v in flatten(section["tags"]).items():
                        if k in tags:
                            tags[k].extend(v)
                        else:
                            tags[k] = v
        assert heuristics == [10]
        assert tags == {
            "info.password": ["rekings.com"],
            "file.behavior": ["Executable Content in Archive"],
            "file.name.extracted": [
                "WinMM.Net.dll",
                "njRAT v0.7d.exe",
                "Plugin/cam.dll",
                "Plugin/ch.dll",
                "Plugin/sc2.dll",
                "Plugin/plg.dll",
                "Plugin/pw.dll",
                "Plugin/mic.dll",
            ],
        }


class TestServiceWithRequestTempSubmissionData:
    @classmethod
    def setup_class(cls):
        # Setup where the samples can be found
        cls.locations = [SELF_LOCATION, SAMPLES_LOCATION]

    @staticmethod
    @pytest.mark.parametrize(
        "sample", ["1b61b16dd4b7f6203d742b47411ca679f1f5734ed01534a37a126263f84396c0"], indirect=True
    )
    # @pytest.mark.skip() # Can remove the skip since there is no test pipeline.
    def test_html_file_with_password(sample):
        cls = Extract()
        cls.start()

        task = Task(create_service_task(sample=sample))
        service_request = ServiceRequest(task)

        cls.execute(service_request)
        assert service_request.temp_submission_data["passwords"] == ["U523"]
