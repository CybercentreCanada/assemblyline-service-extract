#!/bin/bash
set -euo pipefail
docker build --pull --build-arg branch=stable -t cccs/${PWD##*/}:gentests -f ./Dockerfile .
docker run -t --rm -e FULL_SELF_LOCATION=/opt/al_service -e FULL_SAMPLES_LOCATION=/opt/samples -v /usr/share/ca-certificates/mozilla:/usr/share/ca-certificates/mozilla -v $(pwd)/tests/:/opt/al_service/tests/ -v ${FULL_SAMPLES_LOCATION}:/opt/samples cccs/${PWD##*/}:gentests bash -c "pip install -U -r tests/requirements.txt; python /opt/al_service/tests/gentests.py"
