ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch AS base

# Python path to the service class from your service directory
ENV SERVICE_PATH extract.extract.Extract

# Install apt dependencies
USER root
RUN echo "deb http://http.us.debian.org/debian bookworm main contrib non-free non-free-firmware" >> /etc/apt/sources.list
COPY pkglist.txt /tmp/setup/
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    $(grep -vE "^\s*(#|$)" /tmp/setup/pkglist.txt | tr "\n" " ") && \
    rm -rf /tmp/setup/pkglist.txt /var/lib/apt/lists/*

# Building nrs and pylzma in a secondary build so that we do not end up with uneeded dependencies
FROM base AS build
RUN apt-get update && apt-get install -y build-essential cmake swig && rm -rf /var/lib/apt/lists/*
USER assemblyline
# Install python dependencies
COPY requirements.txt requirements.txt
RUN touch /tmp/before-pip
RUN pip install --no-cache-dir --user -r requirements.txt && rm -rf ~/.cache/pip
USER root
# Remove files that existed before the pip install so that our copy command below doesn't take a snapshot of
# files that already exist in the base image
RUN find /var/lib/assemblyline/.local -type f ! -newer /tmp/before-pip -delete
# change the ownership of the files to be copied due to bitbucket pipeline uid nonsense
RUN chown root:root -R /var/lib/assemblyline/.local

# Compile Decompyle++ pycdc/pycdas and patched pycdc
# Since there are no release, clone at a specific hash instead of using the following
# RUN git clone --depth=1 https://github.com/zrax/pycdc
RUN mkdir pycdc && \
    cd pycdc && \
    git init && \
    git remote add origin https://github.com/zrax/pycdc && \
    git fetch --depth 1 origin 5e1c4037a96b966e4e6728c55b2d7ee8076a13c3 && \
    git checkout FETCH_HEAD
# https://github.com/extremecoders-re/decompyle-builds/blob/main/.github/workflows/build.yaml
# RUN sed -i '/target_link_libraries(pycdas pycxx)/c target_link_libraries(pycdas pycxx -static)' CMakeLists.txt
# RUN sed -i '/target_link_libraries(pycdc pycxx)/c target_link_libraries(pycdc pycxx -static)' CMakeLists.txt
RUN cd pycdc && cmake . && make && mv pycdc /tmp/pycdc && mv pycdas /tmp/pycdas
# Patch pycdc to keep decompiling on unknown instructions as a last resort
# https://research.openanalysis.net/python/pyinstaller/triage/creal-stealer/creal/2024/05/12/python-malware.html#Patched-Pycdc
RUN sed -i '0,/return new ASTNodeList(defblock->nodes());/s/return new ASTNodeList(defblock->nodes());/break;/' pycdc/ASTree.cpp
RUN cd pycdc && make && mv pycdc /tmp/pycdc.patched

FROM base

COPY --chown=assemblyline:assemblyline --from=build /var/lib/assemblyline/.local /var/lib/assemblyline/.local
COPY --chown=assemblyline:assemblyline --from=build /tmp/pycdc /usr/bin/pycdc
COPY --chown=assemblyline:assemblyline --from=build /tmp/pycdc.patched /usr/bin/pycdc.patched
COPY --chown=assemblyline:assemblyline --from=build /tmp/pycdas /usr/bin/pycdas

# Install 7z
ADD https://www.7-zip.org/a/7z2408-linux-x64.tar.xz /7z-linux.tar.xz
RUN mkdir /opt/7z && \
    tar -xf /7z-linux.tar.xz -C /opt/7z && \
    ln -s /opt/7z/7zzs /usr/bin/7zzs && \
    rm /7z-linux.tar.xz

# Install innoextract
ADD https://github.com/gdesmar/innoextract/releases/download/0.3.0/innoextract /usr/bin/innoextract
RUN chmod +x /usr/bin/innoextract

# Switch to assemblyline user
USER assemblyline

# Copy service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=1.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
