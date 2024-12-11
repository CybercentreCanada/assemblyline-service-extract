ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch AS base

# Set service to be run
ENV SERVICE_PATH extract.extract.Extract

# Switch to root user
USER root

RUN echo "deb http://http.us.debian.org/debian bookworm main contrib non-free non-free-firmware" >> /etc/apt/sources.list

# Install apt dependencies
COPY pkglist.txt pkglist.txt
RUN apt-get update && grep -vE '^#' pkglist.txt | xargs apt-get install -y && rm -rf /var/lib/apt/lists/*

# Building nrs and pylzma in a secondary build so that we do not end up with uneeded dependencies
FROM base AS build
RUN apt-get update && apt-get install -y build-essential swig && rm -rf /var/lib/apt/lists/*
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

FROM base

COPY --chown=assemblyline:assemblyline --from=build /var/lib/assemblyline/.local /var/lib/assemblyline/.local

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
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
