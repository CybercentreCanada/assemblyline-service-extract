ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch AS base

ENV SERVICE_PATH extract.extract.Extract

USER root

RUN echo "deb http://http.us.debian.org/debian stretch main contrib non-free" >> /etc/apt/sources.list

RUN apt-get update && apt-get install -y libssl1.1 unace-nonfree python-lxml unrar && rm -rf /var/lib/apt/lists/*

FROM base AS build

RUN apt-get update && apt-get install -y build-essential libssl-dev wget && rm -rf /var/lib/apt/lists/*

USER assemblyline

# Install pip packages
RUN touch /tmp/before-pip
RUN pip install --no-cache-dir --user tnefparse olefile beautifulsoup4 pylzma lxml msoffcrypto-tool html5lib pikepdf && rm -rf ~/.cache/pip

# Download the support files from Amazon S3
RUN wget -O /tmp/cybozulib.tar.gz https://assemblyline-support.s3.amazonaws.com/cybozulib.tar.gz

# Extract the tar files and make msoffice
USER root
RUN mkdir -p /opt/al/support/extract
RUN tar -zxf /tmp/cybozulib.tar.gz -C /opt/al/support/extract

# Remove files that existed before the pip install so that our copy command below doesn't take a snapshot of
# files that already exist in the base image
RUN find /var/lib/assemblyline/.local -type f ! -newer /tmp/before-pip -delete

# change the ownership of the files to be copied due to bitbucket pipeline uid nonsense
RUN chown root:root -R /var/lib/assemblyline/.local
RUN chown root:root -R /opt/al/support

FROM base

COPY --from=build /opt/al/support /opt/al/support
COPY --chown=assemblyline:assemblyline --from=build /var/lib/assemblyline/.local /var/lib/assemblyline/.local

ADD https://www.7-zip.org/a/7z2201-linux-x86.tar.xz /7z2201-linux-x86.tar.xz
RUN mkdir /opt/7z && tar -xf /7z2201-linux-x86.tar.xz -C /opt/7z
RUN ln -s /opt/7z/7zzs /usr/bin/7zzs

# Switch to assemblyline user
USER assemblyline

# Clone Extract service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
