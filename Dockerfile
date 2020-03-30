FROM cccs/assemblyline-v4-service-base:latest AS base

ENV SERVICE_PATH extract.extract.Extract

USER root

RUN echo "deb http://http.us.debian.org/debian stretch main contrib non-free" >> /etc/apt/sources.list

RUN apt-get update && apt-get install -y libssl1.1 p7zip-full p7zip-rar unace-nonfree poppler-utils python-lxml unrar && rm -rf /var/lib/apt/lists/*


FROM base AS build

RUN apt-get update && apt-get install -y build-essential libssl-dev && rm -rf /var/lib/apt/lists/*

USER assemblyline

# Install pip packages
RUN touch /tmp/before-pip
RUN pip install --no-cache-dir --user tnefparse olefile beautifulsoup4 pylzma lxml && rm -rf ~/.cache/pip

# Download the support files from Amazon S3
RUN aws s3 cp s3://assemblyline-support/msoffice.tar.gz /tmp
RUN aws s3 cp s3://assemblyline-support/cybozulib.tar.gz /tmp

# Extract the tar files and make msoffice
USER root
RUN mkdir -p /opt/al/support/extract
RUN tar -zxf /tmp/msoffice.tar.gz -C /opt/al/support/extract
RUN tar -zxf /tmp/cybozulib.tar.gz -C /opt/al/support/extract
RUN make -C /opt/al/support/extract/msoffice -j RELEASE=1

# Remove files that existed before the pip install so that our copy command below doesn't take a snapshot of
# files that already exist in the base image
RUN find /var/lib/assemblyline/.local -type f ! -newer /tmp/before-pip -delete

# change the ownership of the files to be copied due to bitbucket pipeline uid nonsense
RUN chown root:root -R /var/lib/assemblyline/.local
RUN chown root:root -R /opt/al/support

FROM base

COPY --from=build /opt/al/support /opt/al/support
COPY --chown=assemblyline:assemblyline --from=build /var/lib/assemblyline/.local /var/lib/assemblyline/.local

# Switch to assemblyline user
USER assemblyline

# Clone Extract service code
WORKDIR /opt/al_service
COPY . .