FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH extract.extract.Extract

USER root

RUN echo "deb http://http.us.debian.org/debian stretch main contrib non-free" >> /etc/apt/sources.list

RUN apt-get update && apt-get install -y build-essential libssl-dev p7zip-full p7zip-rar unace-nonfree poppler-utils python-lxml unrar && rm -rf /var/lib/apt/lists/*

USER assemblyline

# Download the support files from Amazon S3
RUN aws s3 cp s3://assemblyline-support/msoffice.tar.gz /tmp
RUN aws s3 cp s3://assemblyline-support/cybozulib.tar.gz /tmp

USER root

# Extract the tar files and make msoffice
RUN mkdir -p /opt/al/support/extract
RUN tar -zxf /tmp/msoffice.tar.gz -C /opt/al/support/extract
RUN tar -zxf /tmp/cybozulib.tar.gz -C /opt/al/support/extract
RUN make -C /opt/al/support/extract/msoffice -j RELEASE=1

# Cleanup
RUN rm -rf /tmp/*

# Switch to assemblyline user
USER assemblyline

# Install pip packages
RUN pip install --user tnefparse olefile beautifulsoup4 pylzma lxml && rm -rf ~/.cache/pip

# Clone Extract service code
WORKDIR /opt/al_service
COPY . .