# syntax=docker/dockerfile:1.1-experimental

# Copyright 2020 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


ARG BASE_IMAGE=docker.io/library/ubuntu:latest
FROM $BASE_IMAGE

ENV LC_CTYPE=POSIX
ENV OVFTOOL_FILENAME=VMware-ovftool-4.4.3-18663434-lin.x86_64.bundle
ENV PATH="/root/.local/bin:$PATH"
ADD $OVFTOOL_FILENAME /tmp/

RUN apt-get update && apt-get install -y apt-transport-https build-essential ca-certificates curl gcc genisoimage git bash jq libffi-dev libssl-dev make openssh-client openssl python3-dev python3-pip rsync sed sshpass unzip vim wget xorriso  \
    && useradd -ms /bin/bash imagebuilder \
    && apt-get purge --auto-remove -y \
    && rm -rf /var/lib/apt/lists/*

# add imagebuilder user to sudoers
RUN echo "imagebuilder ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

ARG ARCH
ARG PASSED_IB_VERSION


RUN curl -L https://vault.bitwarden.com/download/\?app\=cli\&platform\=linux > bitwarden.zip
RUN unzip bitwarden.zip
RUN mv bw /usr/local/bin/bw
RUN chmod +x /usr/local/bin/bw
RUN rm bitwarden.zip

RUN curl -fL https://getcli.jfrog.io | sh
RUN mv jfrog /usr/local/bin/jfrog
RUN chmod +x /usr/local/bin/jfrog
RUN jfrog -v

# get version from https://github.com/vmware/govmomi/releases/latest
ENV VERSION=v0.30.4
ENV URL=https://github.com/vmware/govmomi/releases/download/${VERSION}/govc_Linux_x86_64.tar.gz
RUN curl -L -o - $URL | tar -C /usr/local/bin -xvzf - govc
RUN chmod +x /usr/local/bin/govc
RUN govc version

RUN /bin/sh /tmp/$OVFTOOL_FILENAME --console --required --eulas-agreed && \
    rm -f /tmp/$OVFTOOL_FILENAME

## run chmod 777 on /home/imagebuilder to allow imagebuilder user to write to the directory
RUN chmod 777 /home/imagebuilder

USER imagebuilder
WORKDIR /home/imagebuilder/

COPY --chown=imagebuilder:imagebuilder ansible ansible/
COPY --chown=imagebuilder:imagebuilder ansible.cfg ansible.cfg
COPY --chown=imagebuilder:imagebuilder cloudinit cloudinit/
COPY --chown=imagebuilder:imagebuilder hack hack/
COPY --chown=imagebuilder:imagebuilder packer packer/
COPY --chown=imagebuilder:imagebuilder Makefile Makefile
COPY --chown=imagebuilder:imagebuilder azure_targets.sh azure_targets.sh

ENV PATH="/home/imagebuilder/.local/bin:${PATH}"
ENV PACKER_ARGS ''
ENV PACKER_VAR_FILES ''
ENV IB_VERSION "${PASSED_IB_VERSION}"

RUN make deps
RUN pip install pyVmomi tools pyvim dohq-artifactory pyyaml tqdm


ENTRYPOINT [ "/usr/bin/make" ]
