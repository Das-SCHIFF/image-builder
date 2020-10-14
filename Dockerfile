FROM registry.devops.telekom.de/t-dci-image-building/helper-docker-images/packer:ubuntu
COPY images/capi/ /tmp
WORKDIR /tmp
ENV PATH="/root/.local/bin:$PATH"
RUN make deps-ova