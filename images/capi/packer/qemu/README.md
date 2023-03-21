To build an image using a specific version of Kubernetes use the "PACKER_FLAGS" env var like in the example below:

PACKER_FLAGS="--var 'kubernetes_rpm_version=1.25.3-0' --var 'kubernetes_semver=v1.25.3' --var 'kubernetes_series=v1.25'  --var 'kubernetes_deb_version=1.25.3-00'" make build-kubevirt-qemu-ubuntu-2004

P.S: In order to change disk size(defaults to 20GB as of 31.10.22) you can update PACKER_FLAGS with:
--var 'disk_size=<disk size in mb>'