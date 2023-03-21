# Building CAPI Images for IBMCLOUD (CAPIBM)

## CAPIBM - PowerVS

### Prerequisites for PowerVS Machine Image

- An IBM Cloud account
- PowerVS Service Instance
- Cloud Object Storage

### Building Images

The build [prerequisites](../capi.md#prerequisites) for using `image-builder` for building PowerVS images are managed by running:

```bash
cd image-builder/images/capi
make deps-powervs
```

From the `images/capi` directory, run `make build-powervs-centos-8`. The image is built and uploaded to your bucket capibm-powervs-{BUILD_NAME}-{KUBERNETES_VERSION}-{BUILD_TIMESTAMP}.

For building a centos-streams8 based CAPI image, run the following commands -

```bash
$ git clone https://github.com/kubernetes-sigs/image-builder.git
$ cd image-builder/images/capi/
$ ANSIBLE_SSH_ARGS="-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa" make build-powervs-centos-8
```

### Configuration

In addition to the configuration found in `images/capi/packer/config`, the `powervs` directory includes several JSON files that define the default configuration for the different operating systems.

| File | Description |
|------|-------------|
| `centos-8.json` | The settings for the CentOS 8 image |

#### Common PowerVS options

This table lists several common options that a user may want to set via `PACKER_VAR_FILES` to customize their build behavior.

| Variable | Description | Default |
|----------|-------------|---------|
| `account_id` | IBM Cloud account id. | `""` |
| `apikey` | IBM Cloud API key. | `""` |
| `capture_cos_access_key` | The Cloud Object Storage access key. | `""` |
| `capture_cos_bucket` | The Cloud Object Storage bucket to upload the image within. | `""` |
| `capture_cos_region` | The Cloud Object Storage region to upload the image within. | `""` |
| `capture_cos_secret_key` | The Cloud Object Storage secret key. | `""` |
| `key_pair_name` | The name of the SSH key pair provided to the server for authenticating users (looked up in the tenant's list of keys). | `""` |
| `region` | The PowerVS service instance region to build the image within. | `""` |
| `service_instance_id` | The PowerVS service instance id to build the image within. | `""` |
| `ssh_private_key_file` | The absolute path to the SSH key file. | `""` |
| `zone` |  The PowerVS service instance zone to build the image within. | `""` |

The parameters can be set via a variable file and passed via `PACKER_VAR_FILES`. See [Customization](../capi.md#customization) for examples.

## CAPIBM - VPC

### Hypervisor

The image is built using KVM hypervisor.

### Prerequisites for VPC Machine Image

#### Installing packages to use qemu-img

Execute the following command to install qemu-kvm and other packages if you are running Ubuntu 18.04 LTS.

```bash
$ sudo -i
# apt install qemu-kvm libvirt-bin qemu-utils
```

If you're on Ubuntu 20.04 LTS, then execute the following command to install qemu-kvm packages.

```bash
$ sudo -i
# apt install qemu-kvm libvirt-daemon-system libvirt-clients virtinst cpu-checker libguestfs-tools libosinfo-bin
```

#### Adding your user to the kvm group

```bash
$ sudo usermod -a -G kvm <yourusername>
$ sudo chown root:kvm /dev/kvm
```

Then exit and log back in to make the change take place.

### Building Images

The build [prerequisites](../capi.md#prerequisites) for using `image-builder` for building VPC images are managed by running:

```bash
cd image-builder/images/capi
make deps-qemu
```

From the `images/capi` directory, run `make build-qemu-ubuntu-xxxx`. The image is built and located in images/capi/output/{BUILD_NAME}-kube-{KUBERNETES_VERSION}. Please replace xxxx with `1804` or `2004` depending on the version you want to build the image for.

For building a ubuntu-2004 based CAPI image, run the following commands -

```bash
$ git clone https://github.com/kubernetes-sigs/image-builder.git
$ cd image-builder/images/capi/
$ make build-qemu-ubuntu-2004
```

#### Customizing Build

User may want to customize their build behavior. The parameters can be set via a variable file and passed via `PACKER_VAR_FILES`. See [Customization](../capi.md#customization) for examples.