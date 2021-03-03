import os
import argparse
import sys
import subprocess
import yaml
import requests
import ssl
import functools
import time
import json
import tarfile
import hashlib
from collections import OrderedDict
from tqdm.auto import tqdm
from tqdm.utils import CallbackIOWrapper
from six.moves.urllib.request import Request, urlopen
from six.moves.urllib.parse import unquote

from threading import Timer

from pyVim.connect import SmartConnectNoSSL, Disconnect
from pyVmomi import vim, vmodl
from artifactory import ArtifactoryPath ##https://github.com/devopshq/artifactory
import atexit

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--artifactory_user', default=os.getenv('artifactory_user') )
    parser.add_argument('--artifactory_key', default=os.getenv('artifactory_key') )
    parser.add_argument('--artifactory_pass', default=os.getenv('artifactory_pass') )
    parser.add_argument('--artifactory_url', default=os.getenv('artifactory_url',"https://artifactory.devops.telekom.de/artifactory") )
    parser.add_argument('--artifactory_repo', default=os.getenv('artifactory_repo',"schiff-generic") )
    parser.add_argument('--upload_mode', default=os.getenv('upload_mode',"govc") )
    parser.add_argument('--bw_user', default=os.getenv('bw_user') )
    parser.add_argument('--bw_pass', default=os.getenv('bw_pass') )
    parser.add_argument('--bw_url', default=os.getenv('bw_url', "https://bitwarden.das-schiff.telekom.de") )
    parser.add_argument('--enable_bw', default=False )
    parser.add_argument('--vcenter_config_file', type=argparse.FileType('r'), nargs="?", default=".bin/dummy.yaml")
    exit = False
    error_occured=True
    args = parser.parse_args()
    vcenter_data = yaml.load(args.vcenter_config_file, Loader=yaml.FullLoader)
    if args.artifactory_user is None and args.artifactory_key is not None:
        artifactory_auth = args.artifactory_key
    elif args.artifactory_user is not None:
        if args.artifactory_key is not None:
            artifactory_auth = (str(args.artifactory_user), str(args.artifactory_key))
        elif args.artifactory_key is None and args.artifactory_pass is not None:
            artifactory_auth = (args.artifactory_user, args.artifactory_pass)
        else:
            print("Set either artifactory API Key or User and Password/API-Key")
            exit = True
    elif args.artifactory_user is None and args.artifactory_key is None:
        print("Set either artifactory API Key or User and Password/API-Key")
        exit = True
    else:
        print("Set either artifactory API Key or User and Password/API-Key")
        exit = True

    if args.enable_bw:
        if args.bw_pass is None and args.bw_user is None:
            print("Set Bitwarden User and Pass")
            exit = True

    if exit == True:
        sys.exit("Mandatory credentials not set")

    if args.enable_bw:
        process = subprocess.run(["bw","config","server",str(args.bw_url)], check=True, stdout=subprocess.PIPE, universal_newlines=True)
        output = process.stdout
        print(output)
        try:
            process = subprocess.run(["bw","login",args.bw_user,args.bw_pass,"--raw"],check=True, stdout=subprocess.PIPE, universal_newlines=True)
            output = process.stdout
            os.environ['BW_SESSION'] = output
            print("Set BW_SESSION")
        except subprocess.CalledProcessError as err:
            if "You are already logged in as" in err.output:
                print("Already logged in")
                pass
        process = subprocess.run(["bw","get","username","vcenter1.sce-dcn.net"],check=True, stdout=subprocess.PIPE, universal_newlines=True)
        output = process.stdout
        print(output)
        process = subprocess.run(["bw","get","password","vcenter1.sce-dcn.net"],check=True, stdout=subprocess.PIPE, universal_newlines=True)
        output = process.stdout
        print(output)
        process = subprocess.run(["bw","logout"],check=True, stdout=subprocess.PIPE, universal_newlines=True)
        output = process.stdout
        print(output)

    ses = requests.Session()
    ses.auth = artifactory_auth
    aql = ArtifactoryPath(args.artifactory_url,session=ses)
    aqlargs = [
        "items.find",
        {
            "$and": [
                {"repo": {"$eq": args.artifactory_repo}},
                {"@deploy": {"$match": "true"}},
                
            ]
        },
    ]
    artifacts = aql.aql(*aqlargs)

    for p in artifacts:

        fileurl= args.artifactory_url + "/" + p["repo"] + "/" + p["path"] + "/" +p["name"]
        if not os.path.isfile(p["name"]):    
            path = ArtifactoryPath(fileurl,session=ses)
            with path.open() as fd:
                # out.write(fd.read())
                # pbar.update(1) 
                chunkr = functools.partial(fd.read,4096)
                with tqdm.wrapattr(open(p["name"], "wb"), "write", miniters=1, desc=p["name"],total=int(p["size"])) as fout:
                    for chunk in iter(chunkr,b""):
                        fout.write(chunk)
        time.sleep(10)
        for vcenter in vcenter_data["vcenters"]:
            if args.upload_mode == "python":
                try:
                    uploadOVA(vcenter,p["name"])
                except Exception as e:
                    print("Upload for vCenter "+vcenter["host"]+" failed")
                    print("Reason:")
                    print(e)
                    error_occured=True
            elif args.upload_mode == "govc":
                print("vCenter: "+vcenter["host"])
                os.environ['GOVC_INSECURE'] = "1"
                os.environ['GOVC_URL'] = vcenter["host"]
                os.environ['GOVC_USERNAME'] = vcenter["user"]
                os.environ['GOVC_PASSWORD'] = vcenter["password"]
                os.environ['GOVC_DATACENTER'] = vcenter["datacenter"]
                os.environ['GOVC_CLUSTER'] = vcenter["cluster"]
                os.environ['GOVC_DATASTORE'] = vcenter["datastore"]
                os.environ['GOVC_NETWORK'] = vcenter["network"]
                os.environ['GOVC_FOLDER'] = vcenter["folder"]
                os.environ['GOVC_RESOURCE_POOL'] = vcenter["resource_pool"]
                print(["govc","import.spec",p["name"]])
                process = subprocess.run(["govc","import.spec",p["name"]],check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
                output = process.stdout
                importoptions = json.loads(output)
                importoptions["NetworkMapping"][0]["Network"] = vcenter["network"]
                with open(p["name"]+".json", 'w') as outfile:
                    json.dump(importoptions, outfile)
                try:
                    print(["govc","import.ova","--options="+p["name"]+".json",p["name"]])
                    process = subprocess.run(["govc","import.ova","--options="+p["name"]+".json",p["name"]],check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
                    output = process.stdout
                    print(output)
                except subprocess.CalledProcessError as err:
                    print("vCenter: "+vcenter["host"]+" failed")
                    print(["govc","import.ova","--options="+p["name"]+".json",p["name"]])
                    print(err.output)
                time.sleep(5)
    if error_occured:
        return 1
def uploadOVA(vcenter_data, ova_path):
    try:
        si = SmartConnectNoSSL(host=vcenter_data["host"],
                               user=vcenter_data["user"],
                               pwd=vcenter_data["password"],
                               port=443)
        atexit.register(Disconnect, si)
        print("Connected to to %s" % vcenter_data["host"])
    except Exception as e:
        print("Unable to connect to %s" % vcenter_data["host"])
        print("Reason:")
        print(e)
        return 1
    content = si.RetrieveContent()
    
    dc = find_datacenter_by_name(content, vcenter_data["datacenter"])
    cluster = find_cluster_by_name(content, vcenter_data["cluster"], dc) 
    rp = find_resource_pool_by_cluster(content, vcenter_data["resource_pool"],cluster)
    ds = find_datastore_by_name(content,vcenter_data["datastore"], dc)
    df = find_folder_by_name(content, vcenter_data["folder"])
    network = find_network_by_name(content, vcenter_data["network"],dc)
    if find_vm_by_name(content,ova_path) is not None:
        print("OVA already uploaded")
        return 0
    ovf_handle = OvfHandler(ova_path)
    ovfManager = si.content.ovfManager
    # CreateImportSpecParams can specify many useful things such as
    # diskProvisioning (thin/thick/sparse/etc)
    # networkMapping (to map to networks)
    # propertyMapping (descriptor specific properties)

    # Virtual interface is the name of the port group network
    nma = vim.OvfManager.NetworkMapping.Array()
    # Let the name equal to VM Network and not the name of the portgroup network
    nm = vim.OvfManager.NetworkMapping(name="nic0", network=network)
    nma.append(nm)
    cisp = vim.OvfManager.CreateImportSpecParams(diskProvisioning="thin",networkMapping=nma)
    cisr = ovfManager.CreateImportSpec(ovf_handle.get_descriptor(),
                                       rp, ds, cisp)

    # These errors might be handleable by supporting the parameters in
    # CreateImportSpecParams
    if len(cisr.error):
        print("The following errors will prevent import of this OVA:")
        for error in cisr.error:
            print("%s" % error)
        return 1

    ovf_handle.set_spec(cisr)

    lease = rp.ImportVApp(cisr.importSpec, df)
    while lease.state == vim.HttpNfcLease.State.initializing:
        print("Waiting for lease to be ready...")
        time.sleep(1)
    if lease.state == vim.HttpNfcLease.State.error:
        print("Lease error: %s" % lease.error)
        return 1
    if lease.state == vim.HttpNfcLease.State.done:
        return 0

    print("Starting deploy...")
    return ovf_handle.upload_disks(lease, vcenter_data["host"])


def find_object_by_name(content, name, obj_type, folder=None, recurse=True):
    if not isinstance(obj_type, list):
        obj_type = [obj_type]

    name = name.strip()

    objects = get_all_objs(content, obj_type, folder=folder, recurse=recurse)
    for obj in objects:
        if unquote(obj.name) == name:
            return obj

    return None

def find_cluster_by_name(content, cluster_name, datacenter=None):

    if datacenter and hasattr(datacenter, 'hostFolder'):
        folder = datacenter.hostFolder
    else:
        folder = content.rootFolder

    return find_object_by_name(content, cluster_name, [vim.ClusterComputeResource], folder=folder)


def find_datacenter_by_name(content, datacenter_name):
    return find_object_by_name(content, datacenter_name, [vim.Datacenter])

def find_datastore_by_name(content, datastore_name, datacenter_name=None):
    return find_object_by_name(content, datastore_name, [vim.Datastore], datacenter_name)


def find_folder_by_name(content, folder_name):
    return find_object_by_name(content, folder_name, [vim.Folder])


def find_dvs_by_name(content, switch_name, folder=None):
    return find_object_by_name(content, switch_name, [vim.DistributedVirtualSwitch], folder=folder)


def find_hostsystem_by_name(content, hostname):
    return find_object_by_name(content, hostname, [vim.HostSystem])


def find_resource_pool_by_name(content, resource_pool_name):
    return find_object_by_name(content, resource_pool_name, [vim.ResourcePool])


def find_resource_pool_by_cluster(content, resource_pool_name='Resources', cluster=None):
    return find_object_by_name(content, resource_pool_name, [vim.ResourcePool], folder=cluster)


def find_network_by_name(content, network_name, datacenter_name=None):
    return find_object_by_name(content, quote_obj_name(network_name), [vim.Network], datacenter_name)

def find_vm_by_name(content, vm_name, folder=None, recurse=True):
    return find_object_by_name(content, vm_name, [vim.VirtualMachine], folder=folder, recurse=recurse)

def get_parent_datacenter(obj):
    """ Walk the parent tree to find the objects datacenter """
    if isinstance(obj, vim.Datacenter):
        return obj
    datacenter = None
    while True:
        if not hasattr(obj, 'parent'):
            break
        obj = obj.parent
        if isinstance(obj, vim.Datacenter):
            datacenter = obj
            break
    return datacenter

def get_all_objs(content, vimtype, folder=None, recurse=True):
    if not folder:
        folder = content.rootFolder

    obj = {}
    container = content.viewManager.CreateContainerView(folder, vimtype, recurse)
    for managed_object_ref in container.view:
        obj.update({managed_object_ref: managed_object_ref.name})
    return obj

def quote_obj_name(object_name=None):
    """
    Replace special characters in object name
    with urllib quote equivalent
    """
    if not object_name:
        return None

    SPECIAL_CHARS = OrderedDict({
        '%': '%25',
        '/': '%2f',
        '\\': '%5c'
    })
    for key in SPECIAL_CHARS.keys():
        if key in object_name:
            object_name = object_name.replace(key, SPECIAL_CHARS[key])

    return object_name

def get_tarfile_size(tarfile):
    """
    Determine the size of a file inside the tarball.
    If the object has a size attribute, use that. Otherwise seek to the end
    and report that.
    """
    if hasattr(tarfile, 'size'):
        return tarfile.size
    size = tarfile.seek(0, 2)
    tarfile.seek(0, 0)
    return size


class OvfHandler(object):
    """
    OvfHandler handles most of the OVA operations.
    It processes the tarfile, matches disk keys to files and
    uploads the disks, while keeping the progress up to date for the lease.
    """
    def __init__(self, ovafile):
        """
        Performs necessary initialization, opening the OVA file,
        processing the files and reading the embedded ovf file.
        """
        self.handle = self._create_file_handle(ovafile)
        self.tarfile = tarfile.open(fileobj=self.handle)
        ovffilename = list(filter(lambda x: x.endswith(".ovf"),
                                  self.tarfile.getnames()))[0]
        ovffile = self.tarfile.extractfile(ovffilename)
        self.descriptor = ovffile.read().decode()

    def _create_file_handle(self, entry):
        """
        A simple mechanism to pick whether the file is local or not.
        This is not very robust.
        """
        if os.path.exists(entry):
            return FileHandle(entry)
        else:
            return WebHandle(entry)

    def get_descriptor(self):
        return self.descriptor

    def set_spec(self, spec):
        """
        The import spec is needed for later matching disks keys with
        file names.
        """
        self.spec = spec

    def get_disk(self, fileItem, lease):
        """
        Does translation for disk key to file name, returning a file handle.
        """
        ovffilename = list(filter(lambda x: x == fileItem.path,
                                  self.tarfile.getnames()))[0]
        return self.tarfile.extractfile(ovffilename)

    def get_device_url(self, fileItem, lease):
        print(fileItem)
        for deviceUrl in lease.info.deviceUrl:
            if deviceUrl.importKey == fileItem.deviceId:
                return deviceUrl
        raise Exception("Failed to find deviceUrl for file %s" % fileItem.path)

    def upload_disks(self, lease, host):
        """
        Uploads all the disks, with a progress keep-alive.
        """
        self.lease = lease
        print(lease)
        try:
            self.start_timer()
            for fileItem in self.spec.fileItem:
                self.upload_disk(fileItem, lease, host)
            lease.Complete()
            print("Finished deploy successfully.")
            return 0
        except vmodl.MethodFault as e:
            print("Hit an error in upload: %s" % e)
            lease.Abort(e)
        except Exception as e:
            print("Lease: %s" % lease.info)
            print("Hit an error in upload: %s" % e)
            lease.Abort(vmodl.fault.SystemError(reason=str(e)))
            raise
        return 1

    def upload_disk(self, fileItem, lease, host):
        """
        Upload an individual disk. Passes the file handle of the
        disk directly to the urlopen request.
        """
        ovffile = self.get_disk(fileItem, lease)
        if ovffile is None:
            return
        deviceUrl = self.get_device_url(fileItem, lease)
        url = deviceUrl.url.replace('*', host)
        headers = {'Content-length': get_tarfile_size(ovffile)}
        if hasattr(ssl, '_create_unverified_context'):
            sslContext = ssl._create_unverified_context()
        else:
            sslContext = None
        req = Request(url, ovffile, headers)
        urlopen(req, context=sslContext)

    def start_timer(self):
        """
        A simple way to keep updating progress while the disks are transferred.
        """
        Timer(5, self.timer).start()

    def timer(self):
        """
        Update the progress and reschedule the timer if not complete.
        """
        try:
            prog = self.handle.progress()
            self.lease.Progress(prog)
            if self.lease.state not in [vim.HttpNfcLease.State.done,
                                        vim.HttpNfcLease.State.error]:
                self.start_timer()
            sys.stderr.write("Progress: %d%%\r" % prog)
        except:  # Any exception means we should stop updating progress.
            pass


class FileHandle(object):
    def __init__(self, filename):
        self.filename = filename
        self.fh = open(filename, 'rb')

        self.st_size = os.stat(filename).st_size
        self.offset = 0

    def __del__(self):
        self.fh.close()

    def tell(self):
        return self.fh.tell()

    def seek(self, offset, whence=0):
        if whence == 0:
            self.offset = offset
        elif whence == 1:
            self.offset += offset
        elif whence == 2:
            self.offset = self.st_size - offset

        return self.fh.seek(offset, whence)

    def seekable(self):
        return True

    def read(self, amount):
        self.offset += amount
        result = self.fh.read(amount)
        return result

    # A slightly more accurate percentage
    def progress(self):
        return int(100.0 * self.offset / self.st_size)


class WebHandle(object):
    def __init__(self, url):
        self.url = url
        r = urlopen(url)
        if r.code != 200:
            raise FileNotFoundError(url)
        self.headers = self._headers_to_dict(r)
        if 'accept-ranges' not in self.headers:
            raise Exception("Site does not accept ranges")
        self.st_size = int(self.headers['content-length'])
        self.offset = 0

    def _headers_to_dict(self, r):
        result = {}
        if hasattr(r, 'getheaders'):
            for n, v in r.getheaders():
                result[n.lower()] = v.strip()
        else:
            for line in r.info().headers:
                if line.find(':') != -1:
                    n, v = line.split(': ', 1)
                    result[n.lower()] = v.strip()
        return result

    def tell(self):
        return self.offset

    def seek(self, offset, whence=0):
        if whence == 0:
            self.offset = offset
        elif whence == 1:
            self.offset += offset
        elif whence == 2:
            self.offset = self.st_size - offset
        return self.offset

    def seekable(self):
        return True

    def read(self, amount):
        start = self.offset
        end = self.offset + amount - 1
        req = Request(self.url,
                      headers={'Range': 'bytes=%d-%d' % (start, end)})
        r = urlopen(req)
        self.offset += amount
        result = r.read(amount)
        r.close()
        return result

    # A slightly more accurate percentage
    def progress(self):
        return int(100.0 * self.offset / self.st_size)


if __name__ == '__main__':
    main()