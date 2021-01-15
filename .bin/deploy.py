import os
import argparse
import sys
import subprocess
import json

from pyVmomi import vim, vmodl
from artifactory import ArtifactoryPath

artifactory_user = os.getenv('artifactory_user')
artifactory_key = os.getenv('artifactory_key')
artifactory_pass = os.getenv('artifactory_pass')
artifactory_url = os.getenv('artifactory_url', "artifactory.devops.telekom.de")
bitwarden_user = os.getenv('bw_user')
bitwarden_pass = os.getenv('bw_pass')
bitwarden_url = os.getenv('bw_url', "https://bitwarden.das-schiff.telekom.de")


if artifactory_user is None and artifactory_key is not None:
    artifactory_auth = artifactory_key
elif artifactory_user is not None:
    if artifactory_key is not None:
        artifactory_auth = (artifactory_user, artifactory_key)
    elif artifactory_key is None and artifactory_pass is not None:
        artifactory_auth = (artifactory_user, artifactory_pass)
    else:
        print("Set either artifactory API Key or User and Password/API-Key")
        exit = True
elif artifactory_user is None and artifactory_key is None:
    print("Set either artifactory API Key or User and Password/API-Key")
    exit = True
else:
    print("Set either artifactory API Key or User and Password/API-Key")
    exit = True

if bitwarden_pass is None and bitwarden_user is None:
    print("Set Bitwarden User and Pass")
    exit = True

if exit == True:
    sys.exit("Mandatory credentials not set")

process = subprocess.run(["bw","config","server",str(bitwarden_url)], check=True, stdout=subprocess.PIPE, universal_newlines=True)
output = process.stdout
print(output)
process = subprocess.run(["bw","login",bitwarden_user,bitwarden_pass,"--raw"],check=True, stdout=subprocess.PIPE, universal_newlines=True)
output = process.stdout
os.environ['BW_SESSION'] = output
print("Set BW_SESSION")
process = subprocess.run(["bw","get","username","vcenter1.sce-dcn.net"],check=True, stdout=subprocess.PIPE, universal_newlines=True)
output = process.stdout
print(output)
process = subprocess.run(["bw","get","password","vcenter1.sce-dcn.net"],check=True, stdout=subprocess.PIPE, universal_newlines=True)
output = process.stdout
print(output)


process = subprocess.run(["bw","logout"],check=True, stdout=subprocess.PIPE, universal_newlines=True)
output = process.stdout
print(output)
