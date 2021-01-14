import os
import argparse
import sys

import bitwarden as bw
from pyVmomi import vim, vmodl
from artifactory import ArtifactoryPath

artifactory_user = os.getenv('artifactory_user')
artifactory_key = os.getenv('artifactory_key') 
artifactory_pass = os.getenv('artifactory_pass') 
artifactory_url = os.getenv('artifactory_url',"artifactory.devops.telekom.de")
bitwarden_user = os.getenv('bw_user')
bitwarden_pass = os.getenv('bw_pass')
bitwarden_url = os.getenv('bw_url',"bitwarden.das-schiff.telekom.de")


if artifactory_user is None and artifactory_key is not None:
    artifactory_auth = artifactory_key
elif artifactory_user is not None:
    if artifactory_key is not None:
        artifactory_auth = (artifactory_user,artifactory_key)
    elif artifactory_key is None and artifactory_pass is not None:
        artifactory_auth = (artifactory_user,artifactory_pass)
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




