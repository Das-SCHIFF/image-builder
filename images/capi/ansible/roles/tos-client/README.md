# tos-client playbook

This playbook can be used out to roll-out TASTE-OS to machines that shall be
scanned on a regular basis.

## Features

* install the TASTE-OS client
* configure all available client options
* register machines
* scan machines on playbook run
* schedule regular scans via cron
* update the collector script
* optional http proxy support

## Prerequisites

The machines that you want to scan need to reach the collector API of TASTE-OS
in order to download the client, register themselves and upload scan results.
For details see the landing / help page of your TASTE-OS instance.

## Setup

For settings see `vars.yml`.

There are some mandatory settings that need to be done:

* `client_url`: download URL for the client (`tos.tar`) -
see landing / help page of the TASTE-OS UI

* `client_sha512sum`: sha512sum of the `tos.tar` -
see landing / help page of the TASTE-OS UI

* `s_token`: s_token for authentication at the Collector API -
can be generated in the TASTE-OS UI after logging in

Please also modify `cronjob_hour` and `cronjob_minute` to help us distribute
load on the TASTE-OS collector and scanning pipeline.

Depending on your environment, it might be necessary to set `proxy_url` as well.

## Drawbacks

Currently, each time we update the client, the sha512 sum will change. If this
happens, you'll need to change the `client_sha512sum` in your config as well.
Unfortunately, we're currently unable to provide all installations of TASTE-OS
with universally valid SSL/TLS certificates which makes the checksum necessary
to ensure integrity of the client. This is due to lack of a universal PKI
infrastructure across all departments of Deutsche Telekom.

There is a `enable_integrity_check` setting you might disable but we definitely
do NOT advise that since you'll have no integrity protection then!

We're currently working on a better solution by providing the client in signed
RPM / DEB packages which will make the checksum obsolete in a later release.
