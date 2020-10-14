#!/bin/sh
set -x
nsenter -m/proc/1/ns/mnt -- sh -c '[ -x /usr/bin/dnf ] && echo "Fedora" > /tmp/os-type'
nsenter -m/proc/1/ns/mnt -- sh -c '[ -x /usr/bin/yum ] && echo "RHEL" > /tmp/os-type'
nsenter -m/proc/1/ns/mnt -- sh -c '[ -x /usr/bin/apt ] && echo "Debian" > /tmp/os-type'

OS=$(nsenter -m/proc/1/ns/mnt -- cat /tmp/os-type)

# echo ==== Checking node dependencies for PSO ====
# if [ $OS = "Debian" ]; then
#     nsenter -m/proc/1/ns/mnt -n/proc/1/ns/net -- apt install -y --no-upgrade open-iscsi multipath-tools nfs-common
# elif [ $OS = "Fedora" ]; then
#     nsenter -m/proc/1/ns/mnt -n/proc/1/ns/net -- dnf install -y --no-upgrade iscsi-initiator-utils device-mapper-multipath nfs-utils libstoragemgmt-udev
#     nsenter -m/proc/1/ns/mnt -- sh -c 'mpathconf --enable --with_multipathd y'
# elif [ $OS = "RHEL" ]; then
#     nsenter -m/proc/1/ns/mnt -n/proc/1/ns/net -- yum install -y iscsi-initiator-utils device-mapper-multipath nfs-utils libstoragemgmt-udev
#     nsenter -m/proc/1/ns/mnt -- sh -c 'mpathconf --enable --with_multipathd y'
# fi

nsenter -m/proc/1/ns/mnt -- sh -c 'cat <<EOF >/etc/multipath.conf
defaults {
  polling_interval      10
}
devices {
  device {
      vendor "PURE"
      product "FlashArray"
      fast_io_fail_tmo 10
      path_grouping_policy "group_by_prio"
      failback "immediate"
      prio "alua"
      hardware_handler "1 alua"
      max_sectors_kb 4096
    }
}
EOF'
nsenter -m/proc/1/ns/mnt -- sh -c 'echo "InitiatorName=iqn.1993-08.org.debian:`cat /etc/machine-id`" > /etc/iscsi/initiatorname.iscsi'
nsenter -m/proc/1/ns/mnt -- sh -c 'if (systemctl status iscsid | grep disabled); then systemctl enable iscsid; fi'
nsenter -m/proc/1/ns/mnt -- sh -c 'if (systemctl status iscsid | grep inactive); then systemctl start iscsid; fi'
nsenter -m/proc/1/ns/mnt -- sh -c 'if (systemctl status multipathd | grep inactive); then systemctl start multipathd; fi'
nsenter -m/proc/1/ns/mnt -- sh -c 'if (systemctl status multipathd | grep inactive); then systemctl start multipathd; fi'
nsenter -m/proc/1/ns/mnt -- sh -c 'echo "iscsi_tcp" > /etc/modules-load.d/iscsi.conf'
if [ $OS = "Debian" ]; then
    nsenter -m/proc/1/ns/mnt -- sh -c '[ ! -f /lib/udev/rules.d/99-pure-storage.rules ] && cat <<EOF >/etc/udev/rules.d/99-pure-storage.rules
# Recommended settings for Pure Storage FlashArray.
# Use noop scheduler for high-performance solid-state storage for SCSI devices
ACTION=="add|change", KERNEL=="sd*[!0-9]", SUBSYSTEM=="block", ENV{ID_VENDOR}=="PURE", ATTR{queue/scheduler}="none"
ACTION=="add|change", KERNEL=="dm-[0-9]*", SUBSYSTEM=="block", ENV{DM_NAME}=="3624a937*", ATTR{queue/scheduler}="none"

# Reduce CPU overhead due to entropy collection
ACTION=="add|change", KERNEL=="sd*[!0-9]", SUBSYSTEM=="block", ENV{ID_VENDOR}=="PURE", ATTR{queue/add_random}="0"
ACTION=="add|change", KERNEL=="dm-[0-9]*", SUBSYSTEM=="block", ENV{DM_NAME}=="3624a937*", ATTR{queue/add_random}="0"

# Spread CPU load by redirecting completions to originating CPU
ACTION=="add|change", KERNEL=="sd*[!0-9]", SUBSYSTEM=="block", ENV{ID_VENDOR}=="PURE", ATTR{queue/rq_affinity}="2"
ACTION=="add|change", KERNEL=="dm-[0-9]*", SUBSYSTEM=="block", ENV{DM_NAME}=="3624a937*", ATTR{queue/rq_affinity}="2"

# Set the HBA timeout to 60 seconds
ACTION=="add|change", KERNEL=="sd*[!0-9]", SUBSYSTEM=="block", ENV{ID_VENDOR}=="PURE", ATTR{device/timeout}="60"
EOF'
fi

if [ $OS = "RHEL" ] || [ $OS = "Fedora" ]; then
    nsenter -m/proc/1/ns/mnt -- sh -c '[ ! -f /etc/udev/rules.d/99-pure-storage.rules ] && cat <<EOF >/etc/udev/rules.d/99-pure-storage.rules
# Recommended settings for Pure Storage FlashArray.
# Use noop scheduler for high-performance solid-state storage for SCSI devices
ACTION=="add|change", KERNEL=="sd*[!0-9]", SUBSYSTEM=="block", ENV{ID_VENDOR}=="PURE", ATTR{queue/scheduler}="none"
ACTION=="add|change", KERNEL=="dm-[0-9]*", SUBSYSTEM=="block", ENV{DM_NAME}=="3624a937*", ATTR{queue/scheduler}="none"

# Reduce CPU overhead due to entropy collection
ACTION=="add|change", KERNEL=="sd*[!0-9]", SUBSYSTEM=="block", ENV{ID_VENDOR}=="PURE", ATTR{queue/add_random}="0"
ACTION=="add|change", KERNEL=="dm-[0-9]*", SUBSYSTEM=="block", ENV{DM_NAME}=="3624a937*", ATTR{queue/add_random}="0"

# Spread CPU load by redirecting completions to originating CPU
ACTION=="add|change", KERNEL=="sd*[!0-9]", SUBSYSTEM=="block", ENV{ID_VENDOR}=="PURE", ATTR{queue/rq_affinity}="2"
ACTION=="add|change", KERNEL=="dm-[0-9]*", SUBSYSTEM=="block", ENV{DM_NAME}=="3624a937*", ATTR{queue/rq_affinity}="2"

# Set the HBA timeout to 60 seconds
ACTION=="add|change", KERNEL=="sd*[!0-9]", SUBSYSTEM=="block", ENV{ID_VENDOR}=="PURE", ATTR{device/timeout}="60"
EOF'
    nsenter -m/proc/1/ns/mnt -- sh -c 'cat <<EOF >>/etc/udev/rules/90-scsi-ua.rules
ACTION=="change", SUBSYSTEM=="scsi", ENV{SDEV_UA}=="CAPACITY_DATA_HAS_CHANGED", TEST=="rescan", ATTR{rescan}="x"
EOF'
fi

nsenter -m/proc/1/ns/mnt -- sh -c '[ -x /sbin/udevadm ] && /sbin/udevadm control --reload-rules'
nsenter -m/proc/1/ns/mnt -- sh -c '[ -x /sbin/udevadm ] && /sbin/udevadm trigger --type=devices --action=change'
nsenter -m/proc/1/ns/mnt -- sh -c '[ -x /usr/bin/udevadm ] && /usr/bin/udevadm control --reload-rules'
nsenter -m/proc/1/ns/mnt -- sh -c '[ -x /usr/bin/udevadm ] && /usr/bin/udevadm trigger --type=devices --action=change'

exit 0