#!/bin/sh
# Copyright 2021, Deutsche Telekom AG
#
# This script collects all data from a host needed to perform a TASTE-OS scan
#
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# !!!                                                                        !!!
# !!!                       DO NOT MODIFY THIS SCRIPT!                       !!!
# !!!         OTHERWISE, CORRECT SCAN RESULTS CANNOT BE GUARANTEED!          !!!
# !!!                                                                        !!!
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

### SETTINGS
# Command delimiter for collector output
DELIMITER="###"
TMPFILE_OUT="collector-out-temp"
TMPFILE_ERR="collector-err-temp"

# Set english as language
LANG=en_US.UTF-8
# Set standard PATH
PATH=/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/bin:/sbin
export PATH

# This function executes the command and builds the correct output
cmd() {
  echo "--START-${?}--"
  unset cmdreturn cmdout cmderr
  # evaluate the command, store stdout to cmdout, stderr to cmderr and return code to cmdreturn
  eval "${1}" 2> "${TMPFILE_ERR}" > "${TMPFILE_OUT}"
  cmdreturn=${?}
  cmdout=$(cat "${TMPFILE_OUT}")
  cmderr=$(cat "${TMPFILE_ERR}")
  if [ -n "${cmdout}" ]; then
    echo "${cmdout}"
  fi
  if [ -n "${cmderr}" ]; then
    echo "${cmderr}" | while read -r line; do
      echo "--stderr--: ${line}"
    done
  fi
  if [ ${cmdreturn} -eq 0 ]; then
    echo "--SUCCESS-${cmdreturn}--"
  else
    echo "--FAILURE-${cmdreturn}--"
  fi
  echo ""
}

# This function prints command delimiters and runs the cmd function to run the command
execute() {
  _cmd=${1}
  printf "%s\n" "${DELIMITER}  ${_cmd}  ${DELIMITER}"
  cmd "$(printf "%b" "${_cmd}")"
}

# This function determines the absolute path to a binary that is running
get_absolute_binary_path() {
  binary_path=$(readlink /proc/"$(pgrep -x -o "${1}")"/exe) 2> /dev/null
  echo "${binary_path}"
}

# This function determines the start user for the binary via the proc filesystem.
get_user_of_binary() {
  # shellcheck disable=SC2012
  user=$(ls -ld /proc/"$(pgrep -x -o "${1}")"/exe 2> /dev/null | awk '{print $3}' 2> /dev/null)
  echo "${user}"
}

# Print used delimiter
echo "DELIMITER: ${DELIMITER}"
echo ""

# Metainformation of collectscript
echo "${DELIMITER} PATCHCOLLECTOR SCRIPT ${DELIMITER}"
echo "# Copyright 2021, Deutsche Telekom AG"
echo "${DELIMITER}  META  ${DELIMITER}"
echo "# Version: 1.3.5"
echo "# OS: unix"
# 
echo "# Date: Thu Feb 11 00:13:27 2021 UTC"
echo "# Uuid: dd9a19c9-58d0-4205-884a-269db7285642"
# 
echo "${DELIMITER}  END META  ${DELIMITER}"
echo "${DELIMITER}  START  ${DELIMITER}"
echo ""

# Generic context information
execute "echo \"start timestamp: \$(date +%s)\"" #NbT
execute "id" #NbT
execute "stat \${0}" #NbT
execute "ps -u root | awk '{print \$4}'" #NbN
execute "ps -axl" #NbT
execute "ps -eaf" #NbT
execute "systemctl --no-pager --all" #NbT
# 
execute "docker ps -a --format '[ {{ json .}} ]'" #NbT
# 
# Generic system information
execute "/bin/hostname" #NbN
execute "uname -s ; uname -r ; uname -m ; (uname -p || echo) ; uname -v" #NbN
execute "uname -r" #NbN #NbO
execute "uname -a" #NbN  #NbO
execute "uname -m" #NbN
execute "uname -p" #NbO
execute "dmidecode || /sbin/dmidecode || /usr/sbin/dmidecode || /usr/local/sbin/dmidecode" #NbN
execute "cat /proc/cpuinfo" #NbT
execute "cat /proc/meminfo" #NbT
execute "cat /proc/version" #NbT
execute "cat /proc/cmdline" #NbT
execute "cat /proc/mounts" #NbT
execute "cat /proc/diskstats" #NbT
execute "cat /proc/stat" #NbT
execute "cat /proc/filesystems" #NbT
execute "lspci -v" #NbT
execute "sysctl -A || /sbin/sysctl -A" #NbT
execute "dmesg" #NbT
execute "virt-what" #NbT
execute "cat /proc/1/cgroup" #NbT

# Generic software information
execute "java -version" #NbT
execute "command -v vmware" #NbN
execute "command -v vmplayer" #NbN

# Gather network information
execute "/sbin/ifconfig -a || /usr/sbin/ifconfig -a" #NbN
execute "netstat -a -n" #NbN
execute "netstat -anp" #NbT
# Only execute iptables when the relevant kernel modules are already loaded and present.
KERNEL_MODULES=$(lsmod 2>/dev/null)
if  echo "$KERNEL_MODULES" | grep -q "ip_tables"  &&  echo "$KERNEL_MODULES" | grep -q "nf_conntrack"  &&  echo "$KERNEL_MODULES" | grep -q "nf_nat" ; then
  execute "iptables -L" # NbT
  execute "iptables -t nat -S" #NbT
  execute "iptables -t filter -S" #NbT
  execute "iptables -t mangle -S" #NbT
  execute "iptables -t raw -S" #NbT
  execute "iptables -t security -S" #NbT
fi
execute "ss -panei" #NbT
execute "ip addr" #NbT
execute "ip route" #NbT
execute "ip -s link" #NbT
execute "ip tcp_metrics" #NbT
execute "arp -e -n" #NbT
execute "ip neighbour" #NbT
# 
execute "docker inspect --format '[ { \"Id\": {{json .Id}}, \"Name\": {{json .Name}}, \"Image\": {{json .Image}}, \"NetworkSettings\": {{json .NetworkSettings}} } ]' \$(docker ps  | awk '\$1 !~ \"CONTAINER\" {print \$1}')" #NbT
# execute "cat /etc/resolv.conf" #NbT
execute "cat /etc/nsswitch.conf" #NbT
execute "cat /etc/hosts" #NbT
execute "timeout 5 nslookup tos-cn.telekom.de" #NbT
execute "timeout 5 dig tos-cn.telekom.de" #NbT

# Determine Linux distribution
execute "cat /etc/SuSE-release" #NbN
execute "cat /etc/SuSE-release 2>/dev/null" #NbN
execute "cat /etc/UnitedLinux-release" #NbN
execute "cat /etc/debian_release" #NbN
execute "cat /etc/debian_version" #NbN
execute "cat /etc/enterprise-release" #NbN
execute "cat /etc/fedora-release" #NbN
execute "cat /etc/gentoo-release" #NbN
execute "cat /etc/lsb-release" #NbN
execute "cat /etc/mandrake-release" #NbN
execute "cat /etc/oracle-release" #NbN
execute "cat /etc/os-release" #NbN
execute "cat /etc/os-release 2>/dev/null" #NbN
execute "cat /etc/redhat-release" #NbN
execute "cat /etc/redhat_version" #NbN
execute "cat /etc/slackware-release" #NbN
execute "cat /etc/slackware-version" #NbN
execute "cat /etc/slp.reg" #NbN
execute "cat /etc/system-release" #NbN
execute "cat /etc/vmware-release" #NbN
execute "cat /etc/yellowdog-release" #NbN
execute "cat /etc/alpine-release" #NbT
execute "cat /etc/hipchat-release" #NbN
execute "cat /etc/euleros-release" #NbO
execute "cat /etc/system-release-cpe" #NbO

# Determine repository configuration
execute "apt-cache policy" #NbT
# Only execute the repolist command if we are root. This avoids writing of unnecessary tmp data.
USER_ID=$(id -u 2>/dev/null)
if [ "$USER_ID" -eq 0 ]; then
  execute "timeout 30 yum -v repolist" #NbT
fi
execute "zypper lr -d"  #NbT

# VMware
execute "/usr/sbin/esxupdate query -a" #NbN
execute "/usr/bin/vmware -v"  #NbN
execute "grep version /etc/vmware/config" #NbN
execute "cat /etc/vmware/config" #NbN
execute "cat /etc/vmware/esx.conf" #NbN

# Debian
execute "dpkg-query -W -f '\${db:Status-Abbrev}  \${Package}  \${Version}  \${architecture}  \${binary:summary}"'\n'"'" #NbN
execute "COLUMNS=160 dpkg -l" #NbN
execute "COLUMNS=250 dpkg -l|cat" #NbN
execute "COLUMNS=400 dpkg -l" #NbO

# SuSE
execute "rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}"'\\n'"'" #NbN

# RedHat
execute "/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}"'\\n'"'" #NbN
execute "/bin/rpm -qa --qf \"%{NAME}~%{VERSION}~%{RELEASE};\"" #NbO

# EulerOS
execute "cat /etc/uvp-release" #NbOrpheus
execute "cat /etc/uvp_version" #NbOrpheus

# Alpine Linux
execute "apk version -v" #NbN

# Solaris
execute "/usr/bin/pkg list" #NbN
execute "uname -p" #NbN
execute "/usr/bin/pkginfo" #NbN
execute "/usr/bin/pkg list -H entire" #NbN
execute "/usr/bin/showrev -a" #NbN
execute "/usr/sbin/patchadd -p" #NbN
execute "/usr/bin/pkginfo -x"  #NbN
execute "psrinfo -pv" #NbT
execute "prtconf -v" #NbT

# HP/UX
execute "/usr/sbin/swlist -l fileset -a revision" #NbN
execute "swlist -l patch -a supersedes" #NbO
execute "print_manifest" #NbT
execute "machinfo" #NbT

# AIX
execute "/etc/ifconfig -a" #NbN
execute "/sbin/ifconfig -a" #NbN
execute "/usr/bin/oslevel -r" #NbN
execute "/usr/bin/oslevel -s"  #NbN
execute "/usr/sbin/emgr -l 2>&1" #NbN
execute "lslpp -Lc" #NbN
execute "prtconf" #NbT
execute "lparstat -i" #NbT

# SNAP
execute "snap list" #NbT
execute "snap connections --all" #NbT

# Flatpak
execute "flatpak remotes -d" #NbT
execute "flatpak list -d" #NbT

# Gather some application configuration

# YUM config for gpg check
execute "cat /etc/yum.conf" #NbT
# APT config for gpg check
execute "cat /etc/apt/sources.list" #NbT
execute "cat /etc/apt/sources.list.d/*" #NbT

# SSH daemon config
execute "cat /etc/ssh/sshd_config" #NbT
execute "cat /etc/ssh/moduli" #NbT
execute "sshd -T" #NbT
execute "sshd -V" #NbT

### Apache Config
APACHE_BINARY=$(get_absolute_binary_path "httpd" 2> /dev/null)
APACHE_USER=$(get_user_of_binary "httpd" 2> /dev/null)
if [ -z "${APACHE_BINARY}" ]; then
  APACHE_BINARY=$(get_absolute_binary_path "apache2" 2> /dev/null)
  # If its the apache2 binary the command is apache2ctl
  APACHE_BINARY="${APACHE_BINARY}ctl"
  APACHE_USER=$(get_user_of_binary "apache2" 2> /dev/null)
fi

# If an apache binary was found execute the apache related commands. Otherwhise just don't
if [ -n "${APACHE_BINARY}" ] && [ "${APACHE_BINARY}" != "ctl" ] && [ -n "${APACHE_USER}" ]; then
  execute "timeout 10 su --login -c \"${APACHE_BINARY} -V\" ${APACHE_USER}" #NbT
  execute "timeout 10 su --login -c \"${APACHE_BINARY} -S\" ${APACHE_USER}" #NbT
  execute "timeout 10 su --login -c \"${APACHE_BINARY} -M\" ${APACHE_USER}" #NbT
  APACHE_BASE_PATH=$(eval "timeout 10 su --login -c \"${APACHE_BINARY} -S\" ${APACHE_USER}" 2> /dev/null | awk '$1 == "ServerRoot:" { gsub(/"/,"",$2); print $2 }')
  if [ -z "${APACHE_BASE_PATH}" ]; then
    # If -S does not provide the ServerRoot try the HTTP_ROOT of -V.
    APACHE_BASE_PATH=$(eval "timeout 10 su --login -c \"${APACHE_BINARY} -V\" ${APACHE_USER}" 2> /dev/null | awk '$0 ~ "HTTPD_ROOT" { gsub(/"|-D[[:space:]]+HTTPD_ROOT=/,""); gsub(/[[:space:]]/,""); print $0 }')
  fi
  # Apache config on Redhat like systems
  execute "ls -laR \"\${APACHE_BASE_PATH}\"" #NbT
  if [ -n "${APACHE_BASE_PATH}" ]; then
    # This command prints all config files with delimiters inbetween them
    CONFIG_FILES_APACHE=$(tail -n +1 "${APACHE_BASE_PATH}"/*/*.conf "${APACHE_BASE_PATH}"/*.conf  2> /dev/null)
  fi
  execute "echo \"\${CONFIG_FILES_APACHE}\"" #NbT

 # Grab SSL Certificates apache
   CERTIFICATE_FILES_APACHE=$(echo "${CONFIG_FILES_APACHE}" | awk '$0 ~ /^[[:space:]]*SSLCertificateFile/ { gsub(/.*SSLCertificateFile[[:space:]]|\047|"/,""); print $0 }')
  if [ -n "${CERTIFICATE_FILES_APACHE}" ]; then
    # variable not quoted here on purpose since we need globbing
    # shellcheck disable=SC2034,SC2086
    CERTS_APACHE=$(tail -n +1 ${CERTIFICATE_FILES_APACHE})
  fi
  execute "echo \"\${CERTS_APACHE}\"" #NbT
  OPENSSL_CIPHER_SUITES_APACHE=$(echo "${CONFIG_FILES_APACHE}" | awk '$0 ~ /^[[:space:]]*SSLCipherSuite/ { gsub(/.*SSLCipherSuite|\047|"|[[:space:]]/,""); print $0 }')
  if [ -n "${OPENSSL_CIPHER_SUITES_APACHE}" ]; then
    # Get detailed information about the cipher suites used
    # shellcheck disable=SC2034
    EXPANDED_CIPHER_SUITES_APACHE=$(echo "${OPENSSL_CIPHER_SUITES_APACHE}" | { while read -r line; do openssl ciphers -v "${line}"; done })
  fi
  execute "echo \"\${EXPANDED_CIPHER_SUITES_APACHE}\"" # NbT
fi

### NGINX Config
NGINX_BINARY=$(get_absolute_binary_path "nginx" 2> /dev/null)
NGINX_USER=$(get_user_of_binary "nginx" 2> /dev/null)
# If an nginx binary was found execute the nginx related commands. Otherwhise just don't
if [ -n "${NGINX_BINARY}" ] && [ -n "${NGINX_USER}" ]; then
  NGINX_CONFIGS=$(timeout 10 su --login -c "${NGINX_BINARY} -T" "${NGINX_USER}" 2> /dev/null)
  execute "echo \"\${NGINX_CONFIGS}\"" #NbT
  execute "timeout 10 su --login -c \"${NGINX_BINARY} -V\" ${NGINX_USER}" #NbT
  NGINX_FILES_EXPANDED=$(echo "${NGINX_CONFIGS}" | awk '$0 ~ /# configuration file/ { gsub(/# configuration file|:/,""); print $0 }')
  # variable not quoted here on purpose since we need globbing
    # shellcheck disable=SC2034,SC2086
  STAT_OF_NGINX_CONFIGS=$(stat ${NGINX_FILES_EXPANDED} 2> /dev/null)
  execute "echo \"\${STAT_OF_NGINX_CONFIGS}\"" #NbT

  # Grab certificates
  CERT_FILES_NGINX=$(echo "${NGINX_CONFIGS}" | awk '$0 ~ /^[[:space:]]*ssl_certificate[[:space:]]+/ { gsub(/.*ssl_certificate[[:space:]]+/, ""); gsub(/;.*/,""); gsub(/"|'\''/,""); print $0}')
  if [ -n "${CERT_FILES_NGINX}" ]; then
    # variable not quoted here on purpose since we need globbing
    # shellcheck disable=SC2034,SC2086
    CERTS_NGINX=$(tail -n +1 ${CERT_FILES_NGINX})
  fi
  execute "echo \"\${CERTS_NGINX}\"" # NbT
  OPENSSL_CIPHER_SUITES_NGINX=$(echo "${NGINX_CONFIGS}" | awk '$0 ~ /^[[:space:]]*ssl_ciphers[[:space:]]+/ { gsub(/.*ssl_ciphers[[:space:]]+/, ""); gsub(/;.*/,""); gsub(/"|'\''/,""); print $0}')
  if [ -n "${OPENSSL_CIPHER_SUITES_NGINX}" ]; then
    # Get detailed information about the cipher suites used
    # shellcheck disable=SC2034
    EXPANDED_CIPHER_SUITES_NGINX=$(echo "${OPENSSL_CIPHER_SUITES_NGINX}" | { while read -r line; do openssl ciphers -v "${line}"; done })
  fi
  execute "echo \"\${EXPANDED_CIPHER_SUITES_NGINX}\"" # NbT
fi

### Generic Linux OS compliance information collection
# Partitions
execute "cat /etc/fstab" #NbT

# Cron Configurations
execute "stat /etc/cron.allow" #NbT
execute "stat /etc/cron.deny" #NbT
execute "stat /etc/at.allow" #NbT
execute "stat /etc/at.deny" #NbT

# Password requirements
execute "cat /etc/login.defs" #NbT

# Coredumps
execute "cat /etc/security/limits.conf" #NbT
execute "cat /etc/security/limits.d/*" #NbT

# User management
execute "cat /etc/passwd | awk -F : '{print \$1\":\"\$5}'" #NbT
# The next two commands search for system users. The first one for system users with /bin/false, /sbin/nologin or /usr/sbin/nologin as shell
# the second one for all system users. These are then compared in the backend to find system users with a login shell, which
# is prohibited by our security requirements
execute "awk -F':' '(\$1!=\"root\" && \$1!=\"sync\" && \$1!=\"shutdown\" && \$1!=\"halt\" && \$3<1000 && (\$7==\"/bin/false\" || \$7==\"/sbin/nologin\" || \$7==\"/usr/sbin/nologin\") ) {print \$1}' /etc/passwd | wc -l" #NbT
execute "awk -F':' '(\$1!=\"root\" && \$1!=\"sync\" && \$1!=\"shutdown\" && \$1!=\"halt\" && \$3<1000) {print \$1}' /etc/passwd | wc -l" #NbT
# Search for users with active account and no password
# shellcheck disable=SC2034
SHADOW=$(awk -F":" '($2 == "") {print $1}' /etc/shadow 2> /dev/null) #NbT
execute "echo \"\${SHADOW}\" | wc -l" #NbT
execute "passwd --status root" #NbT
execute "grep \"^ExecStart=\" /usr/lib/systemd/system/rescue.service" #NbT
execute "grep \"^ExecStart=\" /lib/systemd/system/rescue.service" #NbT

# Logging
execute "cat /etc/default/grub" #NbT
execute "cat /etc/logrotate.conf" #NbT
execute "cat /etc/logrotate.d/*" #NbT
execute "ls -la /etc/cron.daily/logrotate" #NbT
execute "systemctl list-timers" #NbT for openSUSE

# Time services
execute "timedatectl" #NbT
execute "ntpstat" #NbT

# Auditd
execute "cat /etc/audit/audit.rules" #NbT
execute "cat /etc/audit/rules.d/audit.rules" #NbT

# RSyslog
execute "cat /etc/rsyslog.conf" #NbT
execute "cat /etc/rsyslog.d/*" #NbT

# Syslog-NG
execute "cat /etc/syslog-ng.conf" #NbT
execute "cat /etc/syslog-ng.d/*" #NbT

# PAM
execute "cat /etc/security/pwquality.conf" #NbT
execute "cat /etc/pam.d/common-password" #NbT only available on Ubuntu
execute "cat /etc/pam.d/common-account" #NbT
execute "cat /etc/pam.d/password-auth" #NbT only availble on RedHat
execute "cat /etc/pam.d/system-auth" #NbT only available on RedHat
execute "cat /etc/pam.d/login" #NbT
execute "cat /etc/pam.d/sshd" #NbT

# SELinux
execute "sestatus" #NbT
execute "semanage export" #NbT

# App Armor
execute "apparmor_status" #NbT
execute "cat /etc/apparmor.d/*" #NbT

# Regular Compliance
execute "grep \"root:x:0:0\" /etc/passwd | wc -l" #NbT
# Check for legacy accounts in passwd shadow and group file and count them
execute "grep ^+: /etc/passwd /etc/shadow /etc/group | wc -l" #NbT
execute "stat /etc/passwd" #NbT
execute "stat /etc/shadow" #NbT
execute "stat /etc/group" #NbT
execute "stat /boot/grub2/grub.cfg" #NbT
execute "stat /boot/grub/grub.cfg" #NbT
execute "stat /var/log" #NbT
execute "stat /etc/crontab" #NbT
execute "stat /etc/cron.*" #NbT
execute "stat /etc/ssh/sshd_config" #NbT

# Virtual Environments
# Detect floating ips/ nat ips in cloud environments (OpenStack, AWS, Azure)
execute "timeout 10 curl --noproxy \"*\" http://169.254.169.254/latest/meta-data/public-ipv4" # NbT
execute "lscpu" #NbT
execute "systemd-detect-virt" #NbT

execute "echo \"end timestamp: \$(date +%s)\"" #NbT

# Ouput end marker
echo "${DELIMITER}  END  ${DELIMITER}"

# Cleanup temp files
if [ -f "${TMPFILE_ERR}" ]; then
    rm "${TMPFILE_ERR}"
fi
if [ -f "${TMPFILE_OUT}" ]; then
    rm "${TMPFILE_OUT}"
fi
