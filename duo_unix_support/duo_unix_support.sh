#!/usr/bin/env bash

# Users can have login_duo installed in different locations by defining a --prefix flag at compile time
PREFIX="/usr"
README_INSTALL="/usr/local"
options=$(getopt -o h -l prefix: -- "$@")
while true; do
    case "$1" in
    --prefix)
        shift;
        PREFIX="$1"
        README_INSTALL="$1"
        ;;
    -h)
        echo "Usage:"
        echo "    ./duo_unix_support.sh -h                       Display this help message."
        echo "    ./duo_unix_support.sh --prefix [dir_name]      Add prefix used to compile Duo Unix with if changed from the default."
        exit
        ;;
    *)
        shift
        break
        ;;
    esac
    shift
done

echo -e "The Duo Unix support script gathers and aggregates information about your Duo Unix installation and the server it is installed on for easy sending to Duo Security support. This script is intended to be used with Debian, Ubuntu, RHEL, and CentOS systems. While use of this script is not required for support cases with Duo, it is highly recommended as it will expedite the support and debugging process. Namely, this script collects:\n\n\t* Logfiles in /var/log, such as auth and secure\n\t* PAM configurations in /etc/pam.d, such as common-auth or sshd\n\t* SSHD configurations in /etc/ssh\n\t* Information about the server distribution and relevant libraries such as SELinux or OpenSSL\n\t* Configurations for pam_duo and login_duo scrubbed of sensitive skeys\n\nThese files are typically asked for during support cases with Duo. We advise that you review any of these files prior to running this script should you wish to expunge any other information you deem sensitive from these files. For a full list of the information collected by this script, see ${README_INSTALL}/share/doc/duo_unix/duo_unix_support/README.md."

read -rp "Do you wish to run this program? [N/y] " user_input

case $user_input in
    [Yy]* ) ;;
    *) exit;;
esac

# Ensure that the person running this script is root
if [ $(id -u) != 0 ]; then
    echo "Please rerun as root"
    exit
fi
# If there is an existing support file or tarball then delete them
if [ -d '/etc/duo/duo_unix_support' ]; then
    rm -rf /etc/duo/duo_unix_support
fi

if [ -e '/etc/duo/duo_unix_support.tar.gz' ]; then
   rm -r /etc/duo/duo_unix_support.tar.gz
fi

if [ -e '/etc/duo' ]; then
    mkdir /etc/duo/duo_unix_support
    cd /etc/duo/duo_unix_support
else
    echo -e "\nNo Duo Unix installation found, exiting"
    exit
fi

# Try to get distro name/version from *-release files.
# This could be something like rhel-release, os-release, lsb_release...
if [ -f /etc/os-release ]; then
    # Covers most modern distros/versions
    . /etc/os-release
    OS=${ID}
    VER=${VERSION_ID}

elif rpm -q centos-release > /dev/null 2>&1; then
    # Older versions of CentOS that have unconventional *-release files
    # without $ID, $VERSION_ID, or the like
    # eg. /etc/rhel-release on CentOS6 reads: CentOS release 6.9 (Final)
    OS='centos'
    VER=$(rpm -q --queryformat '%{VERSION}' centos-release)

elif rpm -q redhat-release-server > /dev/null 2>&1; then
    # Older versions of RHEL that have unconventional *-release files
    OS='rhel'
    VER=$(rpm -q --queryformat '%{RELEASE}' redhat-release-server | awk -F. '{print $1}')

elif [ -f /etc/lsb-release ]; then
    # Certain newer versions of Debian/Ubuntu
    . /etc/lsb-release
    OS=${DISTRIB_ID}
    VER=${DISTRIB_RELEASE}

elif [ -f /etc/debian_version ]; then
    # Certain older versions of Debian
    OS='debian'
    VER=$(cat /etc/debian_version)

else
    VER=$(uname -a)
fi

KERNEL=$(uname -srm)
OPENSSL_VER=$(openssl version)

# login_duo can exist in different locations
if [ -e "${PREFIX}/sbin/login_duo" ]; then
    echo "duo_unix=$(${PREFIX}/sbin/login_duo -v 2>&1)" >> configuration.txt
elif [ -e "${PREFIX}/local/sbin/login_duo" ]; then
    echo "duo_unix=$(${PREFIX}/local/sbin/login_duo -v 2>&1)" >> configuration.txt
else
    echo "Could not find version of Duo Unix (login_duo was not found)" > configuration.txt
fi

echo "operating_system=${OS}" >> configuration.txt
echo "version=${VER}" >> configuration.txt
echo "kernel=${KERNEL}" >> configuration.txt
echo "openssl_version=${OPENSSL_VER}" >> configuration.txt
echo "ssh=$(ssh -V 2>&1)" &>> configuration.txt
echo -e "\nGathering logs and pam configs"
# Check if the user has gcc and make
if type gcc >/dev/null; then
   GCC_VER=$(gcc --version)
   echo "gcc=$GCC_VER" | grep "gcc" >> configuration.txt
fi
if type make >/dev/null; then
   MAKE_VER=$(make --version)
   echo "make=$MAKE_VER" | grep "make" >> configuration.txt
fi

# Copy over common configurations and scrub the skey from the configs

echo "* Successfully copied login_duo.conf"
sed '/skey/d' /etc/duo/login_duo.conf > login_duo.conf
chmod --reference /etc/duo/login_duo.conf login_duo.conf

# The user might not have pam_duo install on their system
if [ -e '/etc/duo/pam_duo.conf' ]; then
    echo "* Successfully copied pam_duo.conf"
    sed '/skey/d' /etc/duo/pam_duo.conf > pam_duo.conf
    chmod --reference /etc/duo/pam_duo.conf pam_duo.conf
fi

check_and_cp () {
  # Check for non-empty argument
  if [ -z $1 ]; then
    echo "Empty argument passed in! Skipping."
  fi

  # Attempt to cp the file over
  if [ -e $1 ]; then
    stderr_output=$(cp -p $1 . 2>&1)
    if [ -z $stderr_output ]; then
      echo "* Successfully copied $1"
    else
      echo "Could not copy $1: $stderr_output"
    fi
  fi
}

#Different Unix systesm utilize different files, it is alright if not all are gathered.
COPY_FILES=(
           "/etc/pam.d/sshd"
           "/etc/pam.d/common-auth"
           "/etc/pam.d/passwd"
           "/etc/pam.d/system-auth"
           "/etc/pam.d/password-auth"
           "/etc/ssh/sshd_config"
           "/var/log/messages"
           "/var/log/secure"
           "/var/log/auth.log"
           "/var/log/syslog"
)

for path in "${COPY_FILES[@]}"
do
  check_and_cp $path
done

# Copy over configurations related only to centos or rhel
if type sestatus &>/dev/null; then
    # Get information about their SELinux policies
    echo -e "\nGathering information about SELinux"
    SESTATUS=$(sestatus)
    SEMODULES=$(semodule -l)
    SEBOOLS=$(getsebool -a)

    echo "sestatus=$SESTATUS" >> selinux_config.txt
    echo "$SEMODULES" >> selinux_modules.txt
    echo "sebools=$SEBOOLS" >> selinux_bools.txt

    #Check to see if sesearch is installed and if it is get policies that use the tcp_socket
    if type sesearch &>/dev/null; then
        SESEARCH=$(sesearch -c tcp_socket -AC)
        echo "sesearch=$SESEARCH" >> selinux_config.txt
    fi
fi
cd ../
if tar -zcpf duo_unix_support.tar.gz duo_unix_support/; then
    chmod 600 /etc/duo/duo_unix_support.tar.gz
    rm -rf /etc/duo/duo_unix_support/
    echo -e "\nPlease send /etc/duo/duo_unix_support.tar.gz to support@duosecurity to open a new support case or continue an ongoing case.\nWe strongly recommend that you keep this file local in the meantime to prevent the tarball from becoming world-readable on flash drives for example. Remember to delete this tarball once sent in."
else
    echo -e "\nFailed to tar /etc/duo/duo_unix_support files, exiting."
fi
