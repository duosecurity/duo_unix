#!/usr/bin/env bash
#
# SPDX-License-Identifier: GPL-2.0-with-classpath-exception
#
# duo_unix_support.sh
#
# Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
# All rights reserved.
#


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

echo -e "The Duo Unix support script gathers and aggregates information about your Duo Unix installation and the server it is installed on for easy sending to Duo Security support. This script is intended to be used with Debian, Ubuntu, RHEL, and CentOS systems. While use of this script is not required for support cases with Duo, it is highly recommended as it will expedite the support and debugging process. Namely, this script collects:\n\n\t* Logfiles such as auth.log, secure, and authlog from /var/log and /var/adm\n\t* PAM configurations in /etc/pam.d, such as common-auth or sshd\n\t* SSHD configurations in /etc/ssh\n\t* Information about the server distribution and relevant libraries such as SELinux or OpenSSL\n\t* Configurations for pam_duo and login_duo, scrubbed to include only an allowlist of non-sensitive options (skey and http_proxy userinfo are redacted)\n\nThese files are typically asked for during support cases with Duo. We advise that you review any of these files prior to running this script should you wish to expunge any other information you deem sensitive from these files. For a full list of the information collected by this script, see ${README_INSTALL}/share/doc/duo_unix/duo_unix_support/README.md."

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

if type ggrep >/dev/null 2>&1; then
    GREP=ggrep
else
    GREP=grep
fi

echo "operating_system=${OS}" >> configuration.txt
echo "version=${VER}" >> configuration.txt
echo "kernel=${KERNEL}" >> configuration.txt
echo "openssl_version=${OPENSSL_VER}" >> configuration.txt
echo "ssh=$(ssh -V 2>&1)" &>> configuration.txt
echo -e "\nGathering logs and pam configs"
# Check if the user has gcc and make
if type gcc &>/dev/null; then
   GCC_VER=$(gcc --version)
   echo "gcc=$GCC_VER" | $GREP "gcc" >> configuration.txt
fi
if type make &>/dev/null; then
   MAKE_VER=$(make --version)
   echo "make=$MAKE_VER" | $GREP "make" >> configuration.txt
fi

# Emit an allowlisted subset of /etc/duo/*.conf into the bundle.
scrub_duo_conf () {
    src="$1"
    dst="$2"
    ( umask 077 && : > "$dst" ) || return 1
    if ! awk '
        BEGIN {
            split("ikey host cafile http_proxy groups group failmode pushinfo noverify prompts autopush accept_env_factor fallback_local_ip https_timeout send_gecos gecos_parsed gecos_delim gecos_username_pos verified_push motd", a, " ")
            for (i in a) allow[a[i]] = 1
            dropped = 0
        }
        # Strip an inline "; ..." comment matching lib/ini.c semantics.
        function strip_inline_comment(v,    i, c, prev) {
            prev = ""
            for (i = 1; i <= length(v); i++) {
                c = substr(v, i, 1)
                if (c == ";" && (prev == " " || prev == "\t" || prev == "")) {
                    v = substr(v, 1, i - 1)
                    break
                }
                prev = c
            }
            sub(/[[:space:]]+$/, "", v)
            return v
        }
        # Replace userinfo in http_proxy with "REDACTED@", keeping the host.
        function redact_userinfo(v,    lower, scheme_len, scheme, rest, i, c, auth_end, last_at) {
            scheme_len = 0
            lower = tolower(v)
            if (substr(lower, 1, 7) == "http://") {
                scheme_len = 7
            } else if (substr(lower, 1, 8) == "https://") {
                scheme_len = 8
            }
            scheme = substr(v, 1, scheme_len)
            rest = substr(v, scheme_len + 1)
            first_term = 0
            for (i = 1; i <= length(rest); i++) {
                c = substr(rest, i, 1)
                if (c == "/" || c == "?" || c == "#") {
                    first_term = i
                    break
                }
            }
            auth_end = (first_term > 0) ? first_term : length(rest) + 1
            last_at = 0
            for (i = 1; i < auth_end; i++) {
                if (substr(rest, i, 1) == "@") {
                    last_at = i
                }
            }
            if (last_at == 0 && first_term > 0) {
                # Fallback: "@" only appears past first_term.
                for (i = first_term; i <= length(rest); i++) {
                    if (substr(rest, i, 1) == "@") {
                        last_at = i
                        auth_end = length(rest) + 1
                    }
                }
            }
            if (last_at == 0) {
                return v
            }
            if (auth_end > length(rest)) {
                return scheme "REDACTED@" substr(rest, last_at + 1)
            }
            return scheme "REDACTED@" substr(rest, last_at + 1, auth_end - last_at - 1) substr(rest, auth_end)
        }
        {
            line = $0
            if (line ~ /^[[:space:]]*$/) {
                print line
                next
            }
            if (line ~ /^[[:space:]]*[#;]/) {
                if (tolower(line) ~ /skey/) {
                    dropped++
                    next
                }
                print line
                next
            }
            if (line ~ /^[[:space:]]*\[[^]]*\][[:space:]]*$/) {
                print line
                next
            }
            if (match(line, /^[[:space:]]*[A-Za-z_][A-Za-z0-9._-]*[[:space:]]*=/) == 0) {
                next
            }
            eq = index(line, "=")
            name = substr(line, 1, eq - 1)
            sub(/^[[:space:]]+/, "", name)
            sub(/[[:space:]]+$/, "", name)
            if (!(name in allow)) {
                dropped++
                next
            }
            value = substr(line, eq + 1)
            sub(/^[[:space:]]+/, "", value)
            value = strip_inline_comment(value)
            if (name == "http_proxy") {
                value = redact_userinfo(value)
            }
            print name " = " value
        }
        END {
            if (dropped > 0) {
                print ""
                print "; " dropped " option(s) from the original file were dropped by"
                print "; duo_unix_support.sh because they are not on the support-bundle"
                print "; allowlist. Names and values are withheld."
            }
        }
    ' "$src" >> "$dst"; then
        echo "Failed to scrub $src" >&2
        return 1
    fi
}

echo "* Successfully copied login_duo.conf"
if ! scrub_duo_conf /etc/duo/login_duo.conf login_duo.conf; then
    echo "Aborting: could not produce scrubbed login_duo.conf" >&2
    exit 1
fi
chmod --reference /etc/duo/login_duo.conf login_duo.conf

# The user might not have pam_duo install on their system
if [ -e '/etc/duo/pam_duo.conf' ]; then
    echo "* Successfully copied pam_duo.conf"
    if ! scrub_duo_conf /etc/duo/pam_duo.conf pam_duo.conf; then
        echo "Aborting: could not produce scrubbed pam_duo.conf" >&2
        exit 1
    fi
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
           "/etc/pam.conf"
           "/etc/pam.d/common-auth"
           "/etc/pam.d/other"
           "/etc/pam.d/passwd"
           "/etc/pam.d/password-auth"
           "/etc/pam.d/sshd"
           "/etc/pam.d/sudo"
           "/etc/pam.d/sudo-i"
           "/etc/pam.d/system-auth"
           "/etc/pam_debug"
           "/etc/security/login.cfg"
           "/etc/ssh/sshd_config"
           "/var/log/auth.log"
           "/var/log/messages"
           "/var/log/secure"
           "/var/log/syslog"
           "/var/adm/messages"
           "/var/adm/messages.0"
           # Solaris auth log paths
           "/var/adm/authlog"
           "/var/log/authlog"
)

PAM_DUO_FILES=$($GREP -ilr "pam_duo.so" "/etc/pam.d")
# There might be duplicates but that's fine
COPY_FILES+=(${PAM_DUO_FILES[@]})

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
