#!/bin/bash
# Script that will check if the current distro/distro version we're running in
# is capable of running FIPS tests.
# Returns 0 if it's capable of doing so, 1 otherwise.
# We also echo the return code before exiting since there's no good way to capture it
# without some actual output in cram :(

FIPS_VALIDATED_DISTROS=("centos8" "rhel8" "centos7" "rhel7" "centos6" "rhel6")

# We can't use uname since that won't work with Docker images.
# See https://stackoverflow.com/questions/31012297/uname-a-returning-the-same-in-docker-host-or-any-docker-container for more details.

# Try to get distro name/version from *-release files.
# This could be something like rhel-release, os-release, lsb_release...
if [ -f /etc/os-release ]; then
    # Covers most modern distros/versions
    . /etc/os-release
    OS=${ID,,} # force lowercase
    VER=${VERSION_ID%.*} # truncate decimal, if any, to get major version, eg. 7 in 7.5 or 16 from 16.04

elif [ -f /etc/lsb-release ]; then
    # Certain newer versions of Debian/Ubuntu
    . /etc/lsb-release
    OS=${DISTRIB_ID,,} # force lowercase
    VER=$DISTRIB_RELEASE

elif [ -f /etc/debian_version ]; then
    # Certain older versions of Debian
    OS="debian"
    VER=$(cat /etc/debian_version)

elif rpm -q centos-release > /dev/null 2>&1; then
    # Older versions of CentOS that have unconventional *-release files
    # without $ID, $VERSION_ID, or the like
    # eg. /etc/rhel-release on CentOS6 reads: CentOS release 6.9 (Final)
    OS="centos"
    VER=$(rpm -q --queryformat '%{VERSION}' centos-release)

elif rpm -q redhat-release-server > /dev/null 2>&1; then
    # Older versions of RHEL that have unconventional *-release files
    OS="rhel"
    VER=$(rpm -q --queryformat '%{RELEASE}' redhat-release-server | awk -F. '{print $1}')

else
    # It's a weird one! Assume it's probably not something we support.
    echo "1"
    exit 1
fi

# Assemble the name together
distro_name="$OS$VER"

# Check that this distro's in our list of supported FIPS distros
for i in "${FIPS_VALIDATED_DISTROS[@]}" ; do
    if [ "$distro_name" == "$i" ] ; then
        # If we are in a FIPS-validated distro, check for presence of FIPS headers
        # It's entirely possible we're in a FIPS-validated distro that still lacks FIPS headers,
        # eg. if the FIPS module isn't installed for some reason
        has_fips_headers=$(gcc -dM -include "openssl/crypto.h" -E - < /dev/null 2>/dev/null | grep '#define OPENSSL_FIPS')
        retcode="$?"
        echo $retcode
        exit $retcode
    fi
done

# We're not using a FIPS-validated distro. Return failure.
echo "1"
exit 1
