#!/bin/sh

if [ $# -ne 2 ]; then
    echo "Usage: testpam.sh <user> <tests_config>" >&2
    exit 1
fi

CWD=`pwd`
USERNAME=$1
CONFIG=$2

cat <<EOF > testpam.pamd
auth    required    ${CWD}/../pam_duo/.libs/pam_duo.so debug conf=confs/${CONFIG}
EOF

export LD_PRELOAD=${CWD}/.libs/libtestpam_preload.so

exec ./testpam $USERNAME
