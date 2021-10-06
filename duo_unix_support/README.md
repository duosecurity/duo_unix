The Duo Unix Support Script is intended to be used to gather information used for debugging Duo Unix issues by Duo Security.  The main purpose of this script is to easily gather and tar information for the sole purpose of debugging.  Please use this script as directed by Duo and delete the tarball, /etc/duo/duo_unix_support.tar.gz, that is generated after use.
This script is supported by Debian, Ubuntu, Red Hat Enterprise Linux, and CentOS.
The following information may be gathered by this script depending on the Operating System:

Logs
    /var/log/secure
    /var/log/messages
    /var/log/auth.log
    /var/log/syslog

Configs
    /etc/duo/login_duo.conf
    /etc/duo/pam_duo.conf
    (With the skeys scrubbed)
    /etc/ssh/sshd_config

PAM Stacks
    /etc/pam.d/sshd
    /etc/pam.d/sudo
    /etc/pam.d/passwd
    /etc/pam.d/common-auth
    /etc/pam.d/system-auth

SELinux
    sebools
    semodules
    sestatus
    Policies that use TCP sockets

Software versions
    Operating System
    Kernel
    OpenSSL
    OpenSSH
    Duo Unix
    gcc
    make

Use
    Ensure either that you are logged in as root or are using sudo before proceeding.

    # chmod +x ./duo_unix_support.sh
    # ./duo_unix_support.sh

    This script will create the file duo_unix_support.tar.gz which will be located in /etc/duo. Delete duo_unix_support.tar.gz after use.
