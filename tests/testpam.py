#!/usr/bin/env python

import getopt
import getpass
import os
import sys

# login_duo-compatible wrapper to pam_duo

def usage():
    print >>sys.stderr, 'Usage: %s [-d] [-c config] [-f username] [-h host]\n' % \
          sys.argv[0]
    sys.exit(1)
    
def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'dc:f:h:')
    except getopt.GetoptError:
        usage()

    opt_conf = '/etc/duo/pam_duo.conf'
    opt_user = getpass.getuser()
    opt_host = None
    
    for o, a in opts:
        if o == '-c':
            opt_conf = a
        elif o == '-f':
            opt_user = a
        elif o == '-h':
            opt_host = a

    args = [ 'testpam', opt_user ]
    if opt_host:
        args.append(opt_host)
    
    if os.environ.get('BUILDDIR'):
        CWD = '%s/tests' % os.environ['BUILDDIR']
    else:
        CWD = '.'
        
    pam_duo = os.path.realpath('%s/../pam_duo/.libs/pam_duo.so' % CWD)
    f = open('testpam.pamd', 'w')
    f.write('auth    required    %s conf=%s debug' % (pam_duo, opt_conf))
    f.close()
    
    libtestpam = os.path.realpath('%s/.libs/libtestpam_preload.so' % CWD)
    env = { 'LD_PRELOAD': libtestpam }

    os.execve('%s/testpam' % CWD, args, env)

if __name__ == '__main__':
    main()
