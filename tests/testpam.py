#!/usr/bin/env python

import getopt
import getpass
import os
import subprocess
import sys
import tempfile

# login_duo-compatible wrapper to pam_duo

def usage():
    print >>sys.stderr, 'Usage: %s [-d] [-c config] [-f user] [-h host]' % \
          sys.argv[0]
    sys.exit(1)
    
def main():
    if os.environ.get('BUILDDIR'):
        build = '%s/tests' % os.environ['BUILDDIR']
    else:
        build = os.path.dirname(__file__)
    
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

    args = [ build + '/testpam', opt_user ]
    if opt_host:
        args.append(opt_host)
    
    f = tempfile.NamedTemporaryFile()
    f.write('auth  required  %s/pam_duo.so conf=%s debug' %
            (os.path.realpath(build + '/../pam_duo/.libs'), opt_conf))
    f.flush()
    
    env = os.environ.copy()
    env['LD_PRELOAD'] = os.path.realpath(build + '/.libs/libtestpam_preload.so')
    env['PAM_CONF'] = f.name
    p = subprocess.Popen(args, env=env)
    p.wait()
    f.close()
    
    sys.exit(p.returncode)

if __name__ == '__main__':
    main()
