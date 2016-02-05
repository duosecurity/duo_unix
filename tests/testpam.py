#!/usr/bin/env python

import getopt
import getpass
import os
import subprocess
import sys
import tempfile
import platform

import paths

# login_duo-compatible wrapper to pam_duo

def usage():
    print >>sys.stderr, 'Usage: %s [-d] [-c config] [-f user] [-h host]' % \
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

    args = [ paths.build + '/testpam', opt_user ]
    if opt_host:
        args.append(opt_host)
    
    f = tempfile.NamedTemporaryFile()
    #f = open('/tmp/pam.conf', 'w')
    if sys.platform == 'sunos5':
        f.write('testpam ')
    f.write('auth  required  %s/pam_duo.so conf=%s debug' %
            (paths.topbuilddir + '/pam_duo/.libs', opt_conf))
    f.flush()
    
    env = os.environ.copy()
    env['PAM_CONF'] = f.name

    if sys.platform == 'darwin':
        env['DYLD_LIBRARY_PATH'] = paths.topbuilddir + '/lib/.libs'
        env['DYLD_INSERT_LIBRARIES'] = paths.build + \
                                       '/.libs/libtestpam_preload.dylib'
        env['DYLD_FORCE_FLAT_NAMESPACE'] = '1'
    elif sys.platform == 'sunos5':
        architecture = {'32bit': '32', '64bit': '64'}[platform.architecture()[0]]
        env['LD_PRELOAD_' + architecture] = paths.build + '/.libs/libtestpam_preload.so'
    else:
        env['LD_PRELOAD'] = paths.build + '/.libs/libtestpam_preload.so'
        
    p = subprocess.Popen(args, env=env)
    p.wait()
    f.close()
    
    sys.exit(p.returncode)

if __name__ == '__main__':
    main()
