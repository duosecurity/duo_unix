#!/usr/bin/env python

import os
import subprocess
import sys
import platform

import paths

def main():
    env = os.environ.copy()

    if sys.platform == 'darwin':
        env['DYLD_LIBRARY_PATH'] = paths.topbuilddir + '/lib/.libs'
        env['DYLD_INSERT_LIBRARIES'] = paths.build + \
                                       '/.libs/liblogin_duo_preload.dylib'
        env['DYLD_FORCE_FLAT_NAMESPACE'] = '1'
    elif sys.platform == 'sunos5':
        architecture = {'32bit': '32', '64bit': '64'}[platform.architecture()[0]]
        env['LD_PRELOAD_' + architecture] = paths.build + '/.libs/liblogin_duo_preload.so'
    else:
        env['LD_PRELOAD'] = paths.build + '/.libs/liblogin_duo_preload.so'

    args = [ paths.login_duo ] + sys.argv[1:]
    p = subprocess.Popen(args, env=env)
    p.wait()
    
    sys.exit(p.returncode)

if __name__ == '__main__':
    main()
