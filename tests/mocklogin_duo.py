#!/usr/bin/env python

import os
import pexpect

import paths

PROMPT = '.* or option \(1-4\): $'

def _login_duo():
    return pexpect.spawn(paths.login_duo + ' -d -c confs/mockduo.conf ' + \
                         '-f foobar echo SUCCESS')

def main():
    p = _login_duo()
    
    p.expect(PROMPT, timeout=2)
    print '===> %r' % p.match.group(0)

    p.sendline('3')
    p.expect(PROMPT)
    print '===> %r' % p.match.group(0)
    
    p.sendline('4')
    p.expect(PROMPT)
    print '===> %r' % p.match.group(0)

    p.sendline('1')
    p.expect(pexpect.EOF)
    print '===> %r' % p.before

    p = _login_duo()
    
    p.expect(PROMPT, timeout=2)
    print '===> %r' % p.match.group(0)
        
    p.sendline('2')
    p.expect(pexpect.EOF)
    print '===> %r' % p.before

if __name__ == '__main__':
    main()

