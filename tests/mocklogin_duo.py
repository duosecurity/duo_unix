#!/usr/bin/env python

import os
import pexpect

import paths

PROMPT = '.* or option \(1-4\): $'

def _login_duo():
    p = pexpect.spawn(paths.login_duo + ' -d -c confs/mockduo.conf ' + \
                      '-f foobar echo SUCCESS')
    p.expect(PROMPT, timeout=10)
    print '===> %r' % p.match.group(0)
    return p

def main():
    p = _login_duo()

    # 3 failures in a row
    p.sendline('123456')
    p.expect(PROMPT)
    print '===> %r' % p.match.group(0)
    
    p.sendline('wefawefgoiagj3rj')
    p.expect(PROMPT)
    print '===> %r' % p.match.group(0)
    
    p.sendline('A' * 500)
    p.expect(pexpect.EOF)
    print '===> %r' % p.before

    # menu options
    p = _login_duo()

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
    
    p.sendline('2')
    p.expect(pexpect.EOF)
    print '===> %r' % p.before

if __name__ == '__main__':
    main()

