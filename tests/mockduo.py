#!/usr/bin/python

import BaseHTTPServer
import cgi
import bson
import hashlib
import hmac
import os
import ssl
import sys
import urllib

IKEY = 'DIXYZV6YM8IFYVWBINCA'
SKEY = 'yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo'

def test1(req, path):
    if path == 'preauth':
        return { 'stat': 'OK',
                 'response': { 'result': 'deny', 'status': 'you suck' } }

                 
class MockDuoHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    server_version = 'MockDuo/1.0'

    def _verify_sig(self, skey, args):
        authz = self.headers['Authorization'].split()[1].decode('base64')
        ikey, sig = authz.split(':')
        if ikey != IKEY:
            return False
        
        canon = [ 'POST', self.headers['Host'], self.path ]
        l = []
        for k in sorted(args.keys()):
            l.append('%s=%s' % (urllib.quote(k, '~'),
                                urllib.quote(args[k], '~')))
        canon.append('&'.join(l))
        h = hmac.new(SKEY, '\n'.join(canon), hashlib.sha1)
        
        return sig == h.hexdigest()

    def _get_args(self):
        env = { 'REQUEST_METHOD': 'POST',
                'CONTENT_TYPE': self.headers['Content-Type'] }
        fs = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ=env)
        args = {}
        for k in fs.keys():
            args[k] = fs[k].value
        print 'args:', args
        return args

    def do_GET(self):
        args = self._get_args();
        print args

        if not self._verify_sig(SKEY, args):
            self.send_response(401)
            self.end_headers()
            return

        if self.path == '/rest/v1/status.bson':
            ret = { 'stat': 'OK',
                    'response': 'hello world' }
        
        self.send_response(200)
        self.send_header("Content-type", "application/bson")
        self.end_headers()
        self.wfile.write(bson.dumps(ret))
        
    def do_POST(self):
        args = self._get_args();

        if not self._verify_sig(SKEY, args):
            self.send_response(401)
            self.end_headers()
            return

        try:
            self.send_response(int(args['user']))
            self.end_headers()
            return
        except:
            pass
        
        if self.path == '/rest/v1/preauth.bson':
            ret = { 'stat': 'OK' }
            if args['user'] == 'preauth-ok-missing_response':
                pass
            elif args['user'] == 'preauth-fail-missing_response':
                ret['stat'] = 'FAIL'
            elif args['user'] == 'preauth-bad-stat':
                ret['stat'] = 'FFFFUUUU'
            elif args['user'] == 'preauth-fail':
                d = { 'stat': 'FAIL', 'code': 666, 'message': 'you fail' }
            elif args['user'] == 'preauth-deny':
                ret['response'] = { 'result': 'deny', 'status': 'you suck' }
            elif args['user'] == 'preauth-allow':
                ret['response'] = { 'result': 'allow', 'status': 'you rock' }
            elif args['user'] == 'preauth-allow-bad_response':
                ret['response'] = { 'result': 'allow', 'xxx': 'you rock' }
            else:
                ret['response'] = {
                    'result': 'auth',
                    'prompt': 'Duo login for %s\n\n' % args['user'] + \
                              '  1. Red\n  2. Green\n  3. Blue\n\n' + \
                              'Yo momma? ',
                    'factors': {
                        'default': 'red',
                        '1': 'red',
                        '2': 'green',
                        '3': 'blue',
                        }
                    }
        elif self.path == '/rest/v1/auth.bson':
            print 'got args', args
            ret = { 'stat': 'OK',
                    'response': { 'result': 'deny', 'status': 'denied' } }
        elif self.path == '/rest/v1/status':
            ret = { 'stat': 'OK',
                    'response': { 'result': 'tx666' } }
        else:
            self.send_response(404)
            self.end_headers()
            return
        
        self.send_response(200)
        self.send_header("Content-type", "application/bson")
        self.end_headers()
        self.wfile.write(bson.dumps(ret))


def main():
    port = 4443
    host = 'localhost'
    if len(sys.argv) == 1:
        cafile = os.path.realpath('%s/certs/mockduo.pem' %
                                  os.path.dirname(__file__))
    elif len(sys.argv) == 2:
        cafile = sys.argv[1]
    else:
        print >>sys.stderr, 'Usage: %s [certfile]\n' % sys.argv[0]
        sys.exit(1)
    
    httpd = BaseHTTPServer.HTTPServer((host, port), MockDuoHandler)

    httpd.socket = ssl.wrap_socket(
        httpd.socket,
        certfile=cafile,
        server_side=True
        )

    httpd.serve_forever()
    
if __name__ == '__main__':
    main()
