#!/usr/bin/env python

import BaseHTTPServer
import cgi
import bson
try:
    from hashlib import sha1
except ImportError:
    import sha as sha1
import hmac
import os
import ssl
import sys
import urllib

IKEY = 'DIXYZV6YM8IFYVWBINCA'
SKEY = 'yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo'

class MockDuoHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    server_version = 'MockDuo/1.0'

    def _verify_sig(self):
        authz = self.headers['Authorization'].split()[1].decode('base64')
        ikey, sig = authz.split(':')
        if ikey != IKEY:
            return False
        
        canon = [ self.method, self.headers['Host'].split(':')[0].lower(),
                  self.path ]
        l = []
        for k in sorted(self.args.keys()):
            l.append('%s=%s' % (urllib.quote(k, '~'),
                                urllib.quote(self.args[k], '~')))
        canon.append('&'.join(l))
        h = hmac.new(SKEY, '\n'.join(canon), sha1)
        
        return sig == h.hexdigest()

    def _get_args(self):
        if self.method == 'POST':
            env = { 'REQUEST_METHOD': 'POST',
                    'CONTENT_TYPE': self.headers['Content-Type'] }
            fs = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                                  environ=env)
            args = {}
            for k in fs.keys():
                args[k] = fs[k].value
        else:
            args = dict(cgi.parse_qsl(self.qs))
        self.args = args
    
    def do_GET(self):
        self.method = 'GET'
        self.path, self.qs = self.path.split('?', 1)
        self._get_args()
        
        if not self._verify_sig():
            self.send_response(401)
            self.send_header("Content-length", "0")
            self.end_headers()
            return

        ret = { 'stat': 'OK' }
        
        if self.path == '/rest/v1/status.bson':
            ret['response'] = { 'result': 'allow', 'status': 'good job!' }
        else:
            ret['response'] = { 'result': 'deny', 'status': 'WTF' }
            
        buf = bson.dumps(ret)

        self.send_response(200)
        self.send_header("Content-type", "application/bson")
        self.send_header("Content-length", len(buf))
        self.end_headers()
        self.wfile.write(buf)
        
    def do_POST(self):
        self.method = 'POST'
        self._get_args()
        print self.args

        if not self._verify_sig():
            self.send_response(401)
            self.send_header("Content-length", "0")
            self.end_headers()
            return

        try:
            self.send_response(int(self.args['user']))
            self.send_header("Content-length", "0")
            self.end_headers()
            return
        except:
            pass
        
        ret = { 'stat': 'OK' }
        
        if self.path == '/rest/v1/preauth.bson':
            if self.args['user'] == 'preauth-ok-missing_response':
                pass
            elif self.args['user'] == 'preauth-fail-missing_response':
                ret['stat'] = 'FAIL'
            elif self.args['user'] == 'preauth-bad-stat':
                ret['stat'] = 'FFFFUUUU'
            elif self.args['user'] == 'preauth-fail':
                d = { 'stat': 'FAIL', 'code': 666, 'message': 'you fail' }
            elif self.args['user'] == 'preauth-deny':
                ret['response'] = { 'result': 'deny', 'status': 'you suck' }
            elif self.args['user'] == 'preauth-allow':
                ret['response'] = { 'result': 'allow', 'status': 'you rock' }
            elif self.args['user'] == 'preauth-allow-bad_response':
                ret['response'] = { 'result': 'allow', 'xxx': 'you rock' }
            else:
                ret['response'] = {
                    'result': 'auth',
                    'prompt': 'Duo login for %s\n\n' % self.args['user'] + \
                              '  1. Push\n  2. Phone\n  3. SMS\n  4. F\n\n' + \
                              'Yo momma? ',
                    'factors': {
                        'default': 'push1',
                        '1': 'push1',
                        '2': 'voice1',
                        '3': 'smsrefresh1',
                        '4': 'voice2',
                        }
                    }
        elif self.path == '/rest/v1/auth.bson':
            print 'got self.args', self.args
            if self.args['factor'] == 'auto':
                if self.args['auto'] == 'push1':
                    if self.args['async'] == '1':
                        ret['response'] = { 'txid': 'txPUSH1' }
                    else:
                        ret['response'] = { 'result': 'deny',
                                            'status': 'Push timed out' }
                elif self.args['auto'] == 'voice1':
                    if self.args['async'] == '1':
                        ret['response'] = { 'txid': 'txVOICE1' }
                    else:
                        ret['response'] = { 'result': 'deny',
                                            'status': 'Call timed out' }
                else:
                    ret['response'] = { 'result': 'deny',
                                        'status': 'Invalid auto label' }
            else:
                ret['response'] = { 'result': 'deny',
                                    'status': '%s denied' %
                                    self.args['factor'] }
        elif self.path == '/rest/v1/status':
            ret = { 'stat': 'OK',
                    'response': { 'result': 'tx666' } }
        else:
            self.send_response(404)
            self.send_header("Content-length", "0")
            self.end_headers()
            return

        buf = bson.dumps(ret)

        self.send_response(200)
        self.send_header("Content-type", "application/bson")
        self.send_header("Content-length", len(buf))
        self.end_headers()
        self.wfile.write(buf)
        self.wfile.close()


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
