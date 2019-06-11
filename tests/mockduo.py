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
import time
import urllib
import socket

IKEY = 'DIXYZV6YM8IFYVWBINCA'
SKEY = 'yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo'
# Used to check if the FQDN is set to either the ipv4 or ipv6 address
IPV6_LOOPBACK_ADDR = '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa'
IPV4_LOOPBACK_ADDR = '1.0.0.127.in-addr.arpa'

tx_msgs = {
    'txPUSH1': [ '0:Pushed a login request to your phone.',
                 '1:Success. Logging you in...' ],
    'txVOICE1': [ '0:Dialing XXX-XXX-1234...',
                  "1:Answered. Press '#' on your phone to log in.",
                  '1:Success. Logging you in...' ],
    'txSMSREFRESH1': [ '0:New SMS passcodes sent' ],
    'txVOICE2': [ '0:Dialing XXX-XXX-5678...',
                  "1:Answered. Press '#' on your phone to log in.",
                  '2:Authentication timed out.' ],
    }

class MockDuoHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    server_version = 'MockDuo/1.0'
    protocol_version = 'HTTP/1.1'

    def _verify_sig(self):
        authz = self.headers['Authorization'].split()[1].decode('base64')
        ikey, sig = authz.split(':')
        if ikey != IKEY:
            return False
        
        canon = [ self.method,
                  self.headers['Host'].split(':')[0].lower(),
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
        print 'got %s %s args: %s' % (self.method, self.path, args)
        return args

    def _get_tx_response(self, txid, async):
        last = True
        if txid not in tx_msgs:
            secs, msg = 0, 'Invalid passcode, please try again.'
        elif async:
            secs, msg = tx_msgs[txid].pop(0).split(':', 1)
            last = not tx_msgs[txid]
        else:
            secs, msg = tx_msgs[txid][-1].split(':', 1)
        
        if msg.startswith('Success'):
            rsp = { 'result': 'allow', 'status': msg }
        elif async and not last:
            rsp = { 'status': msg }
        else:
            rsp = { 'result': 'deny', 'status': msg }
        time.sleep(int(secs))
        return rsp

    def _send(self, code, buf=''):
        self.send_response(code)
        self.send_header("Content-length", str(len(buf)))
        if buf:
            self.send_header("Content-type", "application/bson")
            self.end_headers()
            self.wfile.write(buf)
        else:
            self.end_headers()
        
    def do_GET(self):
        self.method = 'GET'
        self.path, self.qs = self.path.split('?', 1)
        self.args = self._get_args()
        
        if not self._verify_sig():
            return self._send(401)
        
        ret = { 'stat': 'OK' }
        
        if self.path == '/rest/v1/status.bson':
            ret['response'] = self._get_tx_response(self.args['txid'], 1)
            buf = bson.dumps(ret)
            return self._send(200, buf)

        self._send(404)

    def hostname_check(self, hostname):
        domain_fqdn = socket.getfqdn().lower()
        if hostname == domain_fqdn.lower() or hostname == socket.gethostname().lower():
            return True 
        #Check if socket.getfqdn() is the loopback address for ipv4 or ipv6 then check the hostname of the machine 
        if domain_fqdn == IPV6_LOOPBACK_ADDR or domain_fqdn == IPV4_LOOPBACK_ADDR:
            if hostname == socket.gethostbyaddr(socket.gethostname())[0].lower():
                return True
        return False 

    def do_POST(self):
        self.method = 'POST'
        self.args = self._get_args()
        
        if not self._verify_sig():
            return self._send(401)
        
        try:
            return self._send(int(self.args['user']))
        except:
            ret = { 'stat': 'OK' }
        
        if self.path == '/rest/v1/preauth.bson':
            if self.args['user'] == 'preauth-ok-missing_response':
                pass
            elif self.args['user'] == 'preauth-fail-missing_response':
                ret['stat'] = 'FAIL'
            elif self.args['user'] == 'preauth-bad-stat':
                ret['stat'] = 'BAD_STATUS'
            elif self.args['user'] == 'preauth-fail':
                ret = { 'stat': 'FAIL', 'code': 1000, 'message': 'Pre-authentication failed' }
            elif self.args['user'] == 'preauth-deny':
                ret['response'] = { 'result': 'deny', 'status': 'preauth-denied' }
            elif self.args['user'] == 'preauth-allow':
                ret['response'] = { 'result': 'allow', 'status': 'preauth-allowed' }
            elif self.args['user'] == 'preauth-allow-bad_response':
                ret['response'] = { 'result': 'allow', 'xxx': 'preauth-allowed-bad-response' }
            elif (self.args['user'] == 'hostname'):
                if (self.hostname_check(self.args['hostname'].lower())):
                    ret['response'] = { 'result': 'deny', 'status': 'correct hostname' }
                else:
                    response = "hostname recieved: " + self.args['hostname'] + " found: " + socket.getfqdn()
                    ret['response'] = { 'result': 'deny', 'status': response }
            elif self.args['user'] == 'failopen':
                if self.args['failmode'] == 'open':
                    ret['response'] = { 'result': 'deny', 'status': 'correct failmode' }
                else:
                    ret['response'] = { 'result': 'deny', 'status': 'incorrect failmode' }
            elif self.args['user'] == 'failclosed':
                if self.args['failmode'] == 'closed':
                    ret['response'] = { 'result': 'deny', 'status': 'correct failmode' }
                else:
                    ret['response'] = { 'result': 'deny', 'status': 'incorrect failmode' }
            elif self.args['user'] == 'gecos_user_gecos_field6':
                ret['response'] = { 'result': 'allow', 'status': 'gecos-user-gecos-field6-allowed' }
            elif self.args['user'] == 'gecos_user_gecos_field3':
                ret['response'] = { 'result': 'allow', 'status': 'gecos-user-gecos-field3-allowed' }
            elif self.args['user'] == 'full_gecos_field':
                ret['response'] = { 'result': 'allow', 'status': 'full-gecos-field' }
            elif self.args['user'] == 'gecos/6':
                ret['response'] = { 'result': 'allow', 'status': 'gecos/6' }
            else:
                ret['response'] = {
                    'result': 'auth',
                    'prompt': 'Duo login for %s\n\n' % self.args['user'] + \
                              'Choose or lose:\n\n' + \
                              '  1. Push 1\n  2. Phone 1\n' + \
                              '  3. SMS 1 (deny)\n  4. Phone 2 (deny)\n\n' + \
                              'Passcode or option (1-4): ',
                    'factors': {
                        'default': 'push1',
                        '1': 'push1',
                        '2': 'voice1',
                        '3': 'smsrefresh1',
                        '4': 'voice2',
                        }
                    }
        elif self.path == '/rest/v1/auth.bson':
            if self.args['factor'] == 'auto':
                txid = 'tx' + self.args['auto'].upper()
                if self.args['async'] == '1':
                    ret['response'] = { 'txid': txid }
                else:
                    ret['response'] = self._get_tx_response(txid, 0)
            else:
                ret['response'] = { 'result': 'deny',
                                    'status': 'no %s' % self.args['factor'] }
            if (self.args['user'] == 'auth_timeout'):
                return self._send(500)
        else:
            return self._send(404)

        buf = bson.dumps(ret)
        
        return self._send(200, buf)

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
