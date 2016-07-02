#!/usr/bin/python

import sys
import socket
import logging
from optparse import OptionParser

from tls import *

def make_hello():
    hello = SSL2ClientHelloMessage.create(cipher_specs=ssl2_ciphers, challenge='0123456789abcdef')
   
    record = SSL2Record.create(hello.bytes)

    return record.bytes

def test_ssl2(hostname, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    logging.debug('Connecting...')

    s.settimeout(5)
    s.connect((hostname, port))
    starttls(s, port, 'auto')

    f = s.makefile('rw', 0)

    f.write(make_hello())

def main():
    options = OptionParser(usage='%prog server [options]',
                           description='Test for Python SSL')
    options.add_option('-p', '--port',
                       type='int', default=443,
                       help='TCP port to test (default: 443)')
    options.add_option('-d', '--debug', action='store_true', dest='debug',
                       default=False,
                       help='Print debugging messages')

    opts, args = options.parse_args()

    if len(args) < 1:
        options.print_help()
        return

    if opts.debug:
        logging.basicConfig(level=logging.DEBUG)

    test_ssl2(args[0], opts.port)

if __name__ == '__main__':
    main()
