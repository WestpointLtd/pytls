#!/usr/bin/python

import sys
import socket
import logging
from optparse import OptionParser
import subprocess

from tls import *

def make_hello(version, cipher):
    hello = ClientHelloMessage.create(version,
                                      '01234567890123456789012345678901',
                                      [cipher])
    
    record = TLSRecord.create(content_type=TLSRecord.Handshake,
                              version=TLSRecord.TLS1_0,
                              message=hello.bytes)

    #hexdump(record.bytes)
    return record.bytes


def supports_cipher(f, version, cipher):
    logging.debug('Sending Client Hello for %d...', cipher)
    f.write(make_hello(version, cipher))

    logging.debug('Waiting for ServerHello...')
    while True:
        record = read_tls_record(f)

        # Look for server hello message.
        if record.content_type() == TLSRecord.Handshake:
            message = HandshakeMessage.from_bytes(record.message())
            if message.message_type() == HandshakeMessage.ServerHello:
                logging.debug('Got server hello...')
                logging.debug('Version: %s, %s', TLSRecord.tls_versions.get(message.server_version(), 'UNKNOWN!'), \
                              hex(message.server_version()))

                selected_cipher = message.cipher_suite()
                if selected_cipher == cipher:
                    return True
                else:
                    logging.warning('BUGGY SERVER:\t%s\t%s', 
                                    cipher_suites.get(selected_cipher, 'UNKNOWN!'), 
                                    hex(message.cipher_suite()))
                    return False
            else:
                raise Exception('Unexpected handshake message')
        elif record.content_type() == TLSRecord.Alert:
            alert = AlertMessage.from_bytes(record.message())
            if alert.alert_level() == AlertMessage.Fatal:
                logging.debug('Server sent a fatal alert')
                return False
        else:
            logging.debug('Record received type %d', record.content_type())
            return False

def test_cipher(hostname, port, version, cipher):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    logging.debug('Connecting...')

    s.settimeout(5)
    s.connect((hostname, port))
    f = s.makefile('rw', 0)
    #f = LoggedFile(f)

    try:
        return supports_cipher(f, version, cipher)
    finally:
        f.close()
        s.close()


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

    supported = set()

    for version in [TLSRecord.SSL3, TLSRecord.TLS1_0, TLSRecord.TLS1_1, TLSRecord.TLS1_2 ]:
        for cipher in cipher_suites.keys():
            if test_cipher(args[0], opts.port, version, cipher):
                supported.add(cipher)

    for cipher in supported:
        print cipher_suites.get(cipher, 'UNKNOWN!'), hex(cipher)


 
if __name__ == '__main__':
    main()


