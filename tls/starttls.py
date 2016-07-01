#!/usr/bin/python

import logging
import struct

starttls_modes = {
    21: 'ftp',
    25: 'smtp',
    110: 'pop3',
    143: 'imap',
    587: 'smtp',
    38476: 'pgsql'
}

def starttls(s, port, mode='auto'):
    logger = logging.getLogger('pytls')

    logger.debug('Using %d, mode %s', port, mode)

    if mode == 'auto':
        if starttls_modes.has_key(port):
            mode = starttls_modes[port]
        else:
            # No starttls
            logger.debug('Not a starttls port')
            return

    if mode == 'none':
        return

    logger.debug('Using starttls mode %s', mode)
    
    BUFSIZ = 1024 # Arbitrary

    if mode == 'smtp':
        s.recv(BUFSIZ)
        s.send("EHLO sslchecker.westpoint.ltd.uk\r\n")
        s.recv(BUFSIZ)
        s.send("STARTTLS\r\n")
        s.recv(BUFSIZ)
    elif mode == 'pop3':
        s.recv(BUFSIZ)
        s.send("STLS\r\n")
        s.recv(BUFSIZ)
    elif mode == 'imap':
        s.recv(BUFSIZ)
        s.send("A0001 STARTTLS\r\n")
        s.recv(BUFSIZ)
    elif mode == 'ftp':
        s.recv(BUFSIZ)
        s.send("AUTH TLS\r\n")
        s.recv(BUFSIZ)
    elif mode == 'pgsql':
        msg = struct.pack('BBBBBBBB', 0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f)
        s.send(msg)
        s.recv(BUFSIZ)
    else:
        raise Exception('Unknown starttls mode, %s' % mode)

if __name__ == '__main__':
    import sys
    import socket

    logging.basicConfig(level=logging.DEBUG)

    host = sys.argv[1]
    port = int(sys.argv[2])
    if len(sys.argv) == 4:
        mode = sys.argv[3]
    else:
        mode = 'auto'

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #s.settimeout(5)
    s.connect((host, port))
    starttls(s, port, mode)

    f = s.makefile('rw', 0)



