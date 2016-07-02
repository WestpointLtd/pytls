import struct
import logging

RC4_128_WITH_MD5 = 0x010080
RC4_128_EXPORT40_WITH_MD5 = 0x020080
RC2_128_CBC_WITH_MD5 = 0x030080
RC2_128_CBC_EXPORT40_WITH_MD5 = 0x040080
IDEA_128_CBC_WITH_MD5 = 0x050080
DES_64_CBC_WITH_MD5 = 0x060040
DES_192_EDE3_CBC_WITH_MD5 = 0x0700C0

ssl2_ciphers = [
    RC4_128_WITH_MD5,
    RC4_128_EXPORT40_WITH_MD5,
    RC2_128_CBC_WITH_MD5,
    RC2_128_CBC_EXPORT40_WITH_MD5,
    IDEA_128_CBC_WITH_MD5,
    DES_64_CBC_WITH_MD5,
    DES_192_EDE3_CBC_WITH_MD5
]

class SSL2Record(object):

    def __init__(self):
        self.bytes = ''

    @classmethod
    def create(cls, message, length=-1):
        self = cls()

        if length < 0:
            length = len(message)

        # TODO: Support 3 byte length format too
        self.bytes = struct.pack('!BB',
                                 (length >> 8) | 0x80,
                                 length & 0xff)
        self.bytes += message

        return self

    @classmethod
    def from_bytes(cls, bytes):
        self = cls()
        self.bytes = bytes
        return self

    def message_length(self):
        length, = struct.unpack('!H', self.bytes[0:2])
        return length

    def message(self):
        return self.bytes[2:self.message_length()+2]


class SSL2HandshakeMessage(object):
    
    # Message types
    Error = 0
    ClientHello = 1
    ClientMasterKey = 2
    ClientFinished = 3
    ServerHello = 4
    ServerVerify = 5
    ServerFinished = 6
    RequestCertificate = 7
    ClientCertificate = 8

    message_types = {
        0: 'Error',
        1: 'ClientHello',
        2: 'ClientMasterKey',
        3: 'ClientFinished',
        4: 'ServerHello',
        5: 'ServerVerify',
        6: 'ServerFinished',
        7: 'RequestCertificate',
        8: 'ClientCertificate'
    }

    def __init__(self):
        self.bytes = ''

    @classmethod
    def create(cls, message_type, message):
        self = cls()

        self.bytes = struct.pack('B', message_type)
        self.bytes += message

        return self

    def __len__(self):
        return len(self.bytes)


class SSL2ClientHelloMessage(SSL2HandshakeMessage):

    def __init__(self):
        SSL2HandshakeMessage.__init__(self)

    @classmethod
    def create(cls, client_version=0x0002, cipher_specs=[], cipher_specs_length=-1,
               session_id='', session_id_length=-1, challenge='', challenge_length=-1):

        if cipher_specs_length < 0:
            cipher_specs_length = len(cipher_specs) * 3
        if session_id_length < 0:
            session_id_length = len(session_id)
        if challenge_length < 0:
            challenge_length = len(challenge)

        # Pack ciphers
        ciphers = ''
        for cipher in cipher_specs:
            ciphers += struct.pack('!BH',
                                   cipher >> 16,
                                   cipher & 0xffff)

        message = struct.pack('!HHHH', client_version,
                              cipher_specs_length, session_id_length, challenge_length)
        message += ciphers
        message += session_id
        message += challenge

        return SSL2HandshakeMessage.create(SSL2HandshakeMessage.ClientHello, message)
