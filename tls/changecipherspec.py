import struct
from utils import *

class ChangeCipherSpecMessage(object):

    def __init__(self):
        self.bytes = ''

    def value(self):
        return ord(self.bytes[0])

    @classmethod
    def create(cls):
        self = cls()
        self.bytes = '\1'

        return self

    @classmethod
    def from_bytes(cls, bytes):
        self = cls()
        self.bytes = bytes
        return self

    def __len__(self):
        return len(self.bytes)
