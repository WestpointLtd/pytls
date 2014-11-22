import struct
from utils import *

class ChangeCipherSpecMessage(object):

    def __init__(self):
        self.bytes = ''

    @classmethod
    def create(cls):
        self = cls()
        self.bytes = '\1'

        return self
