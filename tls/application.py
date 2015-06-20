
class ApplicationMessage(object):

    def __init__(self):
        self.bytes = ''

    def data():
        return self.bytes

    @classmethod
    def create(cls, data=''):
        self = cls()
        self.bytes = data
        return self

    @classmethod
    def from_bytes(cls, bytes):
        self = cls()
        self.bytes = bytes
        return self

