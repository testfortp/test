
class Fault(Exception):
    def __init__(self, reason, code=255):
        self.code = code
        self.reason = reason

    def __str__(self):
        return repr(self.code)+" ("+repr(self.reason)+")"

    def __repr__(self):
        return self.__str__()


