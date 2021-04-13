# http://stackoverflow.com/questions/4999233/how-to-raise-error-if-duplicates-keys-in-dictionary
class RejectingDict(dict):
    def __setitem__(self, k, v):
        if k in self:
            raise ValueError("Key is already present: " + repr(k))
        return super().__setitem__(k, v)

    def force_insert(self, k, v):
        return super().__setitem__(k, v)


class PatchingException(Exception):
    pass

class MissingBlockException(PatchingException):
    pass

class DetourException(PatchingException):
    pass

class DoubleDetourException(PatchingException):
    pass

class InvalidVAddrException(PatchingException):
    pass

class IncompatiblePatchesException(PatchingException):
    pass

class DuplicateLabelsException(PatchingException):
    pass

class AttrDict(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__dict__ = self
