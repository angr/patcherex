
import os
import bisect
import logging
import importlib
from collections import OrderedDict
from collections import defaultdict

from patcherex.patches import *

from ..backend import Backend
from .misc import ASM_ENTRY_POINT_PUSH_ENV, ASM_ENTRY_POINT_RESTORE_ENV

l = logging.getLogger("patcherex.backends.DetourBackend")


"""
symbols will look like {}
"""

# http://stackoverflow.com/questions/4999233/how-to-raise-error-if-duplicates-keys-in-dictionary
class RejectingDict(dict):
    def __setitem__(self, k, v):
        if k in self:
            raise ValueError("Key is already present: " + repr(k))
        else:
            return super(RejectingDict, self).__setitem__(k, v)

    def force_insert(self, k, v):
        return super(RejectingDict, self).__setitem__(k, v)


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

def DetourBackend(filename, data_fallback=None, base_address=None, try_pdf_removal=True):
    with open(filename, "rb") as f:
        start_bytes = f.read(0x14)
        if start_bytes.startswith(b"\x7fCGC"):
            detourbackendclass = getattr(importlib.import_module("patcherex.arch.cgc.detourbackend"), "DetourBackend")
        elif start_bytes.startswith(b"\x7fELF"):
            # more details can be found at glibc/elf/elf.h
            # EM_X86_64 == \x3e\x00
            if start_bytes.startswith(b"\x03\x00", 0x12): # EM_386
                detourbackendclass = getattr(importlib.import_module("patcherex.arch.i386.detourbackend"), "DetourBackend")
            elif start_bytes.startswith(b"\xb7\x00", 0x12): # EM_AARCH64
                detourbackendclass = getattr(importlib.import_module("patcherex.arch.aarch64.detourbackend"), "DetourBackend")
            elif start_bytes.startswith(b"\x28\x00", 0x12): # EM_ARM
                detourbackendclass = getattr(importlib.import_module("patcherex.arch.arm.detourbackend"), "DetourBackend")
            else:
                raise Exception("Unsupported architecture.")
        else:
            raise Exception("Unsupported file type.")

        return detourbackendclass(filename, data_fallback=None, base_address=None, try_pdf_removal=True)

def init_backend(program_name, options):
    return DetourBackend(program_name, **options)
