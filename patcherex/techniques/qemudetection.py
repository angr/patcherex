import patcherex

import logging
import struct
from patcherex.patches import *

l = logging.getLogger("patcherex.techniques.QemuDetection")

class QemuDetection(object):

    def __init__(self,binary_fname,backend):
        self.binary_fname = binary_fname
        self.patcher = backend

    def get_patches(self):
        patches = []
        added_code = '''
            ;int transmit(int fd, const void *buf, size_t count, size_t *tx_bytes) [2]
            xor eax, eax
            push eax
            mov esi, esp
            mov eax, 0x2

            mov ebx, 0x2 ;stderr!
            ; it seems that at least one page must exist
            mov ecx,  0xbaaa9001 ;two pages before the end of the stack + 1
            mov edx, 0x10000
            int 0x80
            test eax, eax
            je _e1
            mov eax, 0x40
            call {exit_eax}
            _e1:
            pop eax
            ; I am just checking that it is different from 0
            ; from a full discussion of this very complicated matter read:
            ; https://git.seclab.cs.ucsb.edu/cgc/tracer/issues/3
            cmp eax, 0
            jg _e2
            mov eax, 0x41
            call {exit_eax}
            _e2:
        '''
        patches.append(AddEntryPointPatch(added_code,name="detect_qemu"))

        added_code = '''
            mov     ebx, eax
            mov     eax, 0x1
            int     80h
        '''
        patches.append(AddCodePatch(added_code,name="exit_eax"))

        return patches


def init_technique(program_name, backend, options):
    return QemuDetection(program_name, backend, **options)
