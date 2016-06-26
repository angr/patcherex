import patcherex
import angr
import struct

import patcherex.utils as utils
import patcherex.cfg_utils as cfg_utils

import capstone
import logging
from patcherex.patches import *

l = logging.getLogger("patcherex.techniques.Adversarial")


class Adversarial(object):

    def __init__(self,binary_fname,backend):
        self.binary_fname = binary_fname
        self.patcher = backend

    def get_patches(self):
        patches = []
        patches.append(AddRWData(4,"computed_value")) #this will accumulate the result of different checks
        patches.append(AddRWData(4,"tmp1"))

        # destroy section header pointers
        patches.append(RawFilePatch(0x20,struct.pack("<I",0xfffffefe)))
        patches.append(RawFilePatch(0x30,struct.pack("<H",0xfefe)))
        patches.append(RawFilePatch(0x30,struct.pack("<H",0xffff)))
        fail_code = '''
        
        '''
        patches.append(AddCodePatch())

        code = '''
        ; 1) transmit flag page to stderr
        ;  - check if it fails (it should not even if we try to send two pages)
        ;  - confuse dynamic detection of type2
        ; int transmit(int fd, const void *buf, size_t count, size_t *tx_bytes) [2]
        xor eax, eax
        mov al, 0x2
        xor ebx, ebx
        mov bl, 0x2 ;stderr!
        ; it seems that at least one page must exist
        mov ecx,  0x4347c000 ;two pages before the end of the stack + 1
        mov edx, 0x10000
        mov esi {tmp1}
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

        return patches
