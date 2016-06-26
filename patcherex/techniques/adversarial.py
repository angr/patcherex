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
            ; infinite loop allocating and writing memory
            xor ebp, ebp
            _loop:
                inc ebp
                call _get_eip
                _get_eip:
                pop eax

                test eax, eax
                jz _exit ; never true
                xor eax, eax
                mov al, 5
                mov ebx, 0x1000
                xor ecx, ecx
                inc ecx
                mov edx, {tmp1}
                int 0x80
                cmp al, 4 ;ENOMEM
                je _loop
                mov esi, DWORD [{tmp1}]
                mov edi, esi
                _inner_loop:
                    mov DWORD [esi], ebp
                    add esi, 4
                    cmp esi, edi
                    je _exit2
                    jmp _inner_loop
                _exit2:
                jmp _loop
            _exit:
        '''
        patches.append(AddCodePatch(fail_code,"evil_fail"))

        code = '''
        ; 1) transmit flag page to stderr
        ;  - check if it fails (it should not even if we try to send two pages)
        ;  - confuse dynamic detection of type2
        ; int transmit(int fd, const void *buf, size_t count, size_t *tx_bytes) [2]
        mov ecx,  0x4347c000
        mov edx, 0x10000
        mov esi {tmp1}
        xor eax, eax
        mov al, 0x2
        xor ebx, ebx
        mov bl, 0x2 ;stderr!
        int 0x80
        test eax, eax
        je _e1
        call {evil_fail}
        _e1:
        cmp [{tmp1}], 0
        jg _e2
        call {evil_fail}
        _e2:
        ; ...
        '''
        patches.append(AddCodePatch(fail_code,"evil_fail"))


        return patches
