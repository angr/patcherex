import patcherex

import logging
import struct
from patcherex.patches import *
from patcherex.backends.basebackend import BaseBackend

l = logging.getLogger("patcherex.techniques.QemuDetection")

class QemuDetection(object):

    def __init__(self,binary_fname):
        self.binary_fname = binary_fname
        self.patcher = BaseBackend(self.binary_fname)

    def get_patches(self):
        patches = []
        added_code = '''
            ; int allocate(size_t length, int is_X, void **addr) [5]
            mov eax, 0x5
            mov ebx, 0x1000
            xor ecx, ecx
            mov edx, {allocate_result}
            int 0x80

            mov ecx, DWORD [{allocate_result}]
            mov DWORD [ecx], 0x55544d51

            ;int transmit(int fd, const void *buf, size_t count, size_t *tx_bytes) [2]
            mov eax, 0x2
            mov ebx, 0x1
            mov edx, 0x10000
            mov esi, {tmp1}
            int 0x80

            call {print_hex_eax}
        '''
        patches.append(AddEntryPointPatch(added_code,name="detect_qemu"))

        added_code = '''
            ; print eax as hex
            pusha
            mov ecx,32
            mov ebx,eax
            _print_reg_loop:
                rol ebx,4
                mov edi,ebx
                and edi,0x0000000f
                lea eax,[{hex_array}+edi]
                mov ebp,ebx
                mov ebx,0x1
                call {print}
                mov ebx,ebp
                sub ecx,4
                jnz _print_reg_loop
            popa
            ret
        '''
        patches.append(AddCodePatch(added_code,name="print_hex_eax"))
        added_code = '''
            ; eax=buf,ebx=len
            pusha
            mov ecx,eax
            mov edx,ebx
            mov eax,0x2
            mov ebx,0x1
            mov esi,0x0
            int 0x80
            popa
            ret
        '''
        patches.append(AddCodePatch(added_code,name="print"))
        patches.append(AddDataPatch("0123456789abcdef",name="hex_array"))
        patches.append(AddDataPatch("XXXX",name="tmp1"))
        patches.append(AddDataPatch("XXXX",name="allocate_result"))

        return patches


