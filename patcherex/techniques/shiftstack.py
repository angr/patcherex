import patcherex

import logging
import struct
from patcherex.patches import *

l = logging.getLogger("patcherex.techniques.ShiftStack")

class ShiftStack(object):

    def __init__(self,binary_fname,backend):
        self.binary_fname = binary_fname
        self.patcher = backend
        self.min_value_pow = 4
        self.max_value_pow = 10

    def get_patches(self):
        patches = []
        patches.append(AddRWDataPatch(4, name="rnd_shiftstack"))
        added_code = '''
            mov ebx, {rnd_shiftstack}
            xor ecx, ecx
            mov cl, 4
            xor edx, edx
            xor eax, eax
            mov al, 7
            int 0x80
            or DWORD [ebx],1
            shl DWORD [ebx], %d
            and DWORD [ebx], %d
        ''' % (self.min_value_pow, ((1 << self.max_value_pow) -1))
        patches.append(AddEntryPointPatch(added_code, name="rnd_shiftstack_setup"))
        added_code = '''
            sub esp, DWORD [{rnd_shiftstack}]
            ; restore flags, assume eax=0 since we are after restore
            push 0x202
            popf
            mov DWORD [esp-4], eax
        '''
        patches.append(AddEntryPointPatch(added_code, name="rnd_shiftstack_do", after_restore=True))

        return patches

def init_technique(program_name, backend, options):
    return ShiftStack(program_name, backend, **options)
