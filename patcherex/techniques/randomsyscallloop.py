import patcherex

import logging
from patcherex.patches import *
from patcherex.backends.basebackend import BaseBackend

l = logging.getLogger("patcherex.techniques.CpudId")

class RandomSyscallLoop(object):

    def __init__(self,binary_fname):
        self.binary_fname = binary_fname
        self.patcher = BaseBackend(self.binary_fname)

    def get_patches(self):
        patches = []
        added_code = '''
            xor edi, edi
            _loop:
            cmp edi, 1000000
            je _exit
            inc edi
            ;int random(void *buf, size_t count, size_t *rnd_bytes) [7]
            mov eax, 0x7
            mov ebx, {space}
            mov ecx, 0x10
            mov edx, {random_result}
            int 0x80
            jmp _loop
            _exit:
            ;
        '''
        patches.append(AddEntryPointPatch(added_code,name="random_loop"))
        patches.append(AddDataPatch("XXXXXXXXXXXXXXXXXXXX",name="space"))
        patches.append(AddDataPatch("XXXX",name="random_result"))

        return patches


