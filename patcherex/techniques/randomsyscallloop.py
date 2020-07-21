import patcherex

import logging
from patcherex.patches import *

l = logging.getLogger("patcherex.techniques.CpudId")

class RandomSyscallLoop(object):

    def __init__(self,binary_fname,backend):
        self.binary_fname = binary_fname
        self.patcher = backend

    def get_patches(self):
        patches = []
        added_code = '''
            xor edi, edi
            _loop_rs:
            cmp edi, 1000000
            je _exit_rs
            inc edi
            ;int random(void *buf, size_t count, size_t *rnd_bytes) [7]
            mov eax, 0x7
            mov ebx, {space}
            mov ecx, 0x10
            mov edx, {random_result}
            int 0x80
            jmp _loop_rs
            _exit_rs:
            ;
        '''
        patches.append(AddEntryPointPatch(added_code,name="random_loop"))
        patches.append(AddRWDataPatch(len("XXXXXXXXXXXXXXXXXXXX"),name="space"))
        patches.append(AddRWDataPatch(len("XXXX"),name="random_result"))

        return patches

def init_technique(program_name, backend, options):
    return RandomSyscallLoop(program_name, backend, **options)
