import patcherex

import logging
import struct
from patcherex.patches import *

l = logging.getLogger("patcherex.techniques.NxStack")

class NxStack(object):

    def __init__(self,binary_fname,backend):
        self.binary_fname = binary_fname
        self.patcher = backend

    def get_patches(self):
        # TODO nx stack should be only used if static analysis tells us that no code is executed on the stack
        # see issue: https://git.seclab.cs.ucsb.edu/cgc/patcherex/issues/14
        patches = []
        nxsegment_after_stack =(0x1, 0x0, 0xbaaab000, 0xbaaab000, 0x0, 0x1000, 0x6, 0x1000)
        patches.append(AddSegmentHeaderPatch(nxsegment_after_stack, name="nxstack_segment_header"))
        added_code = '''
            ; int 3
            ; this can be placed before or after the stack shift
            add esp, 0x1000
            ; restore flags, assume eax=0 since we are after restore
            push 0x202
            popf
            mov DWORD [esp-4], eax
        '''
        patches.append(AddEntryPointPatch(added_code, name="move_stack_to_nx", after_restore=True))

        return patches


