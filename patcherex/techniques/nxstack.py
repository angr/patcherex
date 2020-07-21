import patcherex

import logging
import struct
import patcherex.cfg_utils as cfg_utils
from patcherex.patches import *

l = logging.getLogger("patcherex.techniques.NxStack")

class NxStack(object):

    def __init__(self,binary_fname,backend):
        self.binary_fname = binary_fname
        self.patcher = backend

    def get_patches(self):
        cfg = self.patcher.cfg
        for k,ff in cfg.functions.items():

            if ff.is_syscall or ff.is_simprocedure:
                # don't patch syscalls or SimProcedures
                continue

            if not ff.is_syscall and ff.startpoint != None and ff.endpoints != None and \
                    cfg_utils.detect_syscall_wrapper(self.patcher,ff) == None and \
                    not cfg_utils.is_floatingpoint_function(self.patcher,ff):
                call_sites = ff.get_call_sites()
                for cs in call_sites:
                    nn = ff.get_node(cs)
                    # max stack size is 8MB
                    if any([0xba2aa000 <=  n.addr < 0xbaaab000 for n in nn.successors()]):
                        l.warning("found call to stack at %#8x, avoiding nx" % nn.addr)
                        return []

            for block in ff.blocks:
                for s in block.vex.statements:
                    if any([0xba2aa000 <= v.value <= 0xbaaab000 for v in s.constants]):
                        l.warning("found constant that looks stack-related at %#8x, avoiding nx" % block.addr)
                        return []

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

def init_technique(program_name, backend, options):
    return NxStack(program_name, backend, **options)
