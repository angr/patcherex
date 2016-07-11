import patcherex
import angr

import patcherex.utils as utils
import patcherex.cfg_utils as cfg_utils

import capstone
import logging
from patcherex.patches import *

l = logging.getLogger("patcherex.techniques.Bitflip")


class Bitflip(object):

    def __init__(self,binary_fname,backend):
        self.binary_fname = binary_fname
        self.patcher = backend


    def get_patches(self):
        patches = []
        cfg = self.patcher.cfg

        receive_wrapper = [ff for ff in cfg.functions.values() if \
                cfg_utils.detect_syscall_wrapper(self.patcher,ff) == 3] 
        if len(receive_wrapper) != 1:
            l.warning("Found %d receive_wrapper... better not to touch anything"%len(receive_wrapper))
            return []
        receive_wrapper = receive_wrapper[0]
        #import IPython; IPython.embed()
        # here we assume that receive_wrapper is a "sane" syscall wrapper, as checked by detect_syscall_wrapper
        last_block = [b for b in receive_wrapper.blocks if b.addr != receive_wrapper.addr][0]
        victim_addr = int(last_block.addr)


        # free registers esi, edx, ecx, ebx are free because we are in a syscall wrapper restoring them

        patches.extend(self.compute_patches(victim_addr))

        return patches
