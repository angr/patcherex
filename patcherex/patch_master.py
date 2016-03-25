#!/usr/bin/env python

import logging
import utils
import traceback
import timeout_decorator

from patches import *
from techniques.shadowstack import ShadowStack
from patcherex import Patcherex

class PatchMaster():
    
    def __init__(self,infile):
        self.infile = infile


    @timeout_decorator.timeout(60*4)
    def generate_shadow_stack_binary(self):
        backend = Patcherex(self.infile)
        cp = ShadowStack(self.infile)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        return backend.get_final_content()


    def generate_one_byte_patch(self):
        backend = Patcherex(self.infile)
        #I modify one byte in ci_pad[7]. It is never used or checked, according to:
        #https://github.com/CyberGrandChallenge/linux-source-3.13.11-ckt21-cgc/blob/541cc214fb6eb6994414fb09414f945115ddae81/fs/binfmt_cgc.c
        one_byte_patch = RawFilePatch(14,"S")
        backend.apply_patches([one_byte_patch])
        return backend.get_final_content()


    def run(self):
        #TODO this should implement all the high level logic of patching

        to_be_submitted = []
        original_binary = open(self.infile).read()
        to_be_submitted.append(original_binary)

        one_byte_patch_binary = self.generate_one_byte_patch()
        to_be_submitted.append(one_byte_patch_binary)

        shadow_stack_binary = None
        try:
            shadow_stack_binary = self.generate_shadow_stack_binary()
        except Exception as e:
            print "ERROR","during generation of shadow stack binary, just returning the other patches"
            traceback.print_exc()
        if shadow_stack_binary != None:
            to_be_submitted.append(shadow_stack_binary)

        return to_be_submitted


if __name__ == "__main__":
    import sys
    import os
    import IPython
    #IPython.embed()
    logging.getLogger("patcherex.ShadowStack").setLevel("INFO")
    logging.getLogger("patcherex.Patcherex").setLevel("INFO")


    input_fname = sys.argv[1]
    out = sys.argv[2]
    pm = PatchMaster(input_fname)
    res = pm.run()
    for i,b in enumerate(res):
        output_fname = out+"_"+str(i)
        fp = open(output_fname,"wb")
        fp.write(b)
        fp.close()
        os.chmod(output_fname, 0755)


'''
./patch_master.py ../../binaries-private/cgc_scored_event_2/cgc/0b32aa01_01 /tmp/ppp && ../../tracer/bin/tracer-qemu-cgc /tmp/ppp_2
'''
