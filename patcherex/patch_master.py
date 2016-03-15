#!/usr/bin/env python

import logging
import utils

from canary_patcher import CanaryPatcher

class PatchMaster():
    
    def __init__(self,infile):
        self.infile = infile

    def run(self):
        #TODO this should implement all the high level logic of patching

        original_binary = open(self.infile).read()

        #I modify one byte in ci_pad[7]. It is never used or checked, according to:
        #https://github.com/CyberGrandChallenge/linux-source-3.13.11-ckt21-cgc/blob/541cc214fb6eb6994414fb09414f945115ddae81/fs/binfmt_cgc.c
        one_byte_patch_binary = utils.str_overwrite(original_binary,"S",14)
        #print repr(one_byte_patch_binary[:32])

        cp = CanaryPatcher(self.infile)
        shadow_stack_binary = cp.apply_to_entire_bin()


        #TODO also add 1 byte patch
        return [original_binary,one_byte_patch_binary,shadow_stack_binary]


if __name__ == "__main__":
    import sys
    import os
    import IPython
    #IPython.embed()
    logging.getLogger("patcherex.CanaryPatcher").setLevel("DEBUG")
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
python ./canary_patcher.py ../../binaries-private/cgc_scored_event_2/cgc/0b32aa01_01 /tmp/t/p1 && ../../tracer/bin/tracer-qemu-cgc /tmp/t/p1
'''
