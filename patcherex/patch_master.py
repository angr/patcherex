#!/usr/bin/env python

import logging
import utils
import traceback
import timeout_decorator
from collections import OrderedDict

from patcherex.techniques.shadowstack import ShadowStack
from patcherex.backends.basebackend import BaseBackend
from patcherex.patches import *


class PatchMaster():
    
    def __init__(self,infile):
        self.infile = infile


    @timeout_decorator.timeout(60*4)
    def generate_shadow_stack_binary(self):
        backend = BaseBackend(self.infile)
        cp = ShadowStack(self.infile)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        return backend.get_final_content()


    def generate_one_byte_patch(self):
        backend = BaseBackend(self.infile)
        #I modify one byte in ci_pad[7]. It is never used or checked, according to:
        #https://github.com/CyberGrandChallenge/linux-source-3.13.11-ckt21-cgc/blob/541cc214fb6eb6994414fb09414f945115ddae81/fs/binfmt_cgc.c
        one_byte_patch = RawFilePatch(14,"S")
        backend.apply_patches([one_byte_patch])
        return backend.get_final_content()


    def run(self,return_dict = False):
        #TODO this should implement all the high level logic of patching

        to_be_submitted = OrderedDict()
        original_binary = open(self.infile).read()
        to_be_submitted["original"] = original_binary

        one_byte_patch_binary = self.generate_one_byte_patch()
        to_be_submitted["1bytepatch"] = one_byte_patch_binary

        shadow_stack_binary = None
        try:
            shadow_stack_binary = self.generate_shadow_stack_binary()
        except Exception as e:
            print "ERROR","during generation of shadow stack binary, just returning the other patches"
            traceback.print_exc()
        if shadow_stack_binary != None:
            to_be_submitted["shadowstack"] = shadow_stack_binary

        if return_dict:
            return to_be_submitted
        else:
            return to_be_submitted.values()


if __name__ == "__main__":
    import sys
    import os
    import IPython
    #IPython.embed()
    logging.getLogger("patcherex.techniques.ShadowStack").setLevel("INFO")
    logging.getLogger("patcherex.backends.BaseBackend").setLevel("INFO")


    input_fname = sys.argv[1]
    out = sys.argv[2]
    pm = PatchMaster(input_fname)
    res = pm.run(return_dict = True)
    for k,v in res.iteritems():
        output_fname = out+"_"+k
        fp = open(output_fname,"wb")
        fp.write(v)
        fp.close()
        os.chmod(output_fname, 0755)


'''
`'''
