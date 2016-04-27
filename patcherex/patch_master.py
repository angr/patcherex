#!/usr/bin/env python

import logging
import utils
import traceback
import timeout_decorator
from collections import OrderedDict

from patcherex.techniques.qemudetection import QemuDetection
from patcherex.techniques.shadowstack import ShadowStack
from patcherex.techniques.packer import Packer
from patcherex.techniques.simplecfi import SimpleCFI
from patcherex.techniques.cpuid import CpuId
from patcherex.techniques.randomsyscallloop import RandomSyscallLoop

from patcherex import utils
from patcherex.backends.basebackend import BaseBackend
from patcherex.patches import *


l = logging.getLogger("patcherex.PatchMaster")

class PatchMaster():
    # TODO cfg creation should be here somewhere, so that we can avoid recomputing it everytime
    # having a serious caching system would be even better
    
    def __init__(self,infile):
        self.infile = infile

    @timeout_decorator.timeout(60*2)
    def generate_shadow_stack_binary(self):
        backend = BaseBackend(self.infile)
        cp = ShadowStack(self.infile)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        return backend.get_final_content()

    @timeout_decorator.timeout(60*2)
    def generated_packed_binary(self):
        backend = BaseBackend(self.infile)
        cp = Packer(self.infile)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        return backend.get_final_content()

    @timeout_decorator.timeout(60*2)
    def generated_simplecfi_binary(self):
        backend = BaseBackend(self.infile)
        cp = SimpleCFI(self.infile)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        return backend.get_final_content()

    @timeout_decorator.timeout(60*2)
    def generated_cpuid_binary(self):
        backend = BaseBackend(self.infile)
        cp = CpuId(self.infile)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        #return utils.str_overwrite(backend.get_final_content(),"ELF",1)
        return backend.get_final_content()

    def generate_one_byte_patch(self):
        backend = BaseBackend(self.infile)
        #I modify one byte in ci_pad[7]. It is never used or checked, according to:
        #https://github.com/CyberGrandChallenge/linux-source-3.13.11-ckt21-cgc/blob/541cc214fb6eb6994414fb09414f945115ddae81/fs/binfmt_cgc.c
        one_byte_patch = RawFilePatch(14,"S")
        backend.apply_patches([one_byte_patch])
        return backend.get_final_content()

    @timeout_decorator.timeout(60*2)
    def generated_qemudetection_binary(self):
        backend = BaseBackend(self.infile)
        cp = QemuDetection(self.infile)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        return backend.get_final_content()

    @timeout_decorator.timeout(60*2)
    def generated_randomsyscallloop_binary(self):
        backend = BaseBackend(self.infile)
        cp = RandomSyscallLoop(self.infile)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        return backend.get_final_content()

    def run(self,return_dict = False):
        #TODO this should implement all the high level logic of patching

        l.info("creating original binary...")
        to_be_submitted = OrderedDict()
        original_binary = open(self.infile).read()
        to_be_submitted["original"] = original_binary
        l.info("original binary created")

        l.info("creating 1byte binary...")
        one_byte_patch_binary = self.generate_one_byte_patch()
        to_be_submitted["1bytepatch"] = one_byte_patch_binary
        l.info("1byte binary created")

        l.info("creating shadowstack binary...")
        shadow_stack_binary = None
        try:
            shadow_stack_binary = self.generate_shadow_stack_binary()
        except Exception as e:
            print "ERROR","during generation of shadow stack binary"
            traceback.print_exc()
        if shadow_stack_binary != None:
            to_be_submitted["shadowstack"] = shadow_stack_binary
        l.info("shadowstack binary created")

        l.info("creating packed binary...")
        packed_binary = None
        try:
            packed_binary = self.generated_packed_binary()
        except Exception as e:
            print "ERROR","during generation of packed binary"
            traceback.print_exc()
        if packed_binary != None:
            to_be_submitted["packed"] = packed_binary
        l.info("packed binary created")

        l.info("creating simplecfi binary...")
        simplecfi_binary = None
        try:
            simplecfi_binary = self.generated_simplecfi_binary()
        except Exception as e:
            print "ERROR","during generation of packed binary"
            traceback.print_exc()
        if simplecfi_binary != None:
            to_be_submitted["simplecfi"] = simplecfi_binary
        l.info("simplecfi binary created")

        l.info("creating qemudetection binary...")
        qemudetection_binary = None
        try:
            qemudetection_binary = self.generated_qemudetection_binary()
        except Exception as e:
            print "ERROR","during generation of packed binary"
            traceback.print_exc()
        if qemudetection_binary != None:
            to_be_submitted["qemudetection"] = qemudetection_binary
        l.info("qemudetection_binary binary created")

        l.info("creating cpuid binary...")
        cpuid_binary = None
        try:
            cpuid_binary = self.generated_cpuid_binary()
        except Exception as e:
            print "ERROR","during generation of cpuid binary"
            traceback.print_exc()
        if cpuid_binary != None:
            to_be_submitted["cpuid"] = cpuid_binary
        l.info("cpuid_binary binary created")

        l.info("creating randomsyscallloop binary...")
        randomsyscallloop_binary = None
        try:
            randomsyscallloop_binary = self.generated_randomsyscallloop_binary()
        except Exception as e:
            print "ERROR","during generation of randomsyscallloop binary"
            traceback.print_exc()
        if randomsyscallloop_binary != None:
            to_be_submitted["randomsyscallloop"] = randomsyscallloop_binary
        l.info("randomsyscallloop_binary binary created")


        if return_dict:
            return to_be_submitted
        else:
            return to_be_submitted.values()


if __name__ == "__main__":
    import sys
    import os
    import IPython
    #IPython.embed()

    logging.getLogger("patcherex.techniques.CpuId").setLevel("INFO")
    logging.getLogger("patcherex.techniques.Packer").setLevel("INFO")
    logging.getLogger("patcherex.techniques.QemuDetection").setLevel("INFO")
    logging.getLogger("patcherex.techniques.SimpleCFI").setLevel("INFO")
    logging.getLogger("patcherex.techniques.ShadowStack").setLevel("INFO")
    logging.getLogger("patcherex.backends.BaseBackend").setLevel("INFO")
    logging.getLogger("patcherex.PatchMaster").setLevel("INFO")

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
rm ../../vm/shared/pm/CADET_*; ./patch_master.py ../../binaries-private/cgc_trials/CADET_00003 ../../vm/shared/pm/CADET_00003
'''
