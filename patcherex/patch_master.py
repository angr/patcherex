#!/usr/bin/env python

import sys
import os
import logging
import utils
import traceback
import timeout_decorator
import itertools
import psutil
import multiprocessing
import subprocess
import concurrent.futures
from ctypes import cdll
from cStringIO import StringIO
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

    def generate_shadow_stack_binary(self):
        backend = BaseBackend(self.infile)
        cp = ShadowStack(self.infile)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        return backend.get_final_content()

    def generate_packed_binary(self):
        backend = BaseBackend(self.infile)
        cp = Packer(self.infile)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        return backend.get_final_content()

    def generate_simplecfi_binary(self):
        backend = BaseBackend(self.infile)
        cp = SimpleCFI(self.infile)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        return backend.get_final_content()

    def generate_cpuid_binary(self):
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

    def generate_qemudetection_binary(self):
        backend = BaseBackend(self.infile)
        cp = QemuDetection(self.infile)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        return backend.get_final_content()

    def generate_randomsyscallloop_binary(self):
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
            packed_binary = self.generate_packed_binary()
        except Exception as e:
            print "ERROR","during generation of packed binary"
            traceback.print_exc()
        if packed_binary != None:
            to_be_submitted["packed"] = packed_binary
        l.info("packed binary created")

        l.info("creating simplecfi binary...")
        simplecfi_binary = None
        try:
            simplecfi_binary = self.generate_simplecfi_binary()
        except Exception as e:
            print "ERROR","during generation of packed binary"
            traceback.print_exc()
        if simplecfi_binary != None:
            to_be_submitted["simplecfi"] = simplecfi_binary
        l.info("simplecfi binary created")

        l.info("creating qemudetection binary...")
        qemudetection_binary = None
        try:
            qemudetection_binary = self.generate_qemudetection_binary()
        except Exception as e:
            print "ERROR","during generation of packed binary"
            traceback.print_exc()
        if qemudetection_binary != None:
            to_be_submitted["qemudetection"] = qemudetection_binary
        l.info("qemudetection_binary binary created")

        l.info("creating cpuid binary...")
        cpuid_binary = None
        try:
            cpuid_binary = self.generate_cpuid_binary()
        except Exception as e:
            print "ERROR","during generation of cpuid binary"
            traceback.print_exc()
        if cpuid_binary != None:
            to_be_submitted["cpuid"] = cpuid_binary
        l.info("cpuid_binary binary created")

        l.info("creating randomsyscallloop binary...")
        randomsyscallloop_binary = None
        try:
            randomsyscallloop_binary = self.generate_randomsyscallloop_binary()
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

def exec_cmd(args,cwd=None,shell=False,debug=False):
    #debug = True
    if debug:
        print "EXECUTING:",repr(args),cwd,shell
    pipe = subprocess.PIPE
    p = subprocess.Popen(args,cwd=cwd,shell=shell,stdout=pipe,stderr=pipe)
    std = p.communicate()
    retcode = p.poll()
    res = (std[0],std[1],retcode)
    if debug:
        print "RESULT:",repr(res)
    return res


def worker(inq,outq):
    def delete_if_exists(fname):
        try:
            os.unlink(fname)
        except OSError:
            pass

    cdll['libc.so.6'].prctl(1,9)

    while True:
        input_file,technique,output_dir = inq.get()
        output_fname = os.path.join(output_dir,os.path.basename(input_file)+"_"+technique)
        delete_if_exists(output_fname)
        delete_if_exists(output_fname+"_log")
        args = ["timeout","-s","9",str(int(60*2)),os.path.realpath(__file__),"single",input_file,technique,output_fname]
        res = exec_cmd(args)
        with open(output_fname+"_log","wb") as fp:
            fp.write("\n"+"="*50+" STDOUT\n")
            fp.write(res[0])
            fp.write("\n"+"="*50+" STDERR\n")
            fp.write(res[1])
            fp.write("\n"+"="*50+" RETCODE\n")
            fp.write(str(res[2]))
        if(res[2]!=0 or not os.path.exists(output_fname)):
            outq.put((False,(input_file,technique,output_dir),res))
        else:
            outq.put((True,(input_file,technique,output_dir),res))


if __name__ == "__main__":
    import IPython
    #IPython.embed()

    if sys.argv[1] == "allpatches":
        logging.getLogger("patcherex.techniques.CpuId").setLevel("INFO")
        logging.getLogger("patcherex.techniques.Packer").setLevel("INFO")
        logging.getLogger("patcherex.techniques.QemuDetection").setLevel("INFO")
        logging.getLogger("patcherex.techniques.SimpleCFI").setLevel("INFO")
        logging.getLogger("patcherex.techniques.ShadowStack").setLevel("INFO")
        logging.getLogger("patcherex.backends.BaseBackend").setLevel("INFO")
        logging.getLogger("patcherex.PatchMaster").setLevel("INFO")

        input_fname = sys.argv[2]
        out = sys.argv[3]
        pm = PatchMaster(input_fname)
        res = pm.run(return_dict = True)
        for k,v in res.iteritems():
            output_fname = out+"_"+k
            fp = open(output_fname,"wb")
            fp.write(v)
            fp.close()
            os.chmod(output_fname, 0755)

    elif sys.argv[1] == "single":
        logging.getLogger("patcherex.techniques.CpuId").setLevel("INFO")
        logging.getLogger("patcherex.techniques.Packer").setLevel("INFO")
        logging.getLogger("patcherex.techniques.QemuDetection").setLevel("INFO")
        logging.getLogger("patcherex.techniques.SimpleCFI").setLevel("INFO")
        logging.getLogger("patcherex.techniques.ShadowStack").setLevel("INFO")
        logging.getLogger("patcherex.backends.BaseBackend").setLevel("INFO")
        logging.getLogger("patcherex.PatchMaster").setLevel("INFO")

        input_fname = sys.argv[2]
        technique = sys.argv[3]
        output_fname = sys.argv[4]
        pm = PatchMaster(input_fname)
        m = getattr(pm,"generate_"+technique+"_binary")
        res = m()
        fp = open(output_fname,"wb")
        fp.write(res)
        fp.close()
        os.chmod(output_fname, 0755)


    elif sys.argv[1] == "multi":
        out = sys.argv[2]
        techniques = sys.argv[3].split(",")
        files = sys.argv[4:]

        tasks = [(f,t,out) for f,t in list(itertools.product(files,techniques))]
        print tasks
        res_dict = {}

        inq = multiprocessing.Queue()
        outq = multiprocessing.Queue()
        plist = []
        nprocesses = int(psutil.cpu_count()/2.0)
        for i in xrange(nprocesses):
            p = multiprocessing.Process(target=worker, args=(inq,outq))
            p.start()
            plist.append(p)

        ntasks = len(tasks)
        for t in tasks:
            inq.put(t)
        for i in xrange(ntasks):
            res = outq.get()
            key = (os.path.basename(res[1][0]),res[1][1])
            status = res[0]
            value = res[2]
            print "=" * 20, str(i+1)+"/"+str(ntasks), key, status
            #print value
            res_dict[key] = value

        for p in plist:
            p.terminate()

        #print repr(res_dict)



'''
'''
