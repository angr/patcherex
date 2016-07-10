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
import random
import concurrent.futures
import datetime
import cPickle as pickle
from ctypes import cdll
from cStringIO import StringIO
from collections import OrderedDict

from patcherex.techniques.qemudetection import QemuDetection
from patcherex.techniques.shadowstack import ShadowStack
from patcherex.techniques.packer import Packer
from patcherex.techniques.simplecfi import SimpleCFI
from patcherex.techniques.cpuid import CpuId
from patcherex.techniques.randomsyscallloop import RandomSyscallLoop
from patcherex.techniques.stackretencryption import StackRetEncryption
from patcherex.techniques.indirectcfi import IndirectCFI
from patcherex.techniques.transmitprotection import TransmitProtection
from patcherex.techniques.shiftstack import ShiftStack
from patcherex.techniques.adversarial import Adversarial
from patcherex.techniques.backdoor import Backdoor

from patcherex import utils
from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import *


l = logging.getLogger("patcherex.PatchMaster")

class PatchMaster():
    # TODO cfg creation should be here somewhere, so that we can avoid recomputing it everytime
    # having a serious caching system would be even better
    
    def __init__(self,infile):
        self.infile = infile
        # to ease autotesting:
        self.ngenerated_patches = 3

    def generate_shadow_stack_binary(self):
        backend = DetourBackend(self.infile)
        cp = ShadowStack(self.infile,backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        return backend.get_final_content()

    def generate_packed_binary(self):
        backend = DetourBackend(self.infile)
        cp = Packer(self.infile,backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        return backend.get_final_content()

    def generate_simplecfi_binary(self):
        backend = DetourBackend(self.infile)
        cp = SimpleCFI(self.infile,backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        return backend.get_final_content()

    def generate_cpuid_binary(self):
        backend = DetourBackend(self.infile)
        cp = CpuId(self.infile,backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        return backend.get_final_content()

    def generate_qemudetection_binary(self):
        backend = DetourBackend(self.infile)
        cp = QemuDetection(self.infile,backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        return backend.get_final_content()

    def generate_randomsyscallloop_binary(self):
        backend = DetourBackend(self.infile)
        cp = RandomSyscallLoop(self.infile,backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        return backend.get_final_content()

    def generate_stackretencryption_binary(self):
        backend = DetourBackend(self.infile)
        cp = StackRetEncryption(self.infile,backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        return backend.get_final_content()

    def generate_indirectcfi_binary(self):
        backend = DetourBackend(self.infile)
        cp = IndirectCFI(self.infile,backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        return backend.get_final_content()

    def generate_adversarial_binary(self):
        backend = DetourBackend(self.infile)
        cp = Adversarial(self.infile,backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        return backend.get_final_content()

    def generate_backdoor_binary(self):
        backend = DetourBackend(self.infile)
        cp = Backdoor(self.infile,backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        return backend.get_final_content()

    def generate_transmitprotection_binary(self):
        backend = DetourBackend(self.infile)
        cp = TransmitProtection(self.infile,backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        return backend.get_final_content()


    ##################

    def generate_light_binary(self):
        backend = DetourBackend(self.infile)
        cp = IndirectCFI(self.infile,backend)
        patches1 = cp.get_patches()
        cp = TransmitProtection(self.infile,backend)
        patches2 = cp.get_patches()
        cp = ShiftStack(self.infile,backend)
        patches3 = cp.get_patches()

        backend.apply_patches(patches1+patches2+patches3)
        return backend.get_final_content()

    def generate_medium_binary(self):
        backend = DetourBackend(self.infile)
        cp = IndirectCFI(self.infile,backend)
        patches1 = cp.get_patches()
        cp = TransmitProtection(self.infile,backend)
        patches2 = cp.get_patches()
        cp = ShiftStack(self.infile,backend)
        patches3 = cp.get_patches()
        cp = Adversarial(self.infile,backend)
        patches4 = cp.get_patches()
        cp = Backdoor(self.infile,backend)
        patches5 = cp.get_patches()

        backend.apply_patches(patches1+patches2+patches3+patches4+patches5)
        return backend.get_final_content()

    def generate_heavy_binary(self):
        backend = DetourBackend(self.infile)
        cp = IndirectCFI(self.infile,backend)
        patches1 = cp.get_patches()
        cp = TransmitProtection(self.infile,backend)
        patches2 = cp.get_patches()
        cp = ShiftStack(self.infile,backend)
        patches3 = cp.get_patches()
        cp = Adversarial(self.infile,backend)
        patches4 = cp.get_patches()
        cp = Backdoor(self.infile,backend)
        patches5 = cp.get_patches()
        cp = StackRetEncryption(self.infile,backend)
        patches6 = cp.get_patches()

        backend.apply_patches(patches1+patches2+patches3+patches4+patches5+patches6)
        return backend.get_final_content()


    def run(self,return_dict = False):
        #TODO this should implement all the high level logic of patching
        to_be_submitted = {}

        l.info("creating stackretencryption_binary...")
        stackretencryption_binary = None
        try:
            stackretencryption_binary = self.generate_stackretencryption_binary()
        except Exception as e:
            print "ERROR","during generation of stackretencryption_binary"
            traceback.print_exc()
        if stackretencryption_binary != None:
            to_be_submitted["stackretencryption"] = stackretencryption_binary
        l.info("stackretencryption_binary created")

        l.info("creating light_binary...")
        binary = None
        try:
            binary = self.generate_light_binary()
        except Exception as e:
            print "ERROR","during generation of light_binary"
            traceback.print_exc()
        if binary != None:
            to_be_submitted["light"] = binary
        l.info("light_binary created")

        l.info("creating medium_binary...")
        binary = None
        try:
            binary = self.generate_medium_binary()
        except Exception as e:
            print "ERROR","during generation of medium_binary"
            traceback.print_exc()
        if binary != None:
            to_be_submitted["medium"] = binary
        l.info("medium_binary created")

        l.info("creating heavy_binary...")
        binary = None
        try:
            binary = self.generate_heavy_binary()
        except Exception as e:
            print "ERROR","during generation of heavy_binary"
            traceback.print_exc()
        if binary != None:
            to_be_submitted["heavy"] = binary
        l.info("heavy_binary created")

        if return_dict:
            return to_be_submitted
        else:
            return to_be_submitted.values()

def process_killer():
    cdll['libc.so.6'].prctl(1,9)


def shellquote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def exec_cmd(args,cwd=None,shell=False,debug=False,pkill=True):
    #debug = True
    if debug:
        print "EXECUTING:",repr(args),cwd,shell
    pipe = subprocess.PIPE
    preexec_fn = None
    if pkill:
        preexec_fn = process_killer
    p = subprocess.Popen(args,cwd=cwd,shell=shell,stdout=pipe,stderr=pipe,preexec_fn=process_killer)
    std = p.communicate()
    retcode = p.poll()
    res = (std[0],std[1],retcode)
    if debug:
        print "RESULT:",repr(res)
    return res


def worker(inq,outq,filename_with_technique=True,timeout=60*3):
    def delete_if_exists(fname):
        try:
            os.unlink(fname)
        except OSError:
            pass

    process_killer()

    while True:
        input_file,technique,output_dir = inq.get()
        if filename_with_technique:
            output_fname = os.path.join(output_dir,os.path.basename(input_file)+"_"+technique)
        else:
            output_fname = os.path.join(output_dir,os.path.basename(input_file))
        delete_if_exists(output_fname)
        delete_if_exists(output_fname+"_log")
        args = ["timeout","-s","9",str(timeout),os.path.realpath(__file__),"single",input_file,technique,output_fname]
        res = exec_cmd(args)
        with open(output_fname+"_log","wb") as fp:
            fp.write("\n"+"="*50+" STDOUT\n")
            fp.write(res[0])
            fp.write("\n"+"="*50+" STDERR\n")
            fp.write(res[1])
            fp.write("\n"+"="*50+" RETCODE\n")
            fp.write(str(res[2]))
            fp.write("\n")
        if(res[2]!=0 or not os.path.exists(output_fname)):
            outq.put((False,(input_file,technique,output_dir),res))
        else:
            outq.put((True,(input_file,technique,output_dir),res))


def ftodir(f,out):
    dname = os.path.split(os.path.split(f)[-2])[-1]
    res = os.path.join(out,dname)
    #print "-->",out,dname,res
    return res


def ftodir2(f,technique,out):
    sep = os.path.sep
    cb_name, flavour = f.split(sep)[-3:-1]
    res = os.path.join(*[out,flavour,technique,cb_name])
    return res


if __name__ == "__main__":


    if sys.argv[1] == "run":
        logging.getLogger("patcherex.techniques.CpuId").setLevel("INFO")
        logging.getLogger("patcherex.techniques.Packer").setLevel("INFO")
        logging.getLogger("patcherex.techniques.QemuDetection").setLevel("INFO")
        logging.getLogger("patcherex.techniques.SimpleCFI").setLevel("INFO")
        logging.getLogger("patcherex.techniques.ShadowStack").setLevel("INFO")
        logging.getLogger("patcherex.backends.DetourBackend").setLevel("INFO")
        logging.getLogger("patcherex.backends.StackRetEncryption").setLevel("INFO")
        logging.getLogger("patcherex.techniques.IndirectCFI").setLevel("INFO")
        logging.getLogger("patcherex.techniques.TransmitProtection").setLevel("INFO")
        logging.getLogger("patcherex.techniques.ShiftStack").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.Adversarial").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.Backdoor").setLevel("DEBUG")
        logging.getLogger("patcherex.PatchMaster").setLevel("INFO")

        input_fname = sys.argv[2]
        out = os.path.join(sys.argv[3],os.path.basename(input_fname))
        pm = PatchMaster(input_fname)

        res = pm.run(return_dict = True)
        with open(sys.argv[2]) as fp:
            original_content = fp.read()
        res["original"] = original_content
        for k,v in res.iteritems():
            output_fname = out+"_"+k
            fp = open(output_fname,"wb")
            fp.write(v)
            fp.close()
            os.chmod(output_fname, 0755)

    elif sys.argv[1] == "single":
        cdll['libc.so.6'].prctl(1,9)
        print "="*50,"process started at",str(datetime.datetime.now())
        print " ".join(map(shellquote,sys.argv))

        logging.getLogger("patcherex.techniques.CpuId").setLevel("INFO")
        logging.getLogger("patcherex.techniques.Packer").setLevel("INFO")
        logging.getLogger("patcherex.techniques.QemuDetection").setLevel("INFO")
        logging.getLogger("patcherex.techniques.SimpleCFI").setLevel("INFO")
        logging.getLogger("patcherex.techniques.ShadowStack").setLevel("INFO")
        logging.getLogger("patcherex.backends.DetourBackend").setLevel("INFO")
        logging.getLogger("patcherex.backend").setLevel("INFO")
        logging.getLogger("patcherex.techniques.StackRetEncryption").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.IndirectCFI").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.TransmitProtection").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.ShiftStack").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.Adversarial").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.Backdoor").setLevel("DEBUG")
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
        print "="*50,"process ended at",str(datetime.datetime.now())

    elif sys.argv[1] == "multi" or sys.argv[1] == "multi_name" or sys.argv[1] == "multi_name2":
        out = sys.argv[2]
        techniques = sys.argv[3].split(",")
        files = sys.argv[7:]
        technique_in_filename = True

        if sys.argv[1] == "multi_name":
            tasks = []
            for f in files:
                for t in techniques:
                    outdir = ftodir(f,out)
                    try:
                        os.makedirs(outdir)
                    except OSError:
                        pass
                    tasks.append((f,t,outdir))

        elif sys.argv[1] == "multi_name2":
            tasks = []
            technique_in_filename = False
            for f in files:
                for t in techniques:
                    outdir = ftodir2(f,t,out)
                    try:
                        os.makedirs(outdir)
                    except OSError:
                        pass
                    try:
                        os.mkdir(outdir)
                    except OSError:
                        pass
                    tasks.append((f,t,outdir))

        elif sys.argv[1] == "multi":
            tasks = [(f,t,out) for f,t in list(itertools.product(files,techniques))]

        print tasks
        res_dict = {}

        inq = multiprocessing.Queue()
        outq = multiprocessing.Queue()
        plist = []
        nprocesses = int(sys.argv[5])
        if nprocesses == 0:
            nprocesses = int(psutil.cpu_count()*1.0)
        timeout = int(sys.argv[6])
        for i in xrange(nprocesses):
            p = multiprocessing.Process(target=worker, args=(inq,outq,technique_in_filename,timeout))
            p.start()
            plist.append(p)

        ntasks = len(tasks)
        random.shuffle(tasks,lambda : 0.1)
        for t in tasks:
            inq.put(t)
        for i in xrange(ntasks):
            res = outq.get()
            sep = os.path.sep
            key = (sep.join(res[1][0].split(sep)[-3:]),res[1][1])
            status = res[0]
            value = res[2]
            print "=" * 20, str(i+1)+"/"+str(ntasks), key, status
            #print value
            res_dict[key] = res

        for p in plist:
            p.terminate()

        failed_patches = {k:v for k,v in res_dict.iteritems() if v[0] == False}
        print "FAILED PATCHES",str(len(failed_patches))+"/"+str(ntasks)
        for k,v in failed_patches:
            print k,v

        pickle.dump(res_dict,open(sys.argv[4],"wb"))

        #IPython.embed()


'''
./patch_master.py multi /tmp/cgc shadow_stack,packed,simplecfi  /tmp/cgc/res.pickle 0 300 ../../bnaries-private/cgc_qualifier_event/cgc/002ba801_01
unbuffer ./patch_master.py multi  ~/antonio/tmp/cgc1/ shadow_stack,packed,simplecfi   ~/antonio/tmp/cgc1/res.pickle 40 300 ../../binaries-private/cgc_qualifier_event/cgc/002ba801_01 | tee ~/antonio/tmp/cgc1/log.txt
find /home/cgc/antonio/shared/patcher_dataset/bin/original_selected  -type f -executable -print | xargs -P1 ./patch_master.py multi_name /home/cgc/antonio/shared/patcher_dataset/bin/packed/  packed  /home/cgc/antonio/shared/patcher_dataset/bin/packed/res.pickle 40 300
./patch_master.py single ../../binaries-private/cgc_trials/CADET_00003 stackretencryption  ../../vm/shared/patched
find ../../binaries-private/cgc_samples_multiflags/ -type f -executable | grep CADET_00003 | tr '\n' ' ' | xargs -P1  ./patch_master.py multi_name2 /tmp/cgc4 stackretencryption,backdoor,final,adversarial  /tmp/cgc/res.pickle 0 300
'''
