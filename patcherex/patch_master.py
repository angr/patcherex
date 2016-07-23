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
import tempfile
import termcolor
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
from patcherex.techniques.nxstack import NxStack
from patcherex.techniques.adversarial import Adversarial
from patcherex.techniques.backdoor import Backdoor
from patcherex.techniques.bitflip import Bitflip
from patcherex.techniques.fidgetpatches import fidget_it
from patcherex.techniques.uninitialized_patcher import UninitializedPatcher
from patcherex.techniques.malloc_ext_patcher import MallocExtPatcher


from patcherex import utils
from patcherex.backends.detourbackend import DetourBackend
from patcherex.backends.reassembler_backend import ReassemblerBackend
from patcherex.patches import *
from networkrules import NetworkRules


l = logging.getLogger("patcherex.PatchMaster")

TEST_RESULTS = False


def test_bin(original,patched,bitflip=False):
    import shellphish_qemu
    qemu_location = shellphish_qemu.qemu_path('cgc-tracer')
    timeout = 15
    inputs = ["","B","\n","\x00","B\n \x00"*50]
    pipe = subprocess.PIPE

    main_args = ["timeout","-s","9",str(timeout),qemu_location]

    for tinput in inputs:
        p = subprocess.Popen(main_args + [original], stdin=pipe, stdout=pipe, stderr=pipe)
        stdout,_ = p.communicate(tinput)
        original_res = (stdout,p.returncode)
        if bitflip:
            used_args = main_args + ["-bitflip"]
        else:
            used_args = main_args
        p = subprocess.Popen(used_args + [patched], stdin=pipe, stdout=pipe, stderr=pipe)
        stdout,_ = p.communicate(tinput)
        patched_res = (stdout,p.returncode)
        assert original_res == patched_res, "unexpected output in %s using %s:\n%s\nvs\n%s" % \
                (patched,repr(tinput),original_res,patched_res)
    print "tested using qemu"
    return


class PatchMaster():

    def __init__(self,infile):
        self.infile = infile

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
    
    def generate_nxstack_binary(self):
        backend = DetourBackend(self.infile)
        cp = NxStack(self.infile,backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        return backend.get_final_content()

    def generate_bitflip_binary(self):
        nr = NetworkRules()
        backend = DetourBackend(self.infile)
        cp = Bitflip(self.infile,backend)
        patches1 = cp.get_patches()

        backend.apply_patches(patches1)
        return (backend.get_final_content(),nr.get_bitflip_rule())

    def generate_fidget_bitflip_binary(self):
        nr = NetworkRules()
        midfile = self.infile + '.fidget' + str(random.randrange(0,1000))
        fidget_it(self.infile, midfile)
        backend = DetourBackend(midfile)
        cp = Bitflip(midfile,backend)
        patches1 = cp.get_patches()

        backend.apply_patches(patches1)
        return (backend.get_final_content(),nr.get_bitflip_rule())


    ##################

    def generate_voidbitflip_binary(self):
        nr = NetworkRules()
        fp = open(self.infile)
        content = fp.read()
        fp.close()
        return (content,nr.get_partialbitflip_null_rule())

    def generate_medium_detour_flip_binary(self):
        nr = NetworkRules()
        backend = DetourBackend(self.infile)
        patches = []

        patches.extend(IndirectCFI(self.infile,backend).get_patches())
        patches.extend(TransmitProtection(self.infile,backend).get_patches())
        patches.extend(ShiftStack(self.infile,backend).get_patches())
        patches.extend(Adversarial(self.infile,backend).get_patches())
        patches.extend(Backdoor(self.infile,backend,enable_bitflip=True).get_patches())
        patches.extend(NxStack(self.infile,backend).get_patches())
        patches.extend(MallocExtPatcher(self.infile,backend).get_patches())
        patches.extend(StackRetEncryption(self.infile,backend).get_patches())
        patches.extend(UninitializedPatcher(self.infile,backend).get_patches())

        backend.apply_patches(patches)
        return (backend.get_final_content(),nr.get_partialbitflip_real_rule())

    def generate_medium_reassembler_flip_binary(self):
        nr = NetworkRules()
        backend = ReassemblerBackend(self.infile)
        patches = []

        patches.extend(IndirectCFI(self.infile,backend).get_patches())
        patches.extend(TransmitProtection(self.infile,backend).get_patches())
        patches.extend(ShiftStack(self.infile,backend).get_patches())
        patches.extend(Adversarial(self.infile,backend).get_patches())
        patches.extend(Backdoor(self.infile,backend,enable_bitflip=True).get_patches())
        patches.extend(NxStack(self.infile,backend).get_patches())
        patches.extend(MallocExtPatcher(self.infile,backend).get_patches())
        patches.extend(StackRetEncryption(self.infile,backend).get_patches())
        patches.extend(UninitializedPatcher(self.infile,backend).get_patches())

        backend.apply_patches(patches)
        return (backend.get_final_content(),nr.get_partialbitflip_real_rule())

    def generate_medium_detour_flip_fidget_binary(self):
        tmp_file = tempfile.mktemp()
        fidget_it(self.infile, tmp_file)

        nr = NetworkRules()
        backend = DetourBackend(tmp_file)
        patches = []

        patches.extend(IndirectCFI(tmp_file,backend).get_patches())
        patches.extend(TransmitProtection(tmp_file,backend).get_patches())
        patches.extend(ShiftStack(tmp_file,backend).get_patches())
        patches.extend(Adversarial(tmp_file,backend).get_patches())
        patches.extend(Backdoor(tmp_file,backend,enable_bitflip=True).get_patches())
        patches.extend(NxStack(tmp_file,backend).get_patches())
        patches.extend(MallocExtPatcher(tmp_file,backend).get_patches())
        patches.extend(StackRetEncryption(tmp_file,backend).get_patches())
        patches.extend(UninitializedPatcher(tmp_file,backend).get_patches())

        backend.apply_patches(patches)
        content = backend.get_final_content()
        os.unlink(tmp_file)
        return (content,nr.get_partialbitflip_real_rule())

    def generate_medium_reassembler_flip_fidget_binary(self):
        tmp_file = tempfile.mktemp()
        fidget_it(self.infile, tmp_file)

        nr = NetworkRules()
        backend = ReassemblerBackend(tmp_file)
        patches = []

        patches.extend(IndirectCFI(tmp_file,backend).get_patches())
        patches.extend(TransmitProtection(tmp_file,backend).get_patches())
        patches.extend(ShiftStack(tmp_file,backend).get_patches())
        patches.extend(Adversarial(tmp_file,backend).get_patches())
        patches.extend(Backdoor(tmp_file,backend,enable_bitflip=True).get_patches())
        patches.extend(NxStack(tmp_file,backend).get_patches())
        patches.extend(MallocExtPatcher(tmp_file,backend).get_patches())
        patches.extend(StackRetEncryption(tmp_file,backend).get_patches())
        patches.extend(UninitializedPatcher(tmp_file,backend).get_patches())

        backend.apply_patches(patches)
        content = backend.get_final_content()
        os.unlink(tmp_file)
        return (content,nr.get_partialbitflip_real_rule())

    def generate_medium_detour_binary(self):
        nr = NetworkRules()
        backend = DetourBackend(self.infile)
        patches = []

        patches.extend(IndirectCFI(self.infile,backend).get_patches())
        patches.extend(TransmitProtection(self.infile,backend).get_patches())
        patches.extend(ShiftStack(self.infile,backend).get_patches())
        patches.extend(Adversarial(self.infile,backend).get_patches())
        patches.extend(Backdoor(self.infile,backend).get_patches())
        patches.extend(NxStack(self.infile,backend).get_patches())
        patches.extend(MallocExtPatcher(self.infile,backend).get_patches())
        patches.extend(StackRetEncryption(self.infile,backend).get_patches())
        patches.extend(UninitializedPatcher(self.infile,backend).get_patches())

        backend.apply_patches(patches)
        return (backend.get_final_content(),"")

    def generate_medium_reassembler_binary(self):
        nr = NetworkRules()
        backend = ReassemblerBackend(self.infile)
        patches = []

        patches.extend(IndirectCFI(self.infile,backend).get_patches())
        patches.extend(TransmitProtection(self.infile,backend).get_patches())
        patches.extend(ShiftStack(self.infile,backend).get_patches())
        patches.extend(Adversarial(self.infile,backend).get_patches())
        patches.extend(Backdoor(self.infile,backend).get_patches())
        patches.extend(NxStack(self.infile,backend).get_patches())
        patches.extend(MallocExtPatcher(self.infile,backend).get_patches())
        patches.extend(StackRetEncryption(self.infile,backend).get_patches())
        patches.extend(UninitializedPatcher(self.infile,backend).get_patches())

        backend.apply_patches(patches)
        return (backend.get_final_content(),"")

    ########################

    def generate_uninitialized_patch(self):
        backend = DetourBackend(self.infile)
        cp = UninitializedPatcher(self.infile, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        return backend.get_final_content(),""

    def generate_malloc_ext_patch(self):
        backend = DetourBackend(self.infile)
        cp = MallocExtPatcher(self.infile, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        return backend.get_final_content(),""

    def create_one_patch(self,patch_type):
        m = getattr(self,"generate_"+patch_type+"_binary")
        patch, network_rule = m()
        return patch, network_rule


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
        if TEST_RESULTS:
            args += ["--test"]
        res = exec_cmd(args)
        with open(output_fname+"_log","wb") as fp:
            fp.write("\n"+"="*30+" STDOUT\n")
            fp.write(res[0])
            fp.write("\n"+"="*30+" STDERR\n")
            fp.write(res[1])
            fp.write("\n"+"="*30+" RETCODE: ")
            fp.write(str(res[2]).strip())
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
        logging.getLogger("patcherex.techniques.NxStack").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.Adversarial").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.Backdoor").setLevel("DEBUG")
        logging.getLogger("patcherex.PatchMaster").setLevel("INFO")

        input_fname = sys.argv[2]
        out = os.path.join(sys.argv[3],os.path.basename(input_fname))
        pm = PatchMaster(input_fname)

        res = pm.run(return_dict = True)
        with open(sys.argv[2]) as fp:
            original_content = fp.read()
        res["original"] = (original_content, '')
        for k,(v,rule) in res.iteritems():
            output_fname = out+"_"+k
            fp = open(output_fname,"wb")
            fp.write(v)
            fp.close()
            os.chmod(output_fname, 0755)
            with open(output_fname+'.rules','wb') as rf:
                rf.write(rule)

    elif sys.argv[1] == "single":
        cdll['libc.so.6'].prctl(1,9)
        print "="*50,"process started at",str(datetime.datetime.now())
        print " ".join(map(shellquote,sys.argv))

        if "--test" in sys.argv:
            TEST_RESULTS = True

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
        logging.getLogger("patcherex.techniques.NxStack").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.Adversarial").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.Backdoor").setLevel("DEBUG")
        logging.getLogger("patcherex.PatchMaster").setLevel("INFO")
        logging.getLogger("fidget").setLevel("INFO")

        input_fname = sys.argv[2]
        technique = sys.argv[3]
        output_fname = sys.argv[4]
        pm = PatchMaster(input_fname)
        m = getattr(pm,"generate_"+technique+"_binary")
        res = m()
        # handle generate_ methods returning also a network rule
        bitflip = False
        if len(res) == 2:
            if not any([output_fname.endswith("_"+str(i)) for i in xrange(2,10)]):
                fp = open(os.path.join(os.path.dirname(output_fname),"ids.rules"),"wb")
                fp.write(res[1])
                fp.close()
            if "bitflip" in res[1]:
                bitflip = True
            patched_bin_content = res[0]
        else:
            patched_bin_content = res

        fp = open(output_fname,"wb")
        fp.write(patched_bin_content)
        fp.close()
        os.chmod(output_fname, 0755)

        if TEST_RESULTS:
            test_bin(input_fname,output_fname,bitflip)

        print "="*50,"process ended at",str(datetime.datetime.now())

    elif sys.argv[1] == "multi" or sys.argv[1] == "multi_name" or sys.argv[1] == "multi_name2":
        out = sys.argv[2]
        techniques = sys.argv[3].split(",")
        if "--test" == sys.argv[7]:
            TEST_RESULTS = True

        files = sys.argv[8:]
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

        print len(tasks)
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
            if status:
                status = termcolor.colored(status,"green")
            else:
                status = termcolor.colored(status,"red")

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
