#!/usr/bin/env python

import sys
import os
import logging
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
import traceback
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
from patcherex.techniques.binary_optimization import optimize_it
from patcherex.techniques.uninitialized_patcher import UninitializedPatcher
from patcherex.techniques.malloc_ext_patcher import MallocExtPatcher
from patcherex.techniques.noflagprintf import NoFlagPrintfPatcher
from patcherex.errors import *


from patcherex.backends.detourbackend import DetourBackend
from patcherex.backends.reassembler_backend import ReassemblerBackend
from patcherex.patches import *
from networkrules import NetworkRules


l = logging.getLogger("patcherex.PatchMaster")


def get_backdoorpov():
    self_location_folder = os.path.dirname(os.path.realpath(__file__))
    backdoorpov_fname = os.path.join(self_location_folder,"../backdoor_stuff/backdoor_pov.pov")
    with open(backdoorpov_fname) as fp:
        content = fp.read()
    return content


def test_bin_with_qemu(original,patched_blob,bitflip=False):
    import shellphish_qemu
    import subprocess32

    def try_bin_with_input(path,tinput):
        pipe = subprocess32.PIPE
        qemu_location = shellphish_qemu.qemu_path('cgc-nxtracer')
        main_args = [qemu_location,"-seed","123"]
        if bitflip:
            used_args = main_args + ["-bitflip"]
        else:
            used_args = main_args

        final_args = used_args + [os.path.realpath(path)]
        print " ".join(final_args)
        p = subprocess32.Popen(final_args, stdin=pipe, stdout=pipe, stderr=pipe, preexec_fn=process_killer)
        status = "ok"
        try:
            try:
                stdout,stderr = p.communicate(tinput,timeout=10)
                print stdout
                print stderr
                print p.returncode
            except OSError:
                print "OSError"
                # I have seen: "OSError: [Errno 32] Broken pipe"
                # likely because the process dies before it reads all the input
                # I just "pass", the code later on will check if it is a crash or normal exit
                if p.returncode == None:
                    # returncode == None means the process is still running
                    # this means the process did not terminate
                    # I am not even sure this is possible, but I am going to terminate it to be sure
                    p.terminate()
            p.wait() # either communicate has finished or I called terminate, so wait will not stall
            # 46 is the special error code value used in cgc-nxtracer used to indicate
            # execution attempt of not executable memory
            if p.returncode < 0 or p.returncode == 46:
                status = "crash"
        except subprocess32.TimeoutExpired:
            print "Timeout"
            status = "halt"
            p.terminate()
            p.wait()
        print status
        return status


    patched = tempfile.mktemp()
    with open(patched,'wb') as fp:
        fp.write(patched_blob)
        os.chmod(patched, 0755)
    # given challenge_binary_node.py the original file is executable

    inputs = ["","B","\n","\x00","1\n \x00"*10]
    success_tests = []
    for tinput in inputs:
        test_result = try_bin_with_input(original,tinput)
        if test_result == "ok":
            success_tests.append(tinput)

    for success_input in success_tests:
        test_result = try_bin_with_input(patched,success_input)
        if test_result != "ok":
            os.unlink(patched)
            raise FunctionalityError("input ->"+success_input.encode('hex')+"<-")
    os.unlink(patched)


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

    def generate_backdoor_reassembler_binary(self):
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

    def generate_medium_reassembler_optimized_binary(self,test_bin=True):
        try:
            intermediate = tempfile.mktemp(prefix='%s_' % os.path.basename(self.infile))
            optimize_it(self.infile, intermediate)

            nr = NetworkRules()
            backend = ReassemblerBackend(intermediate)
            patches = []

            patches.extend(IndirectCFI(intermediate,backend).get_patches())
            patches.extend(TransmitProtection(intermediate,backend).get_patches())
            patches.extend(ShiftStack(intermediate,backend).get_patches())
            patches.extend(Adversarial(intermediate,backend).get_patches())
            patches.extend(Backdoor(intermediate,backend).get_patches())
            # patches.extend(NxStack(intermediate,backend).get_patches())
            patches.extend(MallocExtPatcher(intermediate,backend).get_patches())
            patches.extend(StackRetEncryption(intermediate,backend).get_patches())
            patches.extend(UninitializedPatcher(intermediate,backend).get_patches())
            patches.extend(NoFlagPrintfPatcher(intermediate, backend).get_patches())

            backend.apply_patches(patches)
            final_content = backend.get_final_content()
            if test_bin:
                test_bin_with_qemu(self.infile,final_content)
            res = (final_content,"")
        except PatcherexError, e:
            traceback.print_exc(e)
            res = (None,None)

        return res

    def generate_medium_reassembler_binary(self,test_bin=True):
        try:
            nr = NetworkRules()
            backend = ReassemblerBackend(self.infile)
            patches = []

            patches.extend(IndirectCFI(self.infile,backend).get_patches())
            patches.extend(TransmitProtection(self.infile,backend).get_patches())
            patches.extend(ShiftStack(self.infile,backend).get_patches())
            patches.extend(Adversarial(self.infile,backend).get_patches())
            patches.extend(Backdoor(self.infile,backend).get_patches())
            # patches.extend(NxStack(self.infile,backend).get_patches())
            patches.extend(MallocExtPatcher(self.infile,backend).get_patches())
            patches.extend(StackRetEncryption(self.infile,backend).get_patches())
            patches.extend(UninitializedPatcher(self.infile,backend).get_patches())
            patches.extend(NoFlagPrintfPatcher(self.infile, backend).get_patches())

            backend.apply_patches(patches)
            final_content = backend.get_final_content()
            if test_bin:
                test_bin_with_qemu(self.infile,final_content)
            res = (final_content,"")
        except PatcherexError, e:
            traceback.print_exc(e)
            res = (None,None)
        return res

    def generate_medium_detour_binary(self,test_bin=True):
        try:
            nr = NetworkRules()
            backend = DetourBackend(self.infile)
            patches = []

            patches.extend(IndirectCFI(self.infile,backend).get_patches())
            patches.extend(TransmitProtection(self.infile,backend).get_patches())
            patches.extend(ShiftStack(self.infile,backend).get_patches())
            patches.extend(Adversarial(self.infile,backend).get_patches())
            patches.extend(Backdoor(self.infile,backend).get_patches())
            # patches.extend(NxStack(self.infile,backend).get_patches())
            patches.extend(MallocExtPatcher(self.infile,backend).get_patches())
            patches.extend(StackRetEncryption(self.infile,backend).get_patches())
            patches.extend(UninitializedPatcher(self.infile,backend).get_patches())
            patches.extend(NoFlagPrintfPatcher(self.infile, backend).get_patches())

            backend.apply_patches(patches)
            final_content = backend.get_final_content()
            if test_bin:
                test_bin_with_qemu(self.infile,final_content)
            res = (final_content,"")
        except PatcherexError, e:
            traceback.print_exc(e)
            res = (None,None)
        return res

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
        patch, network_rule = m(test_bin=True)
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


def worker(inq,outq,filename_with_technique=True,timeout=60*3,test_results=True):
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
        if test_results:
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
        logging.getLogger("patcherex.backends.DetourBackend").setLevel("INFO")
        logging.getLogger("patcherex.backend").setLevel("INFO")
        logging.getLogger("patcherex.techniques.NoFlagPrintfPatcher").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.StackRetEncryption").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.IndirectCFI").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.TransmitProtection").setLevel("DEBUG")
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

        logging.getLogger("patcherex.backends.DetourBackend").setLevel("INFO")
        logging.getLogger("patcherex.backend").setLevel("INFO")
        logging.getLogger("patcherex.techniques.NoFlagPrintfPatcher").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.StackRetEncryption").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.IndirectCFI").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.TransmitProtection").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.ShiftStack").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.NxStack").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.Adversarial").setLevel("DEBUG")
        logging.getLogger("patcherex.techniques.Backdoor").setLevel("DEBUG")
        logging.getLogger("patcherex.PatchMaster").setLevel("INFO")

        input_fname = sys.argv[2]
        technique = sys.argv[3]
        output_fname = sys.argv[4]
        pm = PatchMaster(input_fname)
        m = getattr(pm,"generate_"+technique+"_binary")

        if "--test" in sys.argv:
            res = m(test_bin = True)
        else:
            res = m(test_bin = False)

        # handle generate_ methods returning also a network rule
        bitflip = False
        if res[0] == None:
            sys.exit(33)
        if not any([output_fname.endswith("_"+str(i)) for i in xrange(2,10)]):
            fp = open(os.path.join(os.path.dirname(output_fname),"ids.rules"),"wb")
            fp.write(res[1])
            fp.close()
        if "bitflip" in res[1]:
            bitflip = True
        patched_bin_content = res[0]

        fp = open(output_fname,"wb")
        fp.write(patched_bin_content)
        fp.close()
        os.chmod(output_fname, 0755)

        print "="*50,"process ended at",str(datetime.datetime.now())

    elif sys.argv[1] == "multi" or sys.argv[1] == "multi_name" or sys.argv[1] == "multi_name2":
        out = sys.argv[2]
        techniques = sys.argv[3].split(",")
        if "--test" == sys.argv[7]:
            test_results = True
        else:
            test_results = False

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
            p = multiprocessing.Process(target=worker, args=(inq,outq,technique_in_filename,timeout,test_results))
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
