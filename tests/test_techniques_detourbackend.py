#!/usr/bin/env python

import os
import nose
import struct
import subprocess
import logging
import shutil
from functools import wraps
import tempfile

import patcherex
from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import *
from tracer import Runner

l = logging.getLogger("patcherex.test.test_techniques_detourbackend")

# TODO ideally these tests should be run in the vm

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries-private'))
qemu_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../tracer/bin/tracer-qemu-cgc"))

'''
This "old" version of QEMU works like a "normal" QEMU, failing to transmit partially invalid memory regions.
It is generated using the branch 'detectable' in the cgc QEMU repository:
git clone git@git.seclab.cs.ucsb.edu:cgc/qemu.git
cd qemu
git checkout detectable
./cgc_configure_debug
make -j4
cp i386-linux-user/qemu-i386 <patcherex>/tests/old_tracer-qemu-cgc
'''
old_qemu_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "old_tracer-qemu-cgc"))

global_data_fallback = None


def add_fallback_strategy(f):
    @wraps(f)
    def wrapper():
        global global_data_fallback
        global_data_fallback = None
        f()
        global_data_fallback = True
        f()
    return wrapper


@add_fallback_strategy
def test_shadowstack():
    logging.getLogger("patcherex.techniques.ShadowStack").setLevel("DEBUG")
    from patcherex.techniques.shadowstack import ShadowStack
    filepath = os.path.join(bin_location, "cgc_trials/CADET_00003")
    pipe = subprocess.PIPE

    p = subprocess.Popen([qemu_location, filepath], stdin=pipe, stdout=pipe, stderr=pipe)
    res = p.communicate("\x00"*1000+"\n")
    print res, p.returncode
    nose.tools.assert_equal((p.returncode == -11), True)

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,global_data_fallback)
        cp = ShadowStack(filepath, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)

        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("\x00"*100+"\n")
        print res, p.returncode
        nose.tools.assert_equal(p.returncode == 68, True)


@add_fallback_strategy
def test_packer():
    from patcherex.techniques.packer import Packer
    filepath = os.path.join(bin_location, "cgc_trials/CADET_00003")
    pipe = subprocess.PIPE

    expected = "\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \t\tYes, that's a palindrome!\n\n\tPlease enter a possible palindrome: "
    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,global_data_fallback)
        cp = Packer(filepath, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)

        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal((res[0] == expected and p.returncode == 0), True)


@add_fallback_strategy
def test_simplecfi():
    logging.getLogger("patcherex.techniques.SimpleCFI").setLevel("DEBUG")
    from patcherex.techniques.simplecfi import SimpleCFI
    filepath = os.path.join(bin_location, "cgc_scored_event_2/cgc/0b32aa01_01")
    pipe = subprocess.PIPE

    p = subprocess.Popen([qemu_location, filepath], stdin=pipe, stdout=pipe, stderr=pipe)
    res = p.communicate("\x00"*1000+"\n")
    print res, p.returncode
    nose.tools.assert_equal((p.returncode == -11), True)

    #0x80480a0 is the binary entry point
    exploiting_input = "AAAA"+"\x00"*80+struct.pack("<I",0x80480a0)*20+"\n" 
    expected1 = "\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \t\tNope, that's not a palindrome\n\n\tPlease enter a possible palindrome: \nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: "

    p = subprocess.Popen([qemu_location, filepath], stdin=pipe, stdout=pipe, stderr=pipe)
    res = p.communicate(exploiting_input)
    expected_retcode = 1 #should be -11
    #TODO fix these two checks when our tracer will be fixed (https://git.seclab.cs.ucsb.edu/cgc/tracer/issues/2)
    nose.tools.assert_equal((res[0][:200] == expected1[:200] and p.returncode == expected_retcode), True)

    expected2 = "\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \t\tYes, that's a palindrome!\n\n\tPlease enter a possible palindrome: "
    expected3 = "\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: "
    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,global_data_fallback)
        cp = SimpleCFI(filepath, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)

        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal((res[0] == expected2 and p.returncode == 0), True)

        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(exploiting_input)
        print res, p.returncode
        nose.tools.assert_equal((res[0] == expected3 and p.returncode == 0x45), True)


@add_fallback_strategy
def test_qemudetection():
    logging.getLogger("patcherex.techniques.QemuDetection").setLevel("DEBUG")
    from patcherex.techniques.qemudetection import QemuDetection
    filepath = os.path.join(bin_location, "cgc_scored_event_2/cgc/0b32aa01_01")
    pipe = subprocess.PIPE

    p = subprocess.Popen([qemu_location, filepath], stdin=pipe, stdout=pipe, stderr=pipe)
    res = p.communicate("\x00"*1000+"\n")
    print res, p.returncode
    nose.tools.assert_equal((p.returncode == -11), True)

    expected = "\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \t\tYes, that's a palindrome!\n\n\tPlease enter a possible palindrome: "
    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,global_data_fallback)
        cp = QemuDetection(filepath, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)

        p = subprocess.Popen([old_qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal(p.returncode == 0x40 or p.returncode == 0x41, True)

        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal((res[0] == expected and p.returncode == 0), True)


@add_fallback_strategy
def test_randomsyscallloop():
    from patcherex.techniques.randomsyscallloop import RandomSyscallLoop
    filepath = os.path.join(bin_location, "cgc_trials/CADET_00003")
    pipe = subprocess.PIPE

    p = subprocess.Popen([qemu_location, filepath], stdin=pipe, stdout=pipe, stderr=pipe)
    res = p.communicate("\x00"*1000+"\n")
    print res, p.returncode
    nose.tools.assert_equal((p.returncode == -11), True)

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,global_data_fallback)
        cp = RandomSyscallLoop(filepath, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)

        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("\x00"*100+"\n")
        print res, p.returncode
        nose.tools.assert_equal(res[0] == "\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: ", True)
        nose.tools.assert_equal(p.returncode == -11, True)


@add_fallback_strategy
def test_cpuid():
    from patcherex.techniques.cpuid import CpuId
    filepath = os.path.join(bin_location, "cgc_trials/CADET_00003")
    pipe = subprocess.PIPE

    p = subprocess.Popen([qemu_location, filepath], stdin=pipe, stdout=pipe, stderr=pipe)
    res = p.communicate("\x00"*1000+"\n")
    print res, p.returncode
    nose.tools.assert_equal((p.returncode == -11), True)

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,global_data_fallback)
        cp = CpuId(filepath, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)

        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("\x00"*100+"\n")
        print res, p.returncode
        nose.tools.assert_equal(res[0].endswith("\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: "), True)
        nose.tools.assert_equal(len(res[0]) > 500, True)
        nose.tools.assert_equal(p.returncode == -11, True)


@add_fallback_strategy
def test_stackretencryption():
    logging.getLogger("patcherex.techniques.StackRetEncryption").setLevel("DEBUG")
    from patcherex.techniques.stackretencryption import StackRetEncryption
    filepath1 = os.path.join(bin_location, "cgc_scored_event_2/cgc/0b32aa01_01")
    filepath2 = os.path.join(bin_location, "cgc_trials/last_trial/original/CROMU_00070")
    pipe = subprocess.PIPE

    p = subprocess.Popen([qemu_location, filepath1], stdin=pipe, stdout=pipe, stderr=pipe)
    res = p.communicate("\x00"*1000+"\n")
    print res, p.returncode
    nose.tools.assert_equal((p.returncode == -11), True)

    #0x80480a0 is the binary entry point
    exploiting_input = "AAAA"+"\x00"*80+struct.pack("<I",0x80480a0)*20+"\n"
    expected1 = "\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: " \
            "\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \t\tNope,"
    p = subprocess.Popen([qemu_location, filepath1], stdin=pipe, stdout=pipe, stderr=pipe)
    res = p.communicate(exploiting_input)
    print res, p.returncode
    nose.tools.assert_equal(p.returncode != -11, True)
    nose.tools.assert_equal(res[0].startswith(expected1),True)

    expected2 = "\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \t\tYes, that's a palindrome!\n\n\tPlease enter a possible palindrome: "
    for allow_reg_reuse in [True,False]:
        with patcherex.utils.tempdir() as td:
            original_file = os.path.join(td, "original")
            shutil.copy(filepath2,original_file)
            os.chmod(original_file,777)

            tmp_file = os.path.join(td, "patched1")
            backend = DetourBackend(filepath1,global_data_fallback)
            cp = StackRetEncryption(filepath1, backend, allow_reg_reuse=allow_reg_reuse)
            patches = cp.get_patches()
            backend.apply_patches(patches)
            backend.save(tmp_file)

            p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
            res = p.communicate("A"*10+"\n")
            print res, p.returncode
            nose.tools.assert_equal((res[0] == expected2 and p.returncode == 0), True)
            p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
            res = p.communicate(exploiting_input)
            print res, p.returncode
            nose.tools.assert_equal(p.returncode == -11, True)

            tmp_file = os.path.join(td, "patched2")
            backend = DetourBackend(filepath2,global_data_fallback)
            cp = StackRetEncryption(filepath2, backend, allow_reg_reuse=allow_reg_reuse)
            patches = cp.get_patches()
            backend.apply_patches(patches)
            backend.save(tmp_file)
            p = subprocess.Popen([qemu_location, original_file], stdin=pipe, stdout=pipe, stderr=pipe)
            res = p.communicate("\x00\x01\x01"+"A"*1000+"\n")
            print res
            sane_stdout, sane_retcode = res[0], p.returncode
            p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
            res = p.communicate("\x00\x01\x01"+"A"*1000+"\n")
            print res
            nose.tools.assert_equal(res[0] == sane_stdout, True)
            nose.tools.assert_equal(p.returncode == sane_retcode, True)


#@add_fallback_strategy
def test_indirectcfi():
    logging.getLogger("patcherex.techniques.IndirectCFI").setLevel("DEBUG")
    from patcherex.techniques.indirectcfi import IndirectCFI

    vulnerable_fname1 = os.path.join(bin_location, "tests/i386/patchrex/indirect_call_test_O0")
    res = Runner(vulnerable_fname1,"00000001\n",record_stdout=True)
    nose.tools.assert_equal(res.stdout,"hello\nCGC")
    res = Runner(vulnerable_fname1,"00000002\n",record_stdout=True)
    nose.tools.assert_equal(res.stdout,"hello\nCGC")
    res = Runner(vulnerable_fname1,"00000003\n",record_stdout=True)
    nose.tools.assert_equal(res.stdout,"hello\nCGC")


    res = Runner(vulnerable_fname1,"00000001\n23456789\n",record_stdout=True)
    nose.tools.assert_equal(res.reg_vals['eip'],0x23456789)
    res = Runner(vulnerable_fname1,"00000002\n43456789\n",record_stdout=True)
    nose.tools.assert_equal(res.reg_vals['eip'],0x43456789)
    res = Runner(vulnerable_fname1,"00000003\n53456789\n",record_stdout=True)
    nose.tools.assert_equal(res.reg_vals['eip'],0x53456789)
    res = Runner(vulnerable_fname1,"00000004\n63456789\n",record_stdout=True)
    nose.tools.assert_equal(res.reg_vals['eip'],0x63456789)

    res = Runner(vulnerable_fname1,"00000001\n08048640\n",record_stdout=True)
    print {k:hex(v) for k,v in res.reg_vals.iteritems()}
    nose.tools.assert_equal(res.reg_vals['ebp'] & 0xfffff000,0x08048000)
    nose.tools.assert_equal(res.reg_vals['eip'],0x0)
    res = Runner(vulnerable_fname1,"00000002\n08048640\n",record_stdout=True)
    print {k:hex(v) for k,v in res.reg_vals.iteritems()}
    nose.tools.assert_equal(res.reg_vals['ebp'] & 0xfffff000,0x08048000)
    nose.tools.assert_equal(res.reg_vals['eip'],0x0)
    res = Runner(vulnerable_fname1,"00000003\n08048640\n",record_stdout=True)
    print {k:hex(v) for k,v in res.reg_vals.iteritems()}
    nose.tools.assert_equal(res.reg_vals['ebp'] & 0xfffff000,0x08048000)
    nose.tools.assert_equal(res.reg_vals['eip'],0x0)
    res = Runner(vulnerable_fname1,"00000004\n08048640  \n",record_stdout=True)
    print {k:hex(v) for k,v in res.reg_vals.iteritems()}
    nose.tools.assert_equal(res.reg_vals['ebp'] & 0xfffff000,0x08048000)
    nose.tools.assert_equal(res.reg_vals['eip'],0x30303030)

    res = Runner(vulnerable_fname1,"00000001\nb7fff000\n",record_stdout=True)
    nose.tools.assert_equal(res.stdout,"hello\nCGCCGCCGC")
    res = Runner(vulnerable_fname1,"00000001\nbaaaa000\n",record_stdout=True)
    nose.tools.assert_equal(res.stdout,"hello\nCGCCGCCGC")
    res = Runner(vulnerable_fname1,"00000001\nb7fff000\n",record_stdout=True)
    nose.tools.assert_equal(res.stdout,"hello\nCGCCGCCGC")
    res = Runner(vulnerable_fname1,"00000002\nbaaaa000\n",record_stdout=True)
    nose.tools.assert_equal(res.stdout,"hello\nCGCCGCCGC")
    res = Runner(vulnerable_fname1,"00000002\nb7fff000\n",record_stdout=True)
    nose.tools.assert_equal(res.stdout,"hello\nCGCCGCCGC")
    res = Runner(vulnerable_fname1,"00000002\nbaaaa000\n",record_stdout=True)
    nose.tools.assert_equal(res.stdout,"hello\nCGCCGCCGC")
    res = Runner(vulnerable_fname1,"00000003\nb7fff000\n",record_stdout=True)
    nose.tools.assert_equal(res.stdout,"hello\nCGCCGCCGC")
    res = Runner(vulnerable_fname1,"00000003\nbaaaa000\n",record_stdout=True)
    nose.tools.assert_equal(res.stdout,"hello\nCGCCGCCGC")
    res = Runner(vulnerable_fname1,"00000003\nb7fff000\n",record_stdout=True)
    nose.tools.assert_equal(res.stdout,"hello\nCGCCGCCGC")
    res = Runner(vulnerable_fname1,"00000004\nbaaaa000\n",record_stdout=True)
    nose.tools.assert_equal(res.stdout,"hello\nCGC")
    res = Runner(vulnerable_fname1,"00000004\nbaaaa000\n",record_stdout=True)
    nose.tools.assert_equal(res.stdout,"hello\nCGC")
    res = Runner(vulnerable_fname1,"00000004\nbaaaa000\n",record_stdout=True)
    nose.tools.assert_equal(res.stdout,"hello\nCGC")

    with patcherex.utils.tempdir() as td:
        patched_fname1 = os.path.join(td, "patched")
        backend = DetourBackend(vulnerable_fname1,global_data_fallback)
        cp = IndirectCFI(vulnerable_fname1, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(patched_fname1)
        res = Runner(patched_fname1,"00000001\n",record_stdout=True)
        nose.tools.assert_equal(res.stdout,"hello\nCGC")

        res = Runner(patched_fname1,"00000001\n23456789\n",record_stdout=True)
        nose.tools.assert_equal(res.stdout,"hello\nCGC")
        print hex(res.reg_vals['eip'])
        nose.tools.assert_true(res.reg_vals['eip'] != 0x23456789)
        res = Runner(patched_fname1,"00000002\n23456789\n",record_stdout=True)
        nose.tools.assert_equal(res.stdout,"hello\nCGC")
        print hex(res.reg_vals['eip'])
        nose.tools.assert_true(res.reg_vals['eip'] != 0x23456789)
        res = Runner(patched_fname1,"00000003\n23456789\n",record_stdout=True)
        nose.tools.assert_equal(res.stdout,"hello\nCGC")
        print hex(res.reg_vals['eip'])
        nose.tools.assert_true(res.reg_vals['eip'] != 0x23456789)
        res = Runner(patched_fname1,"00000004\n23456789\n",record_stdout=True)
        nose.tools.assert_equal(res.stdout,"hello\n")
        print hex(res.reg_vals['eip'])
        nose.tools.assert_true(res.reg_vals['eip'] != 0x23456789)

        #main: 08048620, stack: baaaa000, heap: b7fff000
        #main -> heap
        res = Runner(patched_fname1,"00000001\nb7fff000\n",record_stdout=True)
        nose.tools.assert_equal(res.stdout,"hello\nCGC")
        print hex(res.reg_vals['eip'])
        nose.tools.assert_true(res.reg_vals['eip'] == 0x8047333)
        #main -> stack
        res = Runner(patched_fname1,"00000001\nbaaaa000\n",record_stdout=True)
        nose.tools.assert_equal(res.stdout,"hello\nCGC")
        print hex(res.reg_vals['eip'])
        nose.tools.assert_true(res.reg_vals['eip'] == 0x8047333)
        #main -> main
        res = Runner(patched_fname1,"00000001\n08048620\n",record_stdout=True)
        nose.tools.assert_equal(res.stdout,"hello\nCGCCGCCGC")
        nose.tools.assert_true(res.reg_vals == None)

        #stack -> main
        res = Runner(patched_fname1,"00000002\n08048620\n",record_stdout=True)
        nose.tools.assert_equal(res.stdout,"hello\nCGC")
        print hex(res.reg_vals['eip'])
        nose.tools.assert_true(res.reg_vals['eip'] == 0x8047333)
        #stack -> heap
        res = Runner(patched_fname1,"00000002\nb7fff000\n",record_stdout=True)
        nose.tools.assert_equal(res.stdout,"hello\nCGC")
        print hex(res.reg_vals['eip'])
        nose.tools.assert_true(res.reg_vals['eip'] == 0x8047333)
        #stack -> stack
        res = Runner(patched_fname1,"00000002\nbaaaa000\n",record_stdout=True)
        nose.tools.assert_equal(res.stdout,"hello\nCGCCGCCGC")
        nose.tools.assert_true(res.reg_vals == None)

        #heap -> main
        res = Runner(patched_fname1,"00000003\n08048620\n",record_stdout=True)
        nose.tools.assert_equal(res.stdout,"hello\nCGC")
        print hex(res.reg_vals['eip'])
        nose.tools.assert_true(res.reg_vals['eip'] == 0x8047333)
        #heap -> stack
        res = Runner(patched_fname1,"00000003\nbaaaa000\n",record_stdout=True)
        nose.tools.assert_equal(res.stdout,"hello\nCGC")
        print hex(res.reg_vals['eip'])
        nose.tools.assert_true(res.reg_vals['eip'] == 0x8047333)
        #heap -> heap
        res = Runner(patched_fname1,"00000003\nb7fff000\n",record_stdout=True)
        nose.tools.assert_equal(res.stdout,"hello\nCGCCGCCGC")
        nose.tools.assert_true(res.reg_vals == None)

        #unknown -> main
        res = Runner(patched_fname1,"00000004\n08048620\n",record_stdout=True)
        nose.tools.assert_equal(res.stdout,"hello\nCGC")
        nose.tools.assert_true(res.reg_vals == None)
        #unknown -> stack
        res = Runner(patched_fname1,"00000004\nbaaaa000\n",record_stdout=True)
        nose.tools.assert_equal(res.stdout,"hello\nCGC")
        nose.tools.assert_true(res.reg_vals == None)
        #unknown -> heap
        res = Runner(patched_fname1,"00000004\nb7fff000\n",record_stdout=True)
        nose.tools.assert_equal(res.stdout,"hello\nCGC")
        nose.tools.assert_true(res.reg_vals == None)

        # call gadget
        res = Runner(patched_fname1,"00000001\n08048640\n",record_stdout=True)
        nose.tools.assert_equal(res.reg_vals['eip'], 0x8047332)
        res = Runner(patched_fname1,"00000002\n08048640\n",record_stdout=True)
        nose.tools.assert_equal(res.reg_vals['eip'], 0x8047332)
        res = Runner(patched_fname1,"00000003\n08048640\n",record_stdout=True)
        nose.tools.assert_equal(res.reg_vals['eip'], 0x8047332)
        res = Runner(patched_fname1,"00000004\n08048640\n",record_stdout=True)
        nose.tools.assert_equal(res.reg_vals['eip'], 0x8047332)


def run_all():
    functions = globals()
    all_functions = dict(filter((lambda (k, v): k.startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            l.info("testing %s" % str(f))
            all_functions[f]()


if __name__ == "__main__":
    import sys
    logging.getLogger("patcherex.backends.DetourBackend").setLevel("INFO")
    logging.getLogger("patcherex.test.test_techniques_detourbackend").setLevel("INFO")
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()

