#!/usr/bin/env python

import os
import nose
import struct
import subprocess
import logging
import shutil
from functools import wraps
import tempfile
import random

import patcherex
import shellphish_qemu
from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import *
from tracer import Runner
from povsim import CGCPovSimulator

l = logging.getLogger("patcherex.test.test_techniques_detourbackend")

# TODO ideally these tests should be run in the vm

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries-private'))
qemu_location = shellphish_qemu.qemu_path('cgc-tracer')
self_location_folder = os.path.dirname(os.path.realpath(__file__))


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
global_try_pdf_removal = True


def add_fallback_strategy(f):
    @wraps(f)
    def wrapper():
        global global_data_fallback
        global global_try_pdf_removal
        global_data_fallback = None
        global_try_pdf_removal = True
        f()
        #global_data_fallback = True
        #global_try_pdf_removal = True
        #f()
        global_data_fallback = None
        global_try_pdf_removal = False
        f()
        global_data_fallback = True
        global_try_pdf_removal = False
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
        backend = DetourBackend(filepath,global_data_fallback,try_pdf_removal=global_try_pdf_removal)
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
        backend = DetourBackend(filepath,global_data_fallback,try_pdf_removal=global_try_pdf_removal)
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
        backend = DetourBackend(filepath,global_data_fallback,try_pdf_removal=global_try_pdf_removal)
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
        backend = DetourBackend(filepath,global_data_fallback,try_pdf_removal=global_try_pdf_removal)
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
        backend = DetourBackend(filepath,global_data_fallback,try_pdf_removal=global_try_pdf_removal)
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
        backend = DetourBackend(filepath,global_data_fallback,try_pdf_removal=global_try_pdf_removal)
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
    filepath3 = os.path.join(bin_location, "cgc_samples_multiflags/CROMU_00008/original/CROMU_00008")
    filepath4 = os.path.join(bin_location, "cgc_samples_multiflags/KPRCA_00026/original/KPRCA_00026")
    pipe = subprocess.PIPE

    p = subprocess.Popen([qemu_location, filepath1], stdin=pipe, stdout=pipe, stderr=pipe)
    res = p.communicate("\x00"*1000+"\n")
    print res, p.returncode
    nose.tools.assert_equal((p.returncode == -11), True)

    #0x80480a0 is the binary entry point
    exploiting_input = "AAAA"+"\x00"*80+struct.pack("<I",0x80480a0)*20+"\n"
    expected1 = "\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: " \
            "\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \t\tNope,"
    input3 = 'login\ninsert\na\na\na\n11/11/11 11:11:11\nfind\nusername <"xdDVRNBQTTrhqk" AND birthdate <6/9/1 20:33:47())\n\n'
    expected3 = '> You logged in.\n> First name: Last name: User name: Birthdate (mm/dd/yy hh:mm:ss): Date ' \
        'is: 11/11/2011 11:11:11\nData added, record 0\n> Enter search express (firstname or fn, lastname or ' \
        'ln, username or un, birthdate or bd, operators ==, !=, >, <, AND and OR):\nSyntax error\n> Command' \
        ' not found.\n> '
    input4 = "1\n2\n3\n4\n5\n6\n"*10
    p = subprocess.Popen([qemu_location, filepath1], stdin=pipe, stdout=pipe, stderr=pipe)
    res = p.communicate(exploiting_input)
    print res, p.returncode
    nose.tools.assert_equal(p.returncode != -11, True)
    nose.tools.assert_equal(res[0].startswith(expected1),True)

    expected2 = "\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \t\tYes, that's a palindrome!\n\n\tPlease enter a possible palindrome: "
    with patcherex.utils.tempdir() as td:
        original_file = os.path.join(td, "original")
        shutil.copy(filepath2,original_file)
        os.chmod(original_file,777)

        tmp_file = os.path.join(td, "patched1")
        backend = DetourBackend(filepath1,global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        cp = StackRetEncryption(filepath1, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)

        seed = str(random.randint(0,1000000000))
        p = subprocess.Popen([qemu_location, "-seed", seed, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal((res[0] == expected2 and p.returncode == 0), True)
        seed = str(random.randint(0,1000000000))
        p = subprocess.Popen([qemu_location, "-seed", seed, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(exploiting_input)
        print res, p.returncode
        nose.tools.assert_equal(p.returncode == -11, True)

        tmp_file = os.path.join(td, "patched2")
        backend = DetourBackend(filepath2,global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        cp = StackRetEncryption(filepath2, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)
        seed = str(random.randint(0,1000000000))
        p = subprocess.Popen([qemu_location, "-seed", seed, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("\x00\x01\x01"+"A"*1000+"\n")
        print res
        sane_stdout, sane_retcode = res[0], p.returncode
        seed = str(random.randint(0,1000000000))
        p = subprocess.Popen([qemu_location, "-seed", seed, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("\x00\x01\x01"+"A"*1000+"\n")
        print res
        nose.tools.assert_equal(res[0] == sane_stdout, True)
        nose.tools.assert_equal(p.returncode == sane_retcode, True)

        # setjmp/longjmp
        tmp_file = os.path.join(td, "patched3")
        backend = DetourBackend(filepath3,global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        cp = StackRetEncryption(filepath3, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)
        p = subprocess.Popen([qemu_location, "-seed", seed, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(input3)
        print res, p.returncode
        nose.tools.assert_equal(res[0], expected3)
        nose.tools.assert_equal(p.returncode, 1)

        # setjmp/longjmp with cgrex
        tmp_file = os.path.join(td, "patched4")
        backend = DetourBackend(filepath4,global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        cp = StackRetEncryption(filepath4, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)
        # backend.save("/tmp/aaa")
        p = subprocess.Popen([qemu_location, "-seed", seed, filepath4], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(input4)
        expected = (res[0],p.returncode)
        p = subprocess.Popen([qemu_location, "-seed", seed, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(input4)
        patched = (res[0],p.returncode)
        print expected
        print patched
        nose.tools.assert_equal(expected, patched)


@add_fallback_strategy
def test_indirectcfi():
    logging.getLogger("patcherex.techniques.IndirectCFI").setLevel("DEBUG")
    from patcherex.techniques.indirectcfi import IndirectCFI
    tests = [
        ("tests/i386/patchrex/indirect_call_test_O0","b7fff000"),
        ("tests/i386/patchrex/indirect_call_test_fullmem_O0","78000000"),
    ]

    for i,(tbin,addr_str) in enumerate(tests):
        vulnerable_fname1 = os.path.join(bin_location, tbin)
        if i==0: #do this only the first time
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

            res = Runner(vulnerable_fname1,"00000001\n"+addr_str+"\n",record_stdout=True)
            nose.tools.assert_equal(res.stdout,"hello\nCGCCGCCGC")
            res = Runner(vulnerable_fname1,"00000001\nbaaaa000\n",record_stdout=True)
            nose.tools.assert_equal(res.stdout,"hello\nCGCCGCCGC")
            res = Runner(vulnerable_fname1,"00000001\n"+addr_str+"\n",record_stdout=True)
            nose.tools.assert_equal(res.stdout,"hello\nCGCCGCCGC")
            res = Runner(vulnerable_fname1,"00000002\nbaaaa000\n",record_stdout=True)
            nose.tools.assert_equal(res.stdout,"hello\nCGCCGCCGC")
            res = Runner(vulnerable_fname1,"00000002\n"+addr_str+"\n",record_stdout=True)
            nose.tools.assert_equal(res.stdout,"hello\nCGCCGCCGC")
            res = Runner(vulnerable_fname1,"00000002\nbaaaa000\n",record_stdout=True)
            nose.tools.assert_equal(res.stdout,"hello\nCGCCGCCGC")
            res = Runner(vulnerable_fname1,"00000003\n"+addr_str+"\n",record_stdout=True)
            nose.tools.assert_equal(res.stdout,"hello\nCGCCGCCGC")
            res = Runner(vulnerable_fname1,"00000003\nbaaaa000\n",record_stdout=True)
            nose.tools.assert_equal(res.stdout,"hello\nCGCCGCCGC")
            res = Runner(vulnerable_fname1,"00000003\n"+addr_str+"\n",record_stdout=True)
            nose.tools.assert_equal(res.stdout,"hello\nCGCCGCCGC")
            res = Runner(vulnerable_fname1,"00000004\nbaaaa000\n",record_stdout=True)
            nose.tools.assert_equal(res.stdout,"hello\nCGC")
            res = Runner(vulnerable_fname1,"00000004\nbaaaa000\n",record_stdout=True)
            nose.tools.assert_equal(res.stdout,"hello\nCGC")
            res = Runner(vulnerable_fname1,"00000004\nbaaaa000\n",record_stdout=True)
            nose.tools.assert_equal(res.stdout,"hello\nCGC")

        with patcherex.utils.tempdir() as td:
            patched_fname1 = os.path.join(td, "patched")
            #import IPython; IPython.embed()
            backend = DetourBackend(vulnerable_fname1,global_data_fallback,try_pdf_removal=global_try_pdf_removal)
            cp = IndirectCFI(vulnerable_fname1, backend)
            patches = cp.get_patches()
            backend.apply_patches(patches)
            backend.save(patched_fname1)
            #backend.save("../../vm/shared/patched")
            res = Runner(patched_fname1,"00000001\n",record_stdout=True)
            nose.tools.assert_equal(res.stdout,"hello\nCGC")

            if i==0:
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

            #main: 08048620, stack: baaaa000, heap: "+addr_str+"
            #main -> heap
            res = Runner(patched_fname1,"00000001\n"+addr_str+"\n",record_stdout=True)
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
            '''
            #stack -> heap
            res = Runner(patched_fname1,"00000002\n"+addr_str+"\n",record_stdout=True)
            nose.tools.assert_equal(res.stdout,"hello\nCGC")
            print hex(res.reg_vals['eip'])
            nose.tools.assert_true(res.reg_vals['eip'] == 0x8047333)
            #stack -> stack
            res = Runner(patched_fname1,"00000002\nbaaaa000\n",record_stdout=True)
            nose.tools.assert_equal(res.stdout,"hello\nCGCCGCCGC")
            nose.tools.assert_true(res.reg_vals == None)
            '''

            #heap -> main
            res = Runner(patched_fname1,"00000003\n08048620\n",record_stdout=True)
            nose.tools.assert_equal(res.stdout,"hello\nCGC")
            print hex(res.reg_vals['eip'])
            nose.tools.assert_true(res.reg_vals['eip'] == 0x8047333)
            '''
            #heap -> stack
            res = Runner(patched_fname1,"00000003\nbaaaa000\n",record_stdout=True)
            nose.tools.assert_equal(res.stdout,"hello\nCGC")
            print hex(res.reg_vals['eip'])
            nose.tools.assert_true(res.reg_vals['eip'] == 0x8047333)
            '''
            #heap -> heap
            res = Runner(patched_fname1,"00000003\n"+addr_str+"\n",record_stdout=True)
            nose.tools.assert_equal(res.stdout,"hello\nCGCCGCCGC")
            nose.tools.assert_true(res.reg_vals == None)

            #unknown -> main
            res = Runner(patched_fname1,"00000004\n08048620\n",record_stdout=True)
            nose.tools.assert_equal(res.stdout,"hello\nCGC")
            nose.tools.assert_true(res.reg_vals == None)
            '''
            #unknown -> stack
            res = Runner(patched_fname1,"00000004\nbaaaa000\n",record_stdout=True)
            nose.tools.assert_equal(res.stdout,"hello\nCGC")
            nose.tools.assert_true(res.reg_vals == None)
            '''
            #unknown -> heap
            res = Runner(patched_fname1,"00000004\n"+addr_str+"\n",record_stdout=True)
            nose.tools.assert_equal(res.stdout,"hello\nCGC")
            nose.tools.assert_true(res.reg_vals == None)

            # call gadget
            if i==0:
                res = Runner(patched_fname1,"00000001\n08048640\n",record_stdout=True)
                nose.tools.assert_equal(res.reg_vals['eip'], 0x8047332)
                res = Runner(patched_fname1,"00000002\n08048640\n",record_stdout=True)
                nose.tools.assert_equal(res.reg_vals['eip'], 0x8047332)
                res = Runner(patched_fname1,"00000003\n08048640\n",record_stdout=True)
                nose.tools.assert_equal(res.reg_vals['eip'], 0x8047332)
                res = Runner(patched_fname1,"00000004\n08048640\n",record_stdout=True)
                nose.tools.assert_equal(res.reg_vals['eip'], 0x8047332)


def test_freeregs():
    def bin_str(name,btype="original"):
        return "cgc_samples_multiflags/%s/%s/%s" % (name,btype,name)

    from patcherex.techniques.stackretencryption import StackRetEncryption
    tests = [
            (bin_str("CADET_00003"),0x08048400,False,True,True),
            (bin_str("CADET_00003"),0x0804860C,False,True,True),
            (bin_str("KPRCA_00038"),0x0804C070,False,False,False),
            (bin_str("KPRCA_00038"),0x0804B390,False,False,False),
            (bin_str("KPRCA_00038"),0x0804AC20,False,True,True),
            (bin_str("KPRCA_00038"),0x0804AAD0,False,True,False),
            (bin_str("CROMU_00012"),0x080498B4,True,False,False),
            (bin_str("CROMU_00012"),0x08048650,False,True,False),
            (bin_str("NRFIN_00026"),0x083BA7e0,False,True,True),
            (bin_str("NRFIN_00026"),0x0897F4D5,True,False,False),
            (bin_str("CROMU_00008","Ofast"),0x804A7F0,False,True,False),
    ]

    cached_backend = {}
    for tbin, addr, is_tail, ecx_free, edx_free in tests:
        fname = os.path.join(bin_location, tbin)
        if fname in cached_backend:
            backend, sr = cached_backend[fname]
        else:
            backend = DetourBackend(fname)
            sr = StackRetEncryption(fname, backend)
            cached_backend[fname] = backend, sr

        print tbin, hex(addr), is_tail, ecx_free, edx_free
        res = sr.is_reg_free(addr,"ecx",is_tail,debug=True)
        nose.tools.assert_equal(ecx_free,res)
        res = sr.is_reg_free(addr,"edx",is_tail,debug=True)
        nose.tools.assert_equal(edx_free,res)

    #import IPython; IPython.embed()


@add_fallback_strategy
def test_transmitprotection():
    def check_test(test):
        values,expected_crash = test
        tinput = "08048000\n00000005\n"
        tsize = 0
        for addr,size in values:
            tinput += "4347c%03x\n%08x\n"% (addr,size)
            tsize += size
        tinput += "08048000\n00000005\n"
        #print repr(tinput)
        #open("../../vm/shared/input","wb").write(tinput)
        res = Runner(patched_fname1,tinput,record_stdout=True)
        if expected_crash:
            nose.tools.assert_true(res.reg_vals!=None)
            nose.tools.assert_equal(res.reg_vals['eip'],0x8047ffb)
        else:
            nose.tools.assert_true(res.stdout.startswith("hello\n\x7fCGC\x01"))
            nose.tools.assert_true(res.stdout.endswith("\x7fCGC\x01"))
            #print repr(res.stdout)
            nose.tools.assert_equal(len(res.stdout),6+5+5+tsize)



    logging.getLogger("patcherex.techniques.TransmitProtection").setLevel("DEBUG")
    from patcherex.techniques.transmitprotection import TransmitProtection
    vulnerable_fname1 = os.path.join(bin_location, "tests/i386/patchrex/arbitrary_transmit_O0")
    vulnerable_fname2 = os.path.join(bin_location, "tests/i386/patchrex/arbitrary_transmit_stdin_O0")

    res = Runner(vulnerable_fname1,"08048000\n00000005\n",record_stdout=True)
    nose.tools.assert_equal(res.stdout,"hello\n\x7fCGC\x01")
    res = Runner(vulnerable_fname1,"08048000\n00000005\n4347c000\n0000000a\n",record_stdout=True)
    nose.tools.assert_true(res.stdout.startswith("hello\n\x7fCGC\x01"))
    nose.tools.assert_equal(len(res.stdout),15+4+2)

    for nslot in [8,16,32,100,1000]:
        print "nlslot:",nslot
        with patcherex.utils.tempdir() as td:
            patched_fname1 = os.path.join(td, "patched1")
            backend = DetourBackend(vulnerable_fname1,global_data_fallback,try_pdf_removal=global_try_pdf_removal)
            cp = TransmitProtection(vulnerable_fname1, backend)
            cp.nslot=nslot
            patches = cp.get_patches()
            backend.apply_patches(patches)
            backend.save(patched_fname1)

            patched_fname2 = os.path.join(td, "patched2")
            backend = DetourBackend(vulnerable_fname2,global_data_fallback,try_pdf_removal=global_try_pdf_removal)
            cp = TransmitProtection(vulnerable_fname2, backend)
            cp.nslot=nslot
            patches = cp.get_patches()
            backend.apply_patches(patches)
            backend.save(patched_fname2)
            #backend.save("../../vm/shared/patched")
            base = "08048000\n00000005\n"

            res = Runner(patched_fname1,"08048000\n00000005\n",record_stdout=True)
            nose.tools.assert_equal(res.stdout,"hello\n\x7fCGC\x01")
            res = Runner(patched_fname1,base+"4347c000\n0000000a\n",record_stdout=True)
            nose.tools.assert_true(res.stdout.startswith("hello\n\x7fCGC\x01"))
            nose.tools.assert_equal(len(res.stdout),11)
            nose.tools.assert_equal(res.reg_vals['eip'],0x08047ffc)

            res = Runner(patched_fname2,"08048000\n00000005\n",record_stdout=True)
            nose.tools.assert_equal(res.stdout,"hello\n\x7fCGC\x01")
            res = Runner(patched_fname2,base+"4347c000\n0000000a\n",record_stdout=True)
            nose.tools.assert_true(res.stdout.startswith("hello\n\x7fCGC\x01"))
            nose.tools.assert_equal(len(res.stdout),11)
            nose.tools.assert_equal(res.reg_vals['eip'],0x08047ffc)

            res = Runner(patched_fname1,base+"4347bfff\n00000004\n08048000\n00000005\n",record_stdout=True)
            nose.tools.assert_equal(res.stdout,"hello\n\x7fCGC\x01\x7fCGC\x01")
            res = Runner(patched_fname1,base+"4347bfff\n00000001\n08048000\n00000005\n",record_stdout=True)
            nose.tools.assert_equal(res.stdout,"hello\n\x7fCGC\x01\x7fCGC\x01")
            res = Runner(patched_fname1,base+"4347d000\n00000005\n08048000\n00000005\n",record_stdout=True)
            nose.tools.assert_equal(res.stdout,"hello\n\x7fCGC\x01\x7fCGC\x01")

            res = Runner(patched_fname1,base+"4347c000\n00000004\n08048000\n00000005\n",record_stdout=True)
            nose.tools.assert_true(res.stdout.startswith("hello\n\x7fCGC\x01"))
            nose.tools.assert_equal(len(res.stdout),11)

            res = Runner(patched_fname1,base+"4347c000\n00000000\n08048000\n00000005\n",record_stdout=True)
            nose.tools.assert_true(res.stdout.startswith("hello\n\x7fCGC\x01"))
            nose.tools.assert_equal(len(res.stdout),16+0)
            res = Runner(patched_fname1,base+"4347c000\n00000001\n08048000\n00000005\n",record_stdout=True)
            nose.tools.assert_true(res.stdout.startswith("hello\n\x7fCGC\x01"))
            nose.tools.assert_equal(len(res.stdout),16+1)
            res = Runner(patched_fname1,base+"4347c000\n00000002\n08048000\n00000005\n",record_stdout=True)
            nose.tools.assert_true(res.stdout.startswith("hello\n\x7fCGC\x01"))
            nose.tools.assert_equal(len(res.stdout),16+2)
            res = Runner(patched_fname1,base+"4347c000\n00000003\n08048000\n00000005\n",record_stdout=True)
            nose.tools.assert_true(res.stdout.startswith("hello\n\x7fCGC\x01"))
            nose.tools.assert_equal(len(res.stdout),16+3)

            complex_tests = [
                (((0,1),(1,1),(2,1),(3,1)),True),
                (((0,1),(1,1),(2,1),(2,1)),False),
                (((0,3),),False),
                (((0,3),(1,1)),False),
                (((0,3),(3,1)),True),
                (((0,3),(4,1)),False),
                ([(0,3)]*2+[(3,1)],True),
                ([(0,3)]*20+[(3,1)],True),
                (((10,1),(11,1),(13,1),(22,1),(23,1),(24,1),(20,1),(100,1),(13,1),(12,1)),True),
                ([(i,1) for i in xrange(100,200,2)]+[(0,3)]+[(3,1)],True),
                ([(i,1) for i in xrange(100,150,2)]+[(0,3)]+[(i,1) for i in xrange(100,150,2)]+[(10,3)]+[(13,1)],True),
                ([(i,1) for i in xrange(100,150,2)]+[(0,3)]+[(i,1) for i in xrange(100,150,2)]+ \
                        [(1000,1)]+[(10,3)]+[(13,1)],True),
                ([(i,1) for i in xrange(100,150,2)]+[(0,3)]+[(i,1) for i in xrange(100,150,2)]+ \
                        [(1000,1)]+[(10,3)]+[(13,1)]+[(i,3) for i in xrange(1000,1100,4)]+[(2000,3)],True),
                ([(i,1) for i in xrange(100,150,2)]+[(0,3)]+[(i,1) for i in xrange(100,150,2)]+ \
                        [(1000,1)]+[(10,2)]+[(13,1)]+[(i,3) for i in xrange(1000,1100,4)]+[(2000,3)],False)
            ]
            complex_tests += [(list(reversed(l)),r) for l,r in complex_tests]
            for test in complex_tests:
                check_test(test)


@add_fallback_strategy
def test_shiftstack():
    logging.getLogger("patcherex.techniques.ShiftStack").setLevel("DEBUG")
    from patcherex.techniques.shiftstack import ShiftStack
    filepath = os.path.join(bin_location, "cfe_original/CROMU_00044/CROMU_00044")
    tinput = "1\n"*50+"2\n"*50

    res = Runner(filepath,tinput,record_stdout=True)
    original_output = res.stdout

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")

        backend = DetourBackend(filepath,global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        cp = ShiftStack(filepath, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)
        # backend.save("../../vm/shared/patched")
        res = Runner(tmp_file,tinput,record_stdout=True)
        nose.tools.assert_equal(original_output, res.stdout)

        backend = DetourBackend(filepath,global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        backend.apply_patches([InsertCodePatch(0x804db6b,"jmp 0x11223344")])
        backend.save(tmp_file)
        res = Runner(tmp_file,tinput,record_stdout=True)
        original_reg_value = res.reg_vals
        nose.tools.assert_equal(original_reg_value['eip'], 0x11223344)

        random_stack_pos = set()
        for _ in xrange(6):
            backend = DetourBackend(filepath,global_data_fallback,try_pdf_removal=global_try_pdf_removal)
            cp = ShiftStack(filepath, backend)
            patches = cp.get_patches()
            backend.apply_patches(patches+[InsertCodePatch(0x804db6b,"jmp 0x11223344")])
            backend.save(tmp_file)
            res = Runner(tmp_file,tinput,record_stdout=True,seed=random.randint(0,1000000000))
            oesp = original_reg_value['esp']
            nesp = res.reg_vals['esp']
            random_stack_pos.add(nesp)
            print hex(nesp),hex(oesp)
            nose.tools.assert_true(oesp-pow(2,cp.max_value_pow)<=nesp<=oesp-pow(2,cp.min_value_pow))
            original_reg_value_mod = dict(original_reg_value)
            original_reg_value_mod.pop('esp')
            res.reg_vals.pop('esp')
            original_reg_value_mod.pop('eflags')
            res.reg_vals.pop('eflags')
            nose.tools.assert_equal(original_reg_value_mod, res.reg_vals)
        print map(hex,random_stack_pos)
        nose.tools.assert_true(len(random_stack_pos)>=2)


@add_fallback_strategy
def test_adversarial():
    logging.getLogger("patcherex.techniques.Adversarial").setLevel("DEBUG")
    from patcherex.techniques.adversarial import Adversarial
    pipe = subprocess.PIPE
    tinput = "1\n"*50+"2\n"*50
    filepath = os.path.join(bin_location, "cfe_original/CROMU_00044/CROMU_00044")

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        cp = Adversarial(filepath, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)
        # backend.save("/tmp/adv")

        original_p = subprocess.Popen([qemu_location, filepath], stdin=pipe, stdout=pipe, stderr=pipe)
        original_res = original_p.communicate(tinput)
        patched_p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        patched_res = patched_p.communicate(tinput)

        nose.tools.assert_equal(original_res[0],patched_res[0])
        nose.tools.assert_equal(original_p.returncode,patched_p.returncode)
        # stderr is different since we leak the flag page there
        nose.tools.assert_true(original_res[1] != patched_res[1])


@add_fallback_strategy
def test_backdoor():
    def solution_to_str(l):
        # deal with endianness craziness
        return "".join(map(chr,[l[3],l[2],l[1],l[0],0,0,0,l[4]]))

    from patcherex.techniques.backdoor import Backdoor
    filepath = os.path.join(bin_location, "cfe_original/CADET_00003/CADET_00003")
    real_backdoor_enter = "3367b180".decode('hex')
    fake_backdoor_enter = "3367b181".decode('hex')
    logging.getLogger('povsim').setLevel("DEBUG")
    custom_bins = [os.path.join(bin_location,os.path.join("tests/i386/patchrex","backdoorme"+str(i))) \
            for i in xrange(1,9+1)]
    bins = [filepath] + custom_bins

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        cp = Backdoor(filepath, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)
        #backend.save("../../vm/shared/patched")

        # test with short and long strings is we destroid original functionality
        # last test is supposed to fail
        tests = ["A","A"*10,real_backdoor_enter[:3],real_backdoor_enter[:3]+"A"*10,
                "\n"*10,real_backdoor_enter[:3]+"A"*10,real_backdoor_enter+"\n"*10]
        for index,tinput in enumerate(tests):
            res = Runner(filepath,tinput,record_stdout=True)
            original_behavior = res.stdout, res.returncode
            res = Runner(tmp_file,tinput,record_stdout=True)
            patched_behavior = res.stdout, res.returncode
            if index != len(tests)-1:
                nose.tools.assert_equal(original_behavior,patched_behavior)
            else:
                nose.tools.assert_true(original_behavior != patched_behavior)

        # test some hardcoded values for the real backdoor
        tests = [   (0x12345678,0x99abcdef,1,[0x00,0xd0,0xb0,0xfd,0xdd]),
                    (0x00000000,0x00000000,2,[0x00,0x88,0x36,0xc1,0x23]),
                    (0xffffffff,0xffffffff,4,[0x01,0x7a,0x09,0x53,0xa8]),
                    (0xffffffff,0xffffffff,4,[0x00,0x7a,0x09,0x53,0xa8])]
        # the last test should fail
        for index, (ebx, eip, seed, solution) in enumerate(tests):
            tinput = real_backdoor_enter+solution_to_str(solution)
            tinput += struct.pack("<I",ebx)
            tinput += struct.pack("<I",eip)
            # fp = open("../../vm/shared/tinput","wb")
            # fp.write(tinput)
            # fp.close()
            res = Runner(tmp_file,tinput,record_stdout=True,seed=seed)
            if index != len(tests)-1:
                nose.tools.assert_equal(res.reg_vals['eip'],eip)
                nose.tools.assert_equal(res.reg_vals['ebx'],ebx)
            else:
                # no crash, the backdoor failed
                nose.tools.assert_equal(res.reg_vals,None)

        # test the fake backdoor
        ebx_vals = set()
        eip_vals = set()
        ntests = 3
        # apparently seed 0 and 1 generate the same randomness
        for index in xrange(1,1+ntests):
            tinput = fake_backdoor_enter + "a"*16
            # fp = open("../../vm/shared/tinput","wb")
            # fp.write(tinput)
            # fp.close()
            res = Runner(tmp_file,tinput,record_stdout=True,seed=index)
            eip_vals.add(res.reg_vals['eip'])
            ebx_vals.add(res.reg_vals['ebx'])
        # check that ebx and eip are actually randomixzed by the fake backdoor
        nose.tools.assert_equal(len(eip_vals),ntests)
        nose.tools.assert_equal(len(ebx_vals),ntests)

        for index,tbin in enumerate(bins):
            tmp_file = os.path.join(td, "patched")
            backend = DetourBackend(tbin,global_data_fallback,try_pdf_removal=global_try_pdf_removal)
            cp = Backdoor(tbin, backend)
            patches = cp.get_patches()
            backend.apply_patches(patches)
            backend.save(tmp_file)
            # backend.save("../../vm/shared/patched")
            pov_tester = CGCPovSimulator()
            backdoor_pov_location = os.path.join(self_location_folder,"../backdoor_stuff/backdoor_pov")
            res = pov_tester.test_binary_pov(backdoor_pov_location,tmp_file)
            if index < len(bins)-2:
                if not res:
                    print "failed on:", os.path.basename(tbin)
                nose.tools.assert_true(res)
            else:
                # the last two are supposed to fail
                nose.tools.assert_equal(res,False)


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
    logging.getLogger("patcherex.techniques.Backdoor").setLevel("DEBUG")

    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()

