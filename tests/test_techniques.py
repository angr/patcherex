#!/usr/bin/env python

import os
import struct
import subprocess
import logging
import shutil
from functools import wraps
import tempfile
import random

import patcherex
from patcherex.patch_master import PatchMaster
from patcherex.backends.detourbackend import DetourBackend
from patcherex.backends.reassembler_backend import ReassemblerBackend
from patcherex.patches import *
from tracer import QEMURunner

l = logging.getLogger("patcherex.test.test_techniques_detourbackend")

try:
    import shellphish_qemu
    qemu_location = shellphish_qemu.qemu_path('cgc-tracer')
except ImportError:
    l.warning("Cannot import shellphish_qemu. Patched binaries will not be tested.")
    qemu_location = None

try:
    from povsim import CGCPovSimulator
except ImportError:
    l.warning("Cannot import povsim. Patched binaries will not be tested.")

from patcherex.techniques.shadowstack import ShadowStack
from patcherex.techniques.packer import Packer
from patcherex.techniques.simplecfi import SimpleCFI
from patcherex.techniques.qemudetection import QemuDetection
from patcherex.techniques.randomsyscallloop import RandomSyscallLoop
from patcherex.techniques.cpuid import CpuId
from patcherex.techniques.stackretencryption import StackRetEncryption
from patcherex.techniques.indirectcfi import IndirectCFI
from patcherex.techniques.stackretencryption import StackRetEncryption
from patcherex.techniques.transmitprotection import TransmitProtection
from patcherex.techniques.shiftstack import ShiftStack
from patcherex.techniques.nxstack import NxStack
from patcherex.techniques.shiftstack import ShiftStack
from patcherex.techniques.adversarial import Adversarial
from patcherex.techniques.backdoor import Backdoor
from patcherex.techniques.bitflip import Bitflip
from patcherex.techniques.backdoor import Backdoor
from patcherex.techniques.uninitialized_patcher import UninitializedPatcher
from patcherex.techniques.malloc_ext_patcher import MallocExtPatcher
from patcherex.techniques.noflagprintf import NoFlagPrintfPatcher
from patcherex.techniques.countdown import Countdown

# TODO ideally these tests should be run in the vm

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../test_binaries'))
poll_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'polls'))
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


def make_edible(cls):
    def args_eat(*args,**kwargs):
        return cls(args[0])
    return args_eat


def try_reassembler_and_detour(f):
    @wraps(f)
    def wrapper():
        f(make_edible(ReassemblerBackend), None, True)
        f(DetourBackend, None, True)

    return wrapper


def try_reassembler_and_detour_full(f):
    @wraps(f)
    def wrapper():
        f(make_edible(ReassemblerBackend), None, True)
        f(DetourBackend, None, True)
        f(DetourBackend, True, True)
        f(DetourBackend, None, False)
        f(DetourBackend, True, False)
    return wrapper


def add_fallback_strategy(f):
    @wraps(f)
    def wrapper():
        f(DetourBackend, None, True)
        f(DetourBackend, None, False)
        f(DetourBackend, True, False)
    return wrapper


def reassembler_only(f):
    @wraps(f)
    def wrapper():
        f(make_edible(ReassemblerBackend), None, True)
    return wrapper


def detour_only(f):
    @wraps(f)
    def wrapper():
        f(DetourBackend, None, True)
    return wrapper

@add_fallback_strategy
def test_shadowstack(BackendClass, data_fallback, try_pdf_removal):
    filepath = os.path.join(bin_location, "CADET_00003")
    pipe = subprocess.PIPE

    p = subprocess.Popen([qemu_location, filepath], stdin=pipe, stdout=pipe, stderr=pipe)
    res = p.communicate(b"\x00" * 1000 + b"\n")
    print(res, p.returncode)
    assert p.returncode == -11

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = BackendClass(filepath,data_fallback,try_pdf_removal=try_pdf_removal)
        cp = ShadowStack(filepath, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)

        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"\x00" * 100 + b"\n")
        print(res, p.returncode)
        assert p.returncode == 68


@add_fallback_strategy
def test_packer(BackendClass, data_fallback, try_pdf_removal):
    filepath = os.path.join(bin_location, "CADET_00003")
    pipe = subprocess.PIPE

    expected = b"\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \t\tYes, that's a palindrome!\n\n\tPlease enter a possible palindrome: "
    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = BackendClass(filepath,data_fallback,try_pdf_removal=try_pdf_removal)
        cp = Packer(filepath, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)

        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"A" * 10 + b"\n")
        print(res, p.returncode)
        assert res[0] == expected and p.returncode == 0


@add_fallback_strategy
def test_simplecfi(BackendClass, data_fallback, try_pdf_removal):
    filepath = os.path.join(bin_location, "0b32aa01_01_2")
    pipe = subprocess.PIPE

    p = subprocess.Popen([qemu_location, filepath], stdin=pipe, stdout=pipe, stderr=pipe)
    res = p.communicate(b"\x00" * 1000 + b"\n")
    print(res, p.returncode)
    assert p.returncode == -11

    #0x80480a0 is the binary entry point
    exploiting_input = b"AAAA" + b"\x00"*80 + struct.pack("<I",0x80480a0)*20 + b"\n"
    expected1 = b"\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \t\tNope, that's not a palindrome\n\n\tPlease enter a possible palindrome: \nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: "

    p = subprocess.Popen([qemu_location, filepath], stdin=pipe, stdout=pipe, stderr=pipe)
    res = p.communicate(exploiting_input)
    expected_retcode = 1 #should be -11
    assert res[0][:200] == expected1[:200] and p.returncode == expected_retcode

    expected2 = b"\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \t\tYes, that's a palindrome!\n\n\tPlease enter a possible palindrome: "
    expected3 = b"\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: "
    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = BackendClass(filepath,data_fallback,try_pdf_removal=try_pdf_removal)
        cp = SimpleCFI(filepath, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)

        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"A" * 10 + b"\n")
        print(res, p.returncode)
        assert res[0] == expected2 and p.returncode == 0

        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(exploiting_input)
        print(res, p.returncode)
        assert res[0] == expected3 and p.returncode == 0x45


@add_fallback_strategy
def test_qemudetection(BackendClass, data_fallback, try_pdf_removal):
    filepath = os.path.join(bin_location, "0b32aa01_01_2")
    pipe = subprocess.PIPE

    p = subprocess.Popen([qemu_location, filepath], stdin=pipe, stdout=pipe, stderr=pipe)
    res = p.communicate(b"\x00" * 1000 + b"\n")
    print(res, p.returncode)
    assert p.returncode == -11

    expected = b"\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \t\tYes, that's a palindrome!\n\n\tPlease enter a possible palindrome: "
    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = BackendClass(filepath,data_fallback,try_pdf_removal=try_pdf_removal)
        cp = QemuDetection(filepath, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)

        p = subprocess.Popen([old_qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"A" * 10 + b"\n")
        print(res, p.returncode)
        assert p.returncode == 0x40 or p.returncode == 0x41

        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"A" * 10 + b"\n")
        print(res, p.returncode)
        assert res[0] == expected and p.returncode == 0


@add_fallback_strategy
def test_randomsyscallloop(BackendClass, data_fallback, try_pdf_removal):
    filepath = os.path.join(bin_location, "CADET_00003")
    pipe = subprocess.PIPE

    p = subprocess.Popen([qemu_location, filepath], stdin=pipe, stdout=pipe, stderr=pipe)
    res = p.communicate(b"\x00" * 1000 + b"\n")
    print(res, p.returncode)
    assert p.returncode == -11

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = BackendClass(filepath,data_fallback,try_pdf_removal=try_pdf_removal)
        cp = RandomSyscallLoop(filepath, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)

        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"\x00" * 100 + b"\n")
        print(res, p.returncode)
        assert res[0] == b"\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: "
        assert p.returncode == -11


@add_fallback_strategy
def test_cpuid(BackendClass, data_fallback, try_pdf_removal):
    filepath = os.path.join(bin_location, "CADET_00003")
    pipe = subprocess.PIPE

    p = subprocess.Popen([qemu_location, filepath], stdin=pipe, stdout=pipe, stderr=pipe)
    res = p.communicate(b"\x00" * 1000 + b"\n")
    print(res, p.returncode)
    assert p.returncode == -11

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = BackendClass(filepath,data_fallback,try_pdf_removal=try_pdf_removal)
        cp = CpuId(filepath, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)

        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"\x00"*100 + b"\n")
        print(res, p.returncode)
        assert res[0].endswith(b"\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: ")
        assert len(res[0]) > 500
        assert p.returncode == -11


@reassembler_only
def test_stackretencryption(BackendClass, data_fallback, try_pdf_removal):
    filepath1 = os.path.join(bin_location, "0b32aa01_01_2")
    filepath2 = os.path.join(bin_location, "CROMU_00070")
    filepath3 = os.path.join(bin_location, "original/CROMU_00008")
    filepath4 = os.path.join(bin_location, "original/KPRCA_00026")
    filepath5 = os.path.join(bin_location, "original/KPRCA_00025")
    pipe = subprocess.PIPE

    '''
    p = subprocess.Popen([qemu_location, filepath1], stdin=pipe, stdout=pipe, stderr=pipe)
    res = p.communicate("\x00"*1000+"\n")
    print res, p.returncode
    assert p.returncode == -11
    '''

    #0x80480a0 is the binary entry point
    exploiting_input = b"AAAA" + b"\x00"*80 + struct.pack("<I",0x80480a0)*20 + b"\n"
    expected1 = b"\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: " \
            b"\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \t\tNope,"
    input3 = b'blogin\ninsert\na\na\na\n11/11/11 11:11:11\nfind\nusername <"xdDVRNBQTTrhqk" AND birthdate <6/9/1 20:33:47())\n\n'
    expected3 = b'> You logged in.\n> First name: Last name: User name: Birthdate (mm/dd/yy hh:mm:ss): Date ' \
        b'is: 11/11/2011 11:11:11\nData added, record 0\n> Enter search express (firstname or fn, lastname or ' \
        b'ln, username or un, birthdate or bd, operators ==, !=, >, <, AND and OR):\nSyntax error\n> Command' \
        b' not found.\n> '
    input4 = b"1\n2\n3\n4\n5\n6\n"*10
    input5 = b"a"*10 + b"\n"*10
    '''
    p = subprocess.Popen([qemu_location, filepath1], stdin=pipe, stdout=pipe, stderr=pipe)
    res = p.communicate(exploiting_input)
    print res, p.returncode
    assert p.returncode != -11
    assert res[0].startswith(expected1)
    '''

    expected2 = b"\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \t\tYes, that's a palindrome!\n\n\tPlease enter a possible palindrome: "
    with patcherex.utils.tempdir() as td:
        seed = str(random.randint(1,1000000000))
        original_file = os.path.join(td, "original")
        shutil.copy(filepath2,original_file)
        os.chmod(original_file,777)

        '''
        tmp_file = os.path.join(td, "patched1")
        backend = BackendClass(filepath1,data_fallback,try_pdf_removal=try_pdf_removal)
        cp = StackRetEncryption(filepath1, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)

        p = subprocess.Popen([qemu_location, "-seed", seed, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        assert res[0] == expected2 and p.returncode == 0
        seed = str(random.randint(0,1000000000))
        p = subprocess.Popen([qemu_location, "-seed", seed, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(exploiting_input)
        print res, p.returncode
        assert p.returncode == -11
        '''

        tmp_file = os.path.join(td, "patched2")
        backend = BackendClass(filepath2,data_fallback,try_pdf_removal=try_pdf_removal)
        cp = StackRetEncryption(filepath2, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)
        seed = str(random.randint(0,1000000000))
        p = subprocess.Popen([qemu_location, "-seed", seed, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"\x00\x01\x01" + b"A"*1000 + b"\n")
        print(res)
        sane_stdout, sane_retcode = res[0], p.returncode
        seed = str(random.randint(0,1000000000))
        p = subprocess.Popen([qemu_location, "-seed", seed, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"\x00\x01\x01" + b"A"*1000 + b"\n")
        print(res)
        assert res[0] == sane_stdout
        assert p.returncode == sane_retcode

        '''
        # setjmp/longjmp
        tmp_file = os.path.join(td, "patched3")
        backend = BackendClass(filepath3,data_fallback,try_pdf_removal=try_pdf_removal)
        cp = StackRetEncryption(filepath3, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)
        p = subprocess.Popen([qemu_location, "-seed", seed, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(input3)
        print res, p.returncode
        assert res[0] == expected3
        assert p.returncode == 1

        # setjmp/longjmp with cgrex
        tmp_file = os.path.join(td, "patched4")
        backend = BackendClass(filepath4,data_fallback,try_pdf_removal=try_pdf_removal)
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
        assert expected == patched
        '''

        ''' # TODO for now this is broken
        # function pointer blacklist
        tmp_file = os.path.join(td, "patched5")
        backend = BackendClass(filepath5,data_fallback,try_pdf_removal=try_pdf_removal)
        cp = StackRetEncryption(filepath5, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)
        # backend.save("/tmp/aaa")
        p = subprocess.Popen([qemu_location, "-seed", seed, filepath5], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(input5)
        expected = (res[0],p.returncode)
        p = subprocess.Popen([qemu_location, "-seed", seed, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(input5)
        patched = (res[0],p.returncode)
        print expected
        print patched
        assert expected == patched
        '''


@reassembler_only
def test_indirectcfi(BackendClass, data_fallback, try_pdf_removal):
    tests = [
        ("patchrex/indirect_call_test_O0", b"b7fff000"),
        #("patchrex/indirect_call_test_fullmem_O0", b"78000000"),
    ]
    if BackendClass == ReassemblerBackend:
        tests = tests[:1]

    for i, (tbin, addr_str) in enumerate(tests):
        vulnerable_fname1 = os.path.join(bin_location, tbin)
        if i==0: #do this only the first time
            res = QEMURunner(vulnerable_fname1, b"00000001\n", record_stdout=True)
            assert res.stdout == b"hello\nCGC"
            res = QEMURunner(vulnerable_fname1, b"00000002\n", record_stdout=True)
            assert res.stdout == b"hello\nCGC"
            res = QEMURunner(vulnerable_fname1, b"00000003\n", record_stdout=True)
            assert res.stdout == b"hello\nCGC"

            '''
            res = QEMURunner(vulnerable_fname1,"00000001\n23456789\n",record_stdout=True)
            assert res.reg_vals['eip'] == x23456789
            res = QEMURunner(vulnerable_fname1,"00000002\n43456789\n",record_stdout=True)
            assert res.reg_vals['eip'] == 0x43456789
            res = QEMURunner(vulnerable_fname1,"00000003\n53456789\n",record_stdout=True)
            assert res.reg_vals['eip'] == 0x53456789
            res = QEMURunner(vulnerable_fname1,"00000004\n63456789\n",record_stdout=True)
            assert res.reg_vals['eip'] == 0x63456789

            res = QEMURunner(vulnerable_fname1,"00000001\n08048640\n",record_stdout=True)
            print {k:hex(v) for k,v in res.reg_vals.iteritems()}
            assert res.reg_vals['ebp'] & 0xfffff000 == 0x08048000
            assert res.reg_vals['eip'] == 0x0
            res = QEMURunner(vulnerable_fname1,"00000002\n08048640\n",record_stdout=True)
            print {k:hex(v) for k,v in res.reg_vals.iteritems()}
            assert res.reg_vals['ebp'] & 0xfffff000 == 0x08048000
            assert res.reg_vals['eip'] == 0x0
            res = QEMURunner(vulnerable_fname1,"00000003\n08048640\n",record_stdout=True)
            print {k:hex(v) for k,v in res.reg_vals.iteritems()}
            assert res.reg_vals['ebp'] & 0xfffff000 == 0x08048000
            assert res.reg_vals['eip'] == 0x0
            res = QEMURunner(vulnerable_fname1,"00000004\n08048640  \n",record_stdout=True)
            print {k:hex(v) for k,v in res.reg_vals.iteritems()}
            assert res.reg_vals['ebp'] & 0xfffff000 == 0x08048000
            assert res.reg_vals['eip'] == 0x30303030
            '''

            res = QEMURunner(vulnerable_fname1, b"00000001\n" + addr_str + b"\n", record_stdout=True)
            assert res.stdout == b"hello\nCGCCGCCGC"
            res = QEMURunner(vulnerable_fname1, b"00000001\nbaaaa000\n", record_stdout=True)
            assert res.stdout == b"hello\nCGCCGCCGC"
            res = QEMURunner(vulnerable_fname1, b"00000001\n" + addr_str + b"\n", record_stdout=True)
            assert res.stdout == b"hello\nCGCCGCCGC"
            res = QEMURunner(vulnerable_fname1, b"00000002\nbaaaa000\n", record_stdout=True)
            assert res.stdout == b"hello\nCGCCGCCGC"
            '''
            res = QEMURunner(vulnerable_fname1,"00000002\n"+addr_str+"\n",record_stdout=True)
            assert res.stdout == "hello\nCGCCGCCGC"
            res = QEMURunner(vulnerable_fname1,"00000002\nbaaaa000\n",record_stdout=True)
            assert res.stdout == "hello\nCGCCGCCGC"
            res = QEMURunner(vulnerable_fname1,"00000003\n"+addr_str+"\n",record_stdout=True)
            assert res.stdout == "hello\nCGCCGCCGC"
            res = QEMURunner(vulnerable_fname1,"00000003\nbaaaa000\n",record_stdout=True)
            assert res.stdout == "hello\nCGCCGCCGC"
            res = QEMURunner(vulnerable_fname1,"00000003\n"+addr_str+"\n",record_stdout=True)
            assert res.stdout == "hello\nCGCCGCCGC"
            res = QEMURunner(vulnerable_fname1,"00000004\nbaaaa000\n",record_stdout=True)
            assert res.stdout == "hello\nCGC"
            res = QEMURunner(vulnerable_fname1,"00000004\nbaaaa000\n",record_stdout=True)
            assert res.stdout == "hello\nCGC"
            res = QEMURunner(vulnerable_fname1,"00000004\nbaaaa000\n",record_stdout=True)
            assert res.stdout == "hello\nCGC"
            '''

        with patcherex.utils.tempdir() as td:
            patched_fname1 = os.path.join(td, "patched")
            backend = BackendClass(vulnerable_fname1,data_fallback,try_pdf_removal=try_pdf_removal)
            cp = IndirectCFI(vulnerable_fname1, backend)
            patches = cp.get_patches()
            backend.apply_patches(patches)
            backend.save(patched_fname1)
            # backend.save("/tmp/aaa")
            res = QEMURunner(patched_fname1, b"00000001\n",record_stdout=True)
            assert res.stdout == b"hello\nCGC"

            if i==0:
                res = QEMURunner(patched_fname1,
                                 b"00000001\n23456789\n",
                                 record_stdout=True,
                                 record_core=True)
                assert res.stdout == b"hello\nCGC"
                print(hex(res.reg_vals['eip']))
                assert res.reg_vals['eip'] != 0x23456789
                # res = QEMURunner(patched_fname1,"00000002\n23456789\n",record_stdout=True)
                # assert res.stdout == "hello\nCGC"
                # print hex(res.reg_vals['eip'])
                # assert res.reg_vals['eip'] != 0x23456789
                # res = QEMURunner(patched_fname1,"00000003\n23456789\n",record_stdout=True)
                # assert res.stdout == "hello\nCGC"
                # print hex(res.reg_vals['eip'])
                # assert res.reg_vals['eip'] != 0x23456789
                res = QEMURunner(patched_fname1,
                                 b"00000004\n23456789\n",
                                 record_stdout=True,
                                 record_core=True)
                assert res.stdout == b"hello\n"
                print(hex(res.reg_vals['eip']))
                assert res.reg_vals['eip'] != 0x23456789

            #main: 08048620, stack: baaaa000, heap: "+addr_str+"
            #main -> heap
            res = QEMURunner(patched_fname1,
                             b"00000001\n" + bytes(addr_str) + b"\n",
                             record_stdout=True,
                             record_core=True)
            assert res.stdout == b"hello\nCGC"
            print(hex(res.reg_vals['eip']))
            assert res.reg_vals['eip'] == 0x8047333
            #main -> stack
            res = QEMURunner(patched_fname1,
                             b"00000001\nbaaaa000\n",
                             record_stdout=True,
                             record_core=True)
            assert res.stdout == b"hello\nCGC"
            print(hex(res.reg_vals['eip']))
            assert res.reg_vals['eip'] == 0x8047333
            #main -> main
            res = QEMURunner(patched_fname1,
                             b"00000001\n08048000\n",
                             record_stdout=True,
                             record_core=True)
            assert res.reg_vals['eip'] == 0x08048004

            #stack -> main
            '''
            res = QEMURunner(patched_fname1,"00000002\n08048620\n",record_stdout=True)
            assert res.stdout == "hello\nCGC"
            print hex(res.reg_vals['eip'])
            assert res.reg_vals['eip'] == 0x8047333
            '''
            '''
            #stack -> heap
            res = QEMURunner(patched_fname1,"00000002\n"+addr_str+"\n",record_stdout=True)
            assert res.stdout == "hello\nCGC"
            print hex(res.reg_vals['eip'])
            assert res.reg_vals['eip'] == 0x8047333
            #stack -> stack
            res = QEMURunner(patched_fname1,"00000002\nbaaaa000\n",record_stdout=True)
            assert res.stdout =="hello\nCGCCGCCGC"
            assert res.reg_vals is None
            '''

            #heap -> main
            '''
            res = QEMURunner(patched_fname1,"00000003\n08048620\n",record_stdout=True)
            assert res.stdout == "hello\nCGC"
            print hex(res.reg_vals['eip'])
            assert res.reg_vals['eip'] == 0x8047333
            '''
            '''
            #heap -> stack
            res = QEMURunner(patched_fname1,"00000003\nbaaaa000\n",record_stdout=True)
            assert res.stdout == "hello\nCGC"
            print hex(res.reg_vals['eip'])
            assert res.reg_vals['eip'] == 0x8047333
            '''
            #heap -> heap
            '''
            res = QEMURunner(patched_fname1,"00000003\n"+addr_str+"\n",record_stdout=True)
            assert res.stdout == "hello\nCGCCGCCGC"
            assert res.reg_vals is None
            '''

            #unknown -> main
            res = QEMURunner(patched_fname1,
                             b"00000001\n08048000\n",
                             record_stdout=True,
                             record_core=True)
            assert res.reg_vals['eip'] == 0x08048004

            '''
            #unknown -> stack
            res = QEMURunner(patched_fname1,"00000004\nbaaaa000\n",record_stdout=True)
            assert res.stdout == "hello\nCGC"
            assert res.reg_vals is None
            '''
            #unknown -> heap
            '''
            res = QEMURunner(patched_fname1,"00000004\n"+addr_str+"\n",record_stdout=True)
            assert res.stdout == "hello\nCGC"
            assert res.reg_vals is None
            '''

            # call gadget
            '''
            if i == 0 and BackendClass != ReassemblerBackend:
                gadget_addr = "08048971"
                res = QEMURunner(patched_fname1,"00000001\n"+gadget_addr+"\n",record_stdout=True)
                assert res.reg_vals['eip'] == 0x8047332
                # res = QEMURunner(patched_fname1,"00000002\n08048640\n",record_stdout=True)
                # assert res.reg_vals['eip'] == 0x8047332
                # res = QEMURunner(patched_fname1,"00000003\n08048640\n",record_stdout=True)
                # assert res.reg_vals['eip'] == 0x8047332
                res = QEMURunner(patched_fname1,"00000004\n"+gadget_addr+"\n",record_stdout=True)
                assert res.reg_vals['eip'] == 0x8047332

                patched_fname2 = os.path.join(td, "patched2")
                backend = BackendClass(vulnerable_fname1+"_exec_allocate",data_fallback,\
                        try_pdf_removal=try_pdf_removal)
                cp = IndirectCFI(vulnerable_fname1+"_exec_allocate", backend)
                patches = cp.get_patches()
                backend.apply_patches(patches)
                backend.save(patched_fname2)
                # backend.save("/tmp/aaa")

                res = QEMURunner(patched_fname1,"00000001\n"+"b7fff000"+"\n",record_stdout=True)
                assert res.reg_vals['eip'] != 0xb7fff000
                res = QEMURunner(patched_fname2,"00000001\n"+"b7fff000"+"\n",record_stdout=True)
                assert res.reg_vals['eip'] == 0xb7fff000 #because we detect executable allocate memory
            '''


def test_freeregs():
    def bin_str(name,btype="original"):
        return "%s/%s" % (btype,name)

    tests = [
            (bin_str("CADET_00003"),0x08048400,False,True,True),
            (bin_str("CADET_00003"),0x0804860C,False,True,True),
            #(bin_str("KPRCA_00038"),0x0804C070,False,False,False),
            #(bin_str("KPRCA_00038"),0x0804B390,False,False,False),
            #(bin_str("KPRCA_00038"),0x0804AC20,False,True,True),
            #(bin_str("KPRCA_00038"),0x0804AAD0,False,True,False),
            (bin_str("CROMU_00012"),0x080498B4,True,False,False),
            (bin_str("CROMU_00012"),0x08048650,False,True,False),
            #(bin_str("NRFIN_00026"),0x083BA7e0,False,True,True),
            #(bin_str("NRFIN_00026"),0x0897F4D5,True,False,False),
            #(bin_str("CROMU_00008","Ofast"),0x804A7F0,False,True,False),
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

        print(tbin, hex(addr), is_tail, ecx_free, edx_free)
        res = sr.is_reg_free(addr,"ecx",is_tail,debug=True)
        assert ecx_free == res
        res = sr.is_reg_free(addr,"edx",is_tail,debug=True)
        assert edx_free == res

    #import IPython; IPython.embed()


@reassembler_only
def test_transmitprotection(BackendClass, data_fallback, try_pdf_removal):
    def check_test(test):
        values,expected_crash = test
        tinput = b"08048000\n00000005\n"
        tsize = 0
        for addr, size in values:
            tinput += b"4347c%03x\n%08x\n" % (addr, size)
            tsize += size
        tinput += b"08048000\n00000005\n"
        #print repr(tinput)
        #open("../../vm/shared/input","wb").write(tinput)
        res = QEMURunner(patched_fname1, tinput, record_stdout=True, record_core=True)
        if expected_crash:
            assert res.reg_vals!=None
            assert res.reg_vals['eip'] == 0x8047ffb
        else:
            assert res.stdout.startswith(b"hello\n\x7fCGC\x01")
            assert res.stdout.endswith(b"\x7fCGC\x01")
            #print repr(res.stdout)
            assert len(res.stdout) == 6+5+5+tsize

    vulnerable_fname1 = os.path.join(bin_location, "patchrex/arbitrary_transmit_O0")
    vulnerable_fname2 = os.path.join(bin_location, "patchrex/arbitrary_transmit_stdin_O0")

    res = QEMURunner(vulnerable_fname1, b"08048000\n00000005\n", record_stdout=True)
    assert res.stdout == b"hello\n\x7fCGC\x01"
    res = QEMURunner(vulnerable_fname1, b"08048000\n00000005\n4347c000\n0000000a\n", record_stdout=True)
    assert res.stdout.startswith(b"hello\n\x7fCGC\x01")
    assert len(res.stdout) == 15+4+2

    for nslot in [8,16,32,100,1000]:
        print("nlslot:", nslot)
        with patcherex.utils.tempdir() as td:
            patched_fname1 = os.path.join(td, "patched1")
            backend = BackendClass(vulnerable_fname1,data_fallback,try_pdf_removal=try_pdf_removal)
            cp = TransmitProtection(vulnerable_fname1, backend)
            cp.nslot=nslot
            patches = cp.get_patches()
            backend.apply_patches(patches)
            backend.save(patched_fname1)

            patched_fname2 = os.path.join(td, "patched2")
            backend = BackendClass(vulnerable_fname2,data_fallback,try_pdf_removal=try_pdf_removal)
            cp = TransmitProtection(vulnerable_fname2, backend)
            cp.nslot=nslot
            patches = cp.get_patches()
            backend.apply_patches(patches)
            backend.save(patched_fname2)
            #backend.save("../../vm/shared/patched")
            base = b"08048000\n00000005\n"

            res = QEMURunner(patched_fname1, b"08048000\n00000005\n",record_stdout=True)
            assert res.stdout == b"hello\n\x7fCGC\x01"
            res = QEMURunner(patched_fname1,
                             base + b"4347c000\n0000000a\n",
                             record_stdout=True,
                             record_core=True)
            assert res.stdout.startswith(b"hello\n\x7fCGC\x01")
            assert len(res.stdout) == 11
            assert res.reg_vals['eip'] == 0x08047ffc

            res = QEMURunner(patched_fname2, b"08048000\n00000005\n",record_stdout=True)
            assert res.stdout == b"hello\n\x7fCGC\x01"
            res = QEMURunner(patched_fname2,
                             base + b"4347c000\n0000000a\n",
                             record_stdout=True,
                             record_core=True)
            assert res.stdout.startswith(b"hello\n\x7fCGC\x01")
            assert len(res.stdout)==11
            assert res.reg_vals['eip'] == 0x08047ffc

            res = QEMURunner(patched_fname1, base + b"4347bfff\n00000004\n08048000\n00000005\n", record_stdout=True)
            assert res.stdout == b"hello\n\x7fCGC\x01\x7fCGC\x01"
            res = QEMURunner(patched_fname1, base + b"4347bfff\n00000001\n08048000\n00000005\n", record_stdout=True)
            assert res.stdout == b"hello\n\x7fCGC\x01\x7fCGC\x01"
            res = QEMURunner(patched_fname1, base + b"4347d000\n00000005\n08048000\n00000005\n", record_stdout=True)
            assert res.stdout == b"hello\n\x7fCGC\x01\x7fCGC\x01"

            res = QEMURunner(patched_fname1, base + b"4347c000\n00000004\n08048000\n00000005\n", record_stdout=True)
            assert res.stdout.startswith(b"hello\n\x7fCGC\x01")
            assert len(res.stdout) == 11

            res = QEMURunner(patched_fname1, base + b"4347c000\n00000000\n08048000\n00000005\n", record_stdout=True)
            assert res.stdout.startswith(b"hello\n\x7fCGC\x01")
            assert len(res.stdout) == 16 + 0
            res = QEMURunner(patched_fname1, base + b"4347c000\n00000001\n08048000\n00000005\n", record_stdout=True)
            assert res.stdout.startswith(b"hello\n\x7fCGC\x01")
            assert len(res.stdout) == 16 + 1
            res = QEMURunner(patched_fname1, base + b"4347c000\n00000002\n08048000\n00000005\n", record_stdout=True)
            assert res.stdout.startswith(b"hello\n\x7fCGC\x01")
            assert len(res.stdout) == 16 + 2
            res = QEMURunner(patched_fname1, base + b"4347c000\n00000003\n08048000\n00000005\n", record_stdout=True)
            assert res.stdout.startswith(b"hello\n\x7fCGC\x01")
            assert len(res.stdout) == 16 + 3

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
                ([(i,1) for i in range(100,200,2)]+[(0,3)]+[(3,1)],True),
                ([(i,1) for i in range(100,150,2)]+[(0,3)]+[(i,1) for i in range(100,150,2)]+[(10,3)]+[(13,1)],True),
                ([(i,1) for i in range(100,150,2)]+[(0,3)]+[(i,1) for i in range(100,150,2)]+ \
                        [(1000,1)]+[(10,3)]+[(13,1)],True),
                ([(i,1) for i in range(100,150,2)]+[(0,3)]+[(i,1) for i in range(100,150,2)]+ \
                        [(1000,1)]+[(10,3)]+[(13,1)]+[(i,3) for i in range(1000,1100,4)]+[(2000,3)],True),
                ([(i,1) for i in range(100,150,2)]+[(0,3)]+[(i,1) for i in range(100,150,2)]+ \
                        [(1000,1)]+[(10,2)]+[(13,1)]+[(i,3) for i in range(1000,1100,4)]+[(2000,3)],False)
            ]
            complex_tests += [(list(reversed(l)),r) for l,r in complex_tests]
            for test in complex_tests:
                check_test(test)


@reassembler_only
def test_shiftstack(BackendClass, data_fallback, try_pdf_removal):
    filepath = os.path.join(bin_location, "CROMU_00044")
    tinput = b"1\n" * 50 + b"2\n" * 50

    res = QEMURunner(filepath,tinput,record_stdout=True)
    original_output = res.stdout

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")

        backend = BackendClass(filepath,data_fallback,try_pdf_removal=try_pdf_removal)
        cp = ShiftStack(filepath, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)
        res = QEMURunner(tmp_file,tinput,record_stdout=True)
        assert original_output == res.stdout

        backend = BackendClass(filepath,data_fallback,try_pdf_removal=try_pdf_removal)
        backend._debugging = True
        backend.apply_patches([InsertCodePatch(0x80487d0,"jmp 0x11223344")])
        backend.save(tmp_file)
        #backend.save("/tmp/aaa")
        res = QEMURunner(tmp_file,tinput, record_stdout=True, record_core=True)
        original_reg_value = res.reg_vals
        assert original_reg_value['eip'] == 0x11223344

        random_stack_pos = set()
        for _ in range(6):
            backend = BackendClass(filepath,data_fallback,try_pdf_removal=try_pdf_removal)
            cp = ShiftStack(filepath, backend)
            patches = cp.get_patches()
            backend.apply_patches(patches+[InsertCodePatch(0x80487d0,"jmp 0x11223344")])
            backend.save(tmp_file)
            res = QEMURunner(tmp_file,
                             tinput,
                             record_stdout=True,
                             record_core=True,
                             seed=random.randint(1,1000000000))
            oesp = original_reg_value['esp']
            nesp = res.reg_vals['esp']
            random_stack_pos.add(nesp)
            print(hex(nesp), hex(oesp))
            assert oesp-pow(2,cp.max_value_pow)<=nesp<=oesp-pow(2,cp.min_value_pow)
            original_reg_value_mod = dict(original_reg_value)
            original_reg_value_mod.pop('esp')
            res.reg_vals.pop('esp')
            original_reg_value_mod.pop('eflags')
            res.reg_vals.pop('eflags')
            assert original_reg_value_mod == res.reg_vals
        print(map(hex,random_stack_pos))
        assert len(random_stack_pos)>=2


@try_reassembler_and_detour_full # this changes the headers, let't test it in all 4 cases
def test_nxstack(BackendClass, data_fallback, try_pdf_removal):
    filepath = os.path.join(bin_location, "CROMU_00044")
    tinput = b"login\n" * 50 + b"2\n"*50
    res = QEMURunner(filepath,tinput,record_stdout=True)
    original_output = res.stdout

    with_stack_randomization = [False,True]
    for stack_randomization in with_stack_randomization:
        with patcherex.utils.tempdir() as td:
            tmp_file = os.path.join(td, "patched")

            '''
            backend = BackendClass(filepath,data_fallback,try_pdf_removal=try_pdf_removal)
            cp = NxStack(filepath, backend)
            patches = cp.get_patches()
            if stack_randomization:
                cp =  ShiftStack(filepath, backend)
                patches += cp.get_patches()
            backend.apply_patches(patches)
            backend.save(tmp_file)
            # backend.save("/tmp/aaa")
            # test that behaves like the original
            res = QEMURunner(tmp_file,tinput,record_stdout=True,seed=random.randint(1,1000000000))
            assert original_output == res.stdout

            # check if the stack is where we expect
            backend = BackendClass(filepath,data_fallback,try_pdf_removal=try_pdf_removal)
            cp = NxStack(filepath, backend)
            patches = cp.get_patches()
            if stack_randomization:
                cp =  ShiftStack(filepath, backend)
                patches += cp.get_patches()
            backend.apply_patches(patches+[InsertCodePatch(0x80487d0,"jmp 0x11223344")])
            backend.save(tmp_file)
            res = QEMURunner(tmp_file,tinput,record_stdout=True,seed=random.randint(1,1000000000))
            nesp = res.reg_vals['esp']
            assert 0xbaaab000 < nesp < 0xbaaac000
            '''

            # check if the stack is really not executable
            backend = BackendClass(filepath,data_fallback,try_pdf_removal=try_pdf_removal)
            cp = NxStack(filepath, backend)
            patches = cp.get_patches()
            if stack_randomization:
                cp =  ShiftStack(filepath, backend)
                patches += cp.get_patches()
            code = '''
                mov eax, 0x11223344
                push 0xabb0c031
                jmp esp
            '''
            backend.apply_patches(patches+[InsertCodePatch(0x80487d0,code)])
            backend.save(tmp_file)
            # backend.save("/tmp/aaa")
            # see: https://git.seclab.cs.ucsb.edu/cgc/qemu/issues/5
            res = QEMURunner(tmp_file,
                             tinput,
                             record_stdout=True,
                             record_core=True,
                             seed=random.randint(1,1000000000),
                             qemu=shellphish_qemu.qemu_path("cgc-nxtracer"))
            if res.reg_vals == None:
                assert res.returncode == 46
            else:
                assert 0xbaaab000 < res.reg_vals['eip'] < 0xbaaac000
                assert res.reg_vals['eax']!=0x000000ab

            '''
            # check if the stack is executable one page before
            backend = BackendClass(filepath,data_fallback,try_pdf_removal=try_pdf_removal)
            cp = NxStack(filepath, backend)
            patches = cp.get_patches()
            if stack_randomization:
                cp =  ShiftStack(filepath, backend)
                patches += cp.get_patches()
            '''
            code = '''
                sub esp, 0x1000
                mov eax, 0x11223344
                push 0xabb0c031
                jmp esp
            '''
            '''
            backend.apply_patches(patches+[InsertCodePatch(0x80487d0,code)])
            backend.save(tmp_file)
            # backend.save("/tmp/aaa")
            res = QEMURunner(tmp_file,tinput,record_stdout=True,seed=random.randint(1,1000000000))
            assert res.reg_vals['eax'] == 0x000000ab

            # check read write on stack to the expanded one and autogrow
            # test that behaves like the original even after all these pushes
            backend = BackendClass(filepath,data_fallback,try_pdf_removal=try_pdf_removal)
            cp = NxStack(filepath, backend)
            patches = cp.get_patches()
            if stack_randomization:
                cp =  ShiftStack(filepath, backend)
                patches += cp.get_patches()
            npushpop = 0x200000 + 1 # 8MB + 4: we do not overflow since we added one page
            code = "push edx\n" * npushpop + "pop edx\n" * npushpop
            patches += [InsertCodePatch(0x80487d0,code)]
            backend.apply_patches(patches)
            backend.save(tmp_file)
            # backend.save("/tmp/aaa")
            res = QEMURunner(tmp_file,tinput,record_stdout=True,seed=random.randint(1,1000000000))
            assert original_output == res.stdout
            '''


@try_reassembler_and_detour
def test_adversarial(BackendClass, data_fallback, try_pdf_removal):
    pipe = subprocess.PIPE
    tinput = b"1\n" * 50 + b"2\n"*50
    filepath = os.path.join(bin_location, "CROMU_00044")

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = BackendClass(filepath,data_fallback,try_pdf_removal=try_pdf_removal)
        cp = Adversarial(filepath, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)
        # backend.save("/tmp/aaa")

        original_p = subprocess.Popen([qemu_location, filepath], stdin=pipe, stdout=pipe, stderr=pipe)
        original_res = original_p.communicate(tinput)
        patched_p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        patched_res = patched_p.communicate(tinput)

        assert original_res[0] == patched_res[0]
        assert original_p.returncode == patched_p.returncode
        # stderr is different since we leak the flag page there
        assert original_res[1] != patched_res[1]


@reassembler_only
def test_backdoor(BackendClass, data_fallback, try_pdf_removal):
    def solution_to_bytearray(l):
        # deal with endianness craziness
        return bytes([ l[3],l[2],l[1],l[0],0,0,0,l[4] ])

    for bitflip in [False,True]:
        print("======== Bitflip:", bitflip)
        filepath = os.path.join(bin_location, "CADET_00003")
        real_backdoor_enter = b"\x33\x67\xb1\x80"
        fake_backdoor_enter = b"\x33\x67\xb1\x81"
        custom_bins = [os.path.join(bin_location,os.path.join("patchrex","backdoorme"+str(i))) \
                for i in range(1,9+1,4)]
        bins = [filepath] + custom_bins

        with patcherex.utils.tempdir() as td:
            tmp_file = os.path.join(td, "patched")
            backend = BackendClass(filepath, data_fallback, try_pdf_removal=try_pdf_removal)
            cp = Backdoor(filepath, backend, enable_bitflip=bitflip)
            patches = cp.get_patches()
            backend.apply_patches(patches)
            backend.save(tmp_file)
            # backend.save("/tmp/aaa")

            # test with short and long strings if we destroyed original functionality
            # last test is supposed to fail
            tests = [b"A", b"A"*10, real_backdoor_enter[:3], real_backdoor_enter[:3] + b"A"*10,
                     b"\n"*10, real_backdoor_enter[:3] + b"A"*10, real_backdoor_enter + b"\n"*10
                     ]
            for index,tinput in enumerate(tests):
                res = QEMURunner(filepath,tinput,record_stdout=True)
                original_behavior = res.stdout, res.returncode
                res = QEMURunner(tmp_file,tinput,record_stdout=True,bitflip=bitflip)
                patched_behavior = res.stdout, res.returncode
                if index != len(tests)-1:
                    assert original_behavior == patched_behavior
                else:
                    assert original_behavior != patched_behavior

            # test some hardcoded values for the real backdoor
            ''' # old qemu seed-->random
            tests = [   (0x12345678,0x99abcdef,1,[0x00,0xd0,0xb0,0xfd,0xdd]),
                        (0x00000000,0x00000000,2,[0x00,0x88,0x36,0xc1,0x23]),
                        (0xffffffff,0xffffffff,4,[0x01,0x7a,0x09,0x53,0xa8]),
                        (0xffffffff,0xffffffff,4,[0x00,0x7a,0x09,0x53,0xa8])]
            '''
            tests = [
                        (0xffffffff,0xffffffff,4,[0x01,0xac,0xf8,0xa3,0xb6]),
                        (0xffffffff,0xffffffff,4,[0x01,0xac,0xf8,0xa3,0xb7])]
            # the last test should fail
            for index, (ebx, eip, seed, solution) in enumerate(tests):
                tinput = real_backdoor_enter + solution_to_bytearray(solution)
                tinput += struct.pack("<I",ebx)
                tinput += struct.pack("<I",eip)
                # fp = open("/tmp/tinput","wb")
                # fp.write(tinput)
                # fp.close()
                res = QEMURunner(tmp_file,
                                 tinput,
                                 record_stdout=True,
                                 record_core=True,
                                 seed=seed,
                                 bitflip=bitflip)
                if index != len(tests)-1:
                    assert res.reg_vals['eip'] == eip
                    assert res.reg_vals['ebx'] == ebx
                else:
                    # no crash, the backdoor failed
                    assert res.reg_vals is None

            # test the fake backdoor
            '''
            ebx_vals = set()
            eip_vals = set()
            ntests = 2
            # apparently seed 0 and 1 generate the same randomness
            for index in xrange(1,1+ntests):
                tinput = fake_backdoor_enter + "a"*16
                # fp = open("../../vm/shared/tinput","wb")
                # fp.write(tinput)
                # fp.close()
                res = QEMURunner(tmp_file,tinput,record_stdout=True,seed=index,bitflip=bitflip)
                eip_vals.add(res.reg_vals['eip'])
                ebx_vals.add(res.reg_vals['ebx'])
            # check that ebx and eip are actually randomized by the fake backdoor
            assert len(eip_vals) == ntests
            assert len(ebx_vals) == ntests

            # test real backdoor
            for index,tbin in enumerate(bins):
                tmp_file = os.path.join(td, "patched")
                backend = BackendClass(tbin,data_fallback,try_pdf_removal=try_pdf_removal)
                cp = Backdoor(tbin, backend,enable_bitflip=bitflip)
                patches = cp.get_patches()
                backend.apply_patches(patches)
                backend.save(tmp_file)
                # backend.save("/tmp/aaa")
                pov_tester = CGCPovSimulator()
                backdoor_pov_location = os.path.join(self_location_folder,"../backdoor_stuff/backdoor_pov.pov")
                res = pov_tester.test_binary_pov(backdoor_pov_location,tmp_file,bitflip=bitflip)
                if index < len(bins)-1:
                    if not res:
                        print "failed on:", os.path.basename(tbin)
                    assert res
                else:
                    # the last two are supposed to fail
                    assert res is False
            '''


@reassembler_only
def test_bitflip(BackendClass, data_fallback, try_pdf_removal):
    all_chars = [bytes([c]) for c in range(256)]
    pipe = subprocess.PIPE
    tests = []
    # tests.append(os.path.join(bin_location, "patchrex/CADET_00003_fixed"))
    # tests.append(os.path.join(bin_location, "patchrex/echo1"))
    tests.append(os.path.join(bin_location, "patchrex/echo2"))
    slens = [0,1,0x1000,0xfff,0x1001]
    i = 1
    while True:
        i *= 111.1
        slens.append(int(i))
        if int(i) > 0x100000:
            break


    with patcherex.utils.tempdir() as td:
        for test in tests:
            tmp_file = os.path.join(td, "patched")
            backend = BackendClass(test, data_fallback, try_pdf_removal=try_pdf_removal)
            cp = Bitflip(test, backend)
            # backend._debugging = True
            patches = cp.get_patches()
            backend.apply_patches(patches)
            backend.save(tmp_file)

            for tlen in slens:
                ostr = bytes(random.choice(list(range(256))) for _ in range(tlen))
                p = subprocess.Popen([qemu_location, test], stdin=pipe, stdout=pipe, stderr=pipe)
                res = p.communicate(ostr)
                expected = (res[0], p.returncode)
                p = subprocess.Popen([qemu_location, "-bitflip", tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
                res = p.communicate(ostr)
                patched = (res[0], p.returncode)
                print(test, tlen)
                assert expected == patched

        for test in tests:
            tmp_file = os.path.join(td, "patched")
            backend = BackendClass(test, data_fallback, try_pdf_removal=try_pdf_removal)
            cp = Backdoor(test, backend, enable_bitflip=True)
            patches = cp.get_patches()
            backend.apply_patches(patches)
            backend.save(tmp_file)
            # backend.save("/tmp/aaa")

            for tlen in slens:
                ostr = bytes(random.choice(list(range(256))) for _ in range(tlen))
                p = subprocess.Popen([qemu_location, test], stdin=pipe, stdout=pipe, stderr=pipe)
                res = p.communicate(ostr)
                expected = (res[0], p.returncode)
                p = subprocess.Popen([qemu_location, "-bitflip", tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
                res = p.communicate(ostr)
                patched = (res[0], p.returncode)
                print(test, tlen)
                assert expected == patched

@reassembler_only
def test_uninitialized(BackendClass, data_fallback, try_pdf_removal):
    filepath = os.path.join(bin_location, "CROMU_00070")

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = BackendClass(filepath)
        cp = UninitializedPatcher(filepath, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)

        # the exploit should no longer work
        pov = os.path.join(poll_location, "CROMU_00070_2.pov")
        assert not CGCPovSimulator().test_binary_pov(pov, tmp_file)

        # the poll should still work
        poll_input = b"\x02\x10\x00\xbf\xb6\x7e\xabZ\x3e\xbeG\x01\x06\x00u\xd3\x04E\x8ao" \
                     b"\x05\x00\x00\x05" \
                     b"\x00\x00\x00\x00" \
                     b"\x02\x0b\x00\xbf\xb6\x7e\xabZ\x3e\xbeG\x00\x01\x2bt" \
                     b"\x03R\x00\x01\x08\xe0\x17\x1b\x00\x07\xa8\xdd\x07\xfe\xc1\x1fW\x0e\x00\x08\xfb\xd7\x09i\xdf\xdde" \
                     b"\x11\x00\x01\xe61\x11\xfd?\x3c\x8e\x25\x00\x08!\x27\x0c!\x97\x90\x12\x24\x00\x09V\x86\x00OL?d\x2a" \
                     b"\x00\x02C\x19\x08\xf3\x1d\x19\x96\x0b\x00\x05\x01\xa3\x06M\xe5\x10\xc1!\x00\x09\xabQ\x08\xea!Z" \
                     b"\x02\x10\x00\xbf\xb6\x7e\xabZ\x3e\xbeG\x01\x06\x02\x02\xec\x08\x84\x85U" \
                     b"\x07\x00\x00\x07" \
                     b"\x07\x00\x00\x07" \
                     b"\x00\x00\x00\x00" \
                     b"\x03\x02\x00\x02\x00\x07" \
                     b"\x06\x00\x00\x06" \
                     b"\x08\x00\x00\x08" \
                     b"\x01\x00\x00\x01"

        pipe = subprocess.PIPE
        p = subprocess.Popen([qemu_location, filepath], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(poll_input)
        expected_output = res[0]

        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(poll_input)
        assert expected_output == res[0]

@reassembler_only
def test_malloc_patcher(BackendClass, data_fallback, try_pdf_removal):
    filepath = os.path.join(bin_location, "NRFIN_00078")

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = BackendClass(filepath)
        cp = MallocExtPatcher(filepath, backend)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)

        # the exploit should no longer work
        pov = os.path.join(poll_location, "NRFIN_00078_2.pov")
        assert not CGCPovSimulator().test_binary_pov(pov, tmp_file)

        # the poll should still work
        poll_input = b"a\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00D1hTwKsiTm8dFvhwwrLqPiV9gogd52Xsu" \
                     b"v\x00\x00\x00\x00\x00\x00\x00\x00\x0a\x00\x00\x00\x5bis6Rg\x5dyo\x2a" \
                     b"n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                     b"d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                     b"q\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

        pipe = subprocess.PIPE
        p = subprocess.Popen([qemu_location, filepath], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(poll_input)
        expected_output = res[0]

        '''
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(poll_input)
        assert expected_output == res[0]
        '''


@reassembler_only
def disable_no_flag_printf(BackendClass, data_fallback, try_pdf_removal):

    # @anto: I don't think the first crash test for PIZZA_00002 makes sense. It should not print out any data from the
    # flag page. Also it crashes the original program as well. I'm disabling this test case for now.

    filepath1 = os.path.join(bin_location, "PIZZA_00002")
    filepath2 = os.path.join(bin_location, "original/KPRCA_00011")

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = BackendClass(filepath1)
        patcher = NoFlagPrintfPatcher(filepath1, backend)
        patches = patcher.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)

        crash_test = b"""new deliverer
%s %s
new pizza
hello
deliver
hello
%s %s
        """
        import ipdb; ipdb.set_trace()
        res = QEMURunner(tmp_file, crash_test, record_stdout=True, record_core=True)
        assert res.returncode != 0
        # shutil.copy(tmp_file, "/tmp/aaa")
        assert res.reg_vals['eip'] == 0x41414141

        ok_test = b"""new deliverer
nick stephens
new pizza
two MILLION dollars
deliver
two MILLION dollars
nick stephens
        """
        res = QEMURunner(filepath1, ok_test, record_stdout=True)
        expected_ret = res.returncode
        expected_stdout = res.stdout
        res = QEMURunner(tmp_file, ok_test, record_stdout=True)
        actual_ret = res.returncode
        actual_stdout = res.stdout
        assert expected_ret == actual_ret
        assert expected_stdout == actual_stdout

        '''
        backend = BackendClass(filepath2)
        patcher = NoFlagPrintfPatcher(filepath2, backend)
        patches = patcher.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)
        # shutil.copy(tmp_file,"/tmp/aaa")
        res = QEMURunner(filepath2, ok_test, record_stdout=True)
        expected_ret = res.returncode
        expected_stdout = res.stdout
        res = QEMURunner(tmp_file, ok_test, record_stdout=True)
        actual_ret = res.returncode
        actual_stdout = res.stdout
        assert expected_ret == actual_ret
        assert expected_stdout == actual_stdout
        '''

@detour_only
def test_countdown_1(BackendClass, data_fallback, try_pdf_removal):
    filepath = os.path.join(bin_location, "countdown_test")

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = BackendClass(filepath, try_pdf_removal=try_pdf_removal)
        obj = backend.project.loader.main_object
        patch_list = []
        patch_list.append({"target_addr": obj.offset_to_addr(0x0a31), "dst_active": obj.offset_to_addr(0xa6e), "dst_zero": obj.offset_to_addr(0xa49), "num_instr": 2, "extra_code": "cmp     dword  [rbp - 0x14], 1", "extra_is_c": False})
        cp = Countdown(filepath, backend, patch_list=patch_list, count=2)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)

        # We should only see the "Usage error"
        expected_output =  b"$> foo\nWrong length!\n\n$> test\nUnkown command!\n\n$> "
        pipe = subprocess.PIPE
        p = subprocess.Popen([tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"foo\ntest\n")
        assert expected_output == res[0]


@detour_only
def test_countdown_2(BackendClass, data_fallback, try_pdf_removal):
    filepath = os.path.join(bin_location, "countdown_test")

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = BackendClass(filepath, try_pdf_removal=try_pdf_removal)
        obj = backend.project.loader.main_object
        patch_list = []
        patch_list.append({"target_addr": obj.offset_to_addr(0x09d5), "dst_active": obj.offset_to_addr(0x09ee), "dst_zero": obj.offset_to_addr(0x09db), "num_instr": 2, "extra_code": "cmp dword [rbp - 4], 3", "extra_is_c": False})
        cp = Countdown(filepath, backend, patch_list=patch_list, count=2)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)

        # We should not see the "Wrong length" error
        expected_output = b"$> foo\nUnkown command!\n\n$> "
        pipe = subprocess.PIPE
        p = subprocess.Popen([tmp_file, "-run"], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"foo\n")
        assert expected_output == res[0]


@detour_only
def test_countdown_3(BackendClass, data_fallback, try_pdf_removal):
    filepath = os.path.join(bin_location, "countdown_test")

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = BackendClass(filepath, try_pdf_removal=try_pdf_removal)
        obj = backend.project.loader.main_object
        patch_list = []
        patch_list.append({"target_addr": obj.offset_to_addr(0x0a42), "dst_active": obj.offset_to_addr(0x0a6e), "dst_zero": obj.offset_to_addr(0x0a49), "num_instr": 3, "extra_code": "movzx eax, byte [rax]\ncmp al, 0x2d", "extra_is_c": False})
        patch_list.append({"target_addr": obj.offset_to_addr(0x0b32), "dst_active": obj.offset_to_addr(0x0a6e), "dst_zero": Countdown.ZERO_TARGET_EXIT, "num_instr": 1,})
        patch_list.append({"target_addr": obj.offset_to_addr(0x0b2c), "dst_active": obj.offset_to_addr(0x0a6e), "dst_zero": Countdown.ZERO_TARGET_EXIT, "num_instr": 1})
        cp = Countdown(filepath, backend, patch_list=patch_list, count=2)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)

        # We should only see the prompt twice
        expected_output = b"$> foo\nWrong length!\n\n$> test\nUnkown command!\n\n"
        pipe = subprocess.PIPE
        p = subprocess.Popen([tmp_file, "-run"], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"foo\ntest\n")
        assert expected_output == res[0]


def run_all():
    functions = globals()
    all_functions = dict(filter((lambda x: x[0].startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            l.info("testing %s", str(f))
            all_functions[f]()


if __name__ == "__main__":
    import sys
    logging.getLogger("patcherex.test.test_techniques").setLevel("INFO")
    logging.getLogger("patcherex.backends.DetourBackend").setLevel("INFO")
    logging.getLogger("patcherex.backends.reassembler_backend").setLevel("DEBUG")
    logging.getLogger("patcherex.techniques.Backdoor").setLevel("DEBUG")
    logging.getLogger("patcherex.techniques.ShadowStack").setLevel("DEBUG")
    logging.getLogger("patcherex.techniques.SimpleCFI").setLevel("DEBUG")
    logging.getLogger("patcherex.techniques.QemuDetection").setLevel("DEBUG")
    logging.getLogger("patcherex.techniques.StackRetEncryption").setLevel("DEBUG")
    logging.getLogger("patcherex.techniques.IndirectCFI").setLevel("DEBUG")
    logging.getLogger("patcherex.techniques.TransmitProtection").setLevel("DEBUG")
    logging.getLogger("patcherex.techniques.Adversarial").setLevel("DEBUG")
    logging.getLogger("patcherex.techniques.NxStack").setLevel("DEBUG")
    logging.getLogger("patcherex.techniques.ShiftStack").setLevel("DEBUG")
    logging.getLogger("patcherex.techniques.Countdown").setLevel("DEBUG")
    logging.getLogger('povsim').setLevel("DEBUG")

    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
