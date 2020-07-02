#!/usr/bin/env python

import os
import struct
import subprocess
import logging
import unittest
from functools import wraps

import patcherex
import shellphish_qemu
from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import *


class Tests(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.l = logging.getLogger("patcherex.test.test_detourbackend")
        self.bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)),  '../../binaries/tests/armhf/patchrex'))
        self.qemu_location = shellphish_qemu.qemu_path('arm')

    def test_inline_patch(self):
        self.run_test("printf_nopie", [InlinePatch(0x103e2, "ldr r1, [pc, #0x14]"), InlinePatch(0x103e4, "add r1, pc"), InlinePatch(0x103e6, "mov r0, r1")], expected_output=b"%s", expected_returnCode=0)

    def test_remove_instruction_patch(self):
        self.run_test("printf_nopie", [RemoveInstructionPatch(0x103e0, 2), RawMemPatch(0x10450, b"\xbf")], expected_output=b"\xbfs", expected_returnCode=0)

    def test_add_code_patch(self):
        added_code = '''
            mov r7, 0x1
            mov r0, 0x32
            svc 0
        '''
        self.run_test("printf_nopie", [AddCodePatch(added_code, "added_code")], set_oep="added_code", expected_returnCode=0x32)

    def test_insert_code_patch(self):
        test_str = b"qwertyuiop\n\x00"
        added_code = '''
            mov r7, 0x4
            mov r0, 0x1
            ldr r1, ={added_data}
            mov r2, %d
            svc 0
        ''' % (len(test_str))
        p1 = InsertCodePatch(0x103ec, added_code)
        p2 = AddRODataPatch(test_str, "added_data")

        self.run_test("printf_nopie", [p1, p2], expected_output=b"qwertyuiop\n\x00Hi", expected_returnCode=0)

    def test_add_label_patch(self):
        p1 = AddLabelPatch(0x10451, "added_label")
        added_code = '''
            mov r7, 0x4
            mov r0, 0x1
            ldr r1, ={added_label}
            mov r2, 1
            svc 0
        '''
        p2 = InsertCodePatch(0x103ec, added_code)

        self.run_test("printf_nopie", [p1, p2], expected_output=b"sHi", expected_returnCode=0)

    def test_raw_file_patch(self):
        self.run_test("printf_nopie", [RawFilePatch(0x44c, b"No")], expected_output=b"No", expected_returnCode=0)

    def test_raw_mem_patch(self):
        self.run_test("printf_nopie", [RawMemPatch(0x1044c, b"No")], expected_output=b"No", expected_returnCode=0)

    def test_add_ro_data_patch(self, tlen=5):
        p1 = AddRODataPatch(b"A"*tlen, "added_data")
        added_code = '''
            mov r7, 0x4
            mov r0, 0x1
            ldr r1, ={added_data}
            mov r2, %d
            svc 0
        ''' % tlen
        p2 = InsertCodePatch(0x103ec, added_code, "added_code")

        self.run_test("printf_nopie", [p1, p2], expected_output=b"A"*tlen + b"Hi", expected_returnCode=0x0)

    def test_add_rw_data_patch(self, tlen=5):
        p1 = AddRWDataPatch(tlen, "added_data_rw")
        added_code = '''
            mov r7, 0x4
            mov r0, 0x41
            mov r1, 0x0
            mov r2, %d
            ldr r3, ={added_data_rw}
            _loop:
                cmp r1, r2
                beq _exit
                str r0, [r3, r1]
                add r1, r1, 1
                b _loop
            _exit:
            mov r0, 0x1
            ldr r1, ={added_data_rw}
            svc 0
        ''' % tlen
        p2 = InsertCodePatch(0x103ec, added_code, "modify_and_print")

        self.run_test("printf_nopie", [p1, p2], expected_output=b"A"*tlen + b"Hi", expected_returnCode=0)

    def test_add_rw_init_data_patch(self, tlen=5):
        p1 = AddRWInitDataPatch(b"A"*tlen, "added_data_rw")
        added_code = '''
            mov r7, 0x4
            mov r0, 0x1
            ldr r1, ={added_data_rw}
            mov r2, %d
            svc 0
        ''' % tlen
        p2 = InsertCodePatch(0x103ec, added_code, "print")

        self.run_test("printf_nopie", [p1, p2], expected_output=b"A"*tlen + b"Hi", expected_returnCode=0)

    def test_add_entry_point_patch(self):
        added_code = '''
            mov r7, 0x4
            mov r0, 0x1
            ldr r1, =0x10450
            mov r2, 2
            svc 0
        '''
        self.run_test("printf_nopie", [AddEntryPointPatch(added_code)], expected_output=b'%sHi', expected_returnCode=0)

    def test_c_compilation(self):
        added_code = '''
            mov r7, 0x4
            mov r0, 0x0
            %s
            ldr r1, =0x10451
            mov r2, 1
            svc 0
            
        ''' % patcherex.arch.arm.utils.get_nasm_c_wrapper_code("c_function", get_return=True)

        self.run_test("printf_nopie", [InsertCodePatch(0x103ec, added_code, name="p1", priority=1), AddCodePatch("__attribute__((fastcall)) int func(int a){ return a + 1; }", "c_function", is_c=True, compiler_flags="", is_thumb=True)], expected_output=b"sHi", expected_returnCode=0x0)

    def test_add_data_patch_long(self):
        lengths = [0, 1, 5, 10, 100, 1000, 2000, 5000]
        for length in lengths:
            self.test_add_ro_data_patch(length)
            self.test_add_rw_data_patch(length)
            self.test_add_rw_init_data_patch(length)

    def test_complex1(self):
            patches = []
            added_code = '''
                mov r7, 0x4
                mov r0, 0x1
                ldr r1, =0x10450
                mov r2, 2
                svc 0
                bl {added_function}
                mov r7, 0x1
                mov r0, 0x34
                svc 0
            '''
            patches.append(AddEntryPointPatch(added_code))

            test_str = b"testtesttest\n\x00"
            added_code = '''
                mov r7, 0x4
                mov r0, 0x1
                ldr r1, ={added_data}
                mov r2, %d
                svc 0
                bx lr
            ''' % (len(test_str))
            patches.append(AddCodePatch(added_code, "added_function", is_thumb=True))
            patches.append(AddRODataPatch(test_str, "added_data"))

            self.run_test("printf_nopie", patches, expected_output=b'%s' + test_str, expected_returnCode=0x34)

    def test_double_patch_collision(self):
        test_str1 = b"1111111111\n\x00"
        test_str2 = b"2222222222\n\x00"
        added_code1 = '''
            mov r7, 0x4
            mov r0, 0x1
            ldr r1, ={str1}
            mov r2, %d
            svc 0
        ''' % (len(test_str1))
        added_code2 = '''
            mov r7, 0x4
            mov r0, 0x1
            ldr r1, ={str2}
            mov r2, %d
            svc 0
        ''' % (len(test_str2))

        p1 = InsertCodePatch(0x103ec, added_code1, name="p1", priority=100)
        p2 = InsertCodePatch(0x103ec, added_code2, name="p2", priority=1)
        p3 = AddRODataPatch(test_str1, "str1")
        p4 = AddRODataPatch(test_str2, "str2")
        self.run_test("printf_nopie", [p1, p2, p3, p4], expected_output=test_str1 + b"Hi")

        p1 = InsertCodePatch(0x103ec, added_code1, name="p1", priority=1)
        p2 = InsertCodePatch(0x103ec, added_code2, name="p2", priority=100)
        p3 = AddRODataPatch(test_str1, "str1")
        p4 = AddRODataPatch(test_str2, "str2")
        backend = self.run_test("printf_nopie", [p1, p2, p3, p4], expected_output=test_str2 + b"Hi")
        self.assertNotIn(p1, backend.added_patches)
        self.assertIn(p2, backend.added_patches)

        p1 = InsertCodePatch(0x103ec, added_code1, name="p1", priority=1)
        p2 = InsertCodePatch(0x103ec+0x4, added_code2, name="p2", priority=100)
        p3 = AddRODataPatch(test_str1, "str1")
        p4 = AddRODataPatch(test_str2, "str2")
        backend = self.run_test("printf_nopie", [p1, p2, p3, p4], expected_output=test_str2 + b"Hi")
        self.assertNotIn(p1, backend.added_patches)
        self.assertIn(p2, backend.added_patches)

    def test_conflicting_symbols(self):
        filepath = os.path.join(self.bin_location, "printf_nopie")

        patches = []
        backend = DetourBackend(filepath)
        patches.append(AddRODataPatch(b"0123456789abcdef", "aaa"))
        patches.append(AddRODataPatch(b"\n", "aaa"))
        exc = False
        try:
            backend.apply_patches(patches)
        except ValueError:
            exc = True
        self.assertTrue(exc)

        patches = []
        backend = DetourBackend(filepath)
        patches.append(AddRODataPatch(b"0123456789abcdef", "aaa"))
        added_code = '''
            nop
        '''
        patches.append(AddCodePatch(added_code, "aaa"))
        exc = False
        try:
            backend.apply_patches(patches)
        except ValueError:
            exc = True
        self.assertTrue(exc)

    def run_test(self, file, patches, set_oep=None, input=None, expected_output=None, expected_returnCode=None):
        filepath = os.path.join(self.bin_location, file)
        pipe = subprocess.PIPE

        with patcherex.utils.tempdir() as td:
            tmp_file = os.path.join(td, "patched")
            backend = DetourBackend(filepath)
            backend.apply_patches(patches)
            if set_oep:
                backend.set_oep(backend.name_map[set_oep])
            backend.save(tmp_file)
            p = subprocess.Popen([self.qemu_location, "-L", "/usr/arm-linux-gnueabihf", tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
            res = p.communicate(input)
            if expected_output:
                self.assertEqual(res[0], expected_output)
            if expected_returnCode:
                self.assertEqual(p.returncode, expected_returnCode)
            return backend

if __name__ == "__main__":
    import sys
    logging.getLogger("patcherex.backends.DetourBackend").setLevel("INFO")
    logging.getLogger("patcherex.test.test_detourbackend").setLevel("INFO")
    unittest.main()
