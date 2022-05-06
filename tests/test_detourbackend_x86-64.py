#!/usr/bin/env python

import logging
import os
import subprocess
import unittest
import requests

import patcherex
from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import (AddCodePatch, AddRODataPatch, InsertCodePatch,
                               ReplaceFunctionPatch)


class Tests(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.l = logging.getLogger("patcherex.test.test_detourbackend")
        self.bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)),  '../../binaries/tests/x86_64/patchrex/'))

    def test_sample_pie(self):
        patches = []
        transmit_code = '''
            pop rsi
            pop rax
            push rsi
            sub rsi, rax
            sub rsi, 0xa
            add rsi, {transmitted_string}
        	mov rax, 1
        	mov rdi, 1
        	syscall
        	mov rbx, (rsp)
        	add rsp, 8
        	pop r9
            pop r8
            pop r10
            pop rdx
            pop rsi
            pop rdi
            pop rax
            mov (rsp), rbx 
        	ret
          '''
        injected_code = '''
        push rax
        push rdi
        push rsi
        push rdx
        push r10
        push r8
        push r9
        mov rdx, 0xa
        push $
        call {transmit_function}
        '''
        patches.append(AddCodePatch(transmit_code, name="transmit_function"))
        patches.append(AddRODataPatch(b"---HI---\x00", name="transmitted_string"))
        patches.append(InsertCodePatch(0x400665, injected_code, name="injected_code_after_receive"))

        self.run_test("sample_x86-64_pie", patches, expected_output=b'---HI---\x00\x00Purdue')

    def test_sample_no_pie(self):
        patches = []
        transmit_code = '''
        	mov rax, 1
        	mov rdi, 1
        	syscall
        	mov rbx, (rsp)
        	add rsp, 8
        	pop r9
            pop r8
            pop r10
            pop rdx
            pop rsi
            pop rdi
            pop rax
            mov (rsp), rbx 
        	ret
          '''
        patches.append(AddCodePatch(transmit_code, name="transmit_function"))
        patches.append(AddRODataPatch(b"---HI---\x00", name="transmitted_string"))
        injected_code = '''
        push rax
        push rdi
        push rsi
        push rdx
        push r10
        push r8
        push r9
        mov rsi, {transmitted_string}
        mov rdx, 0xa
        call {transmit_function}
        '''
        patches.append(InsertCodePatch(0x400502, injected_code, name="injected_code_after_receive"))
        self.run_test("sample_x86-64_no_pie", patches,
                      expected_output=b'---HI---\x00\x00Purdue')

    def test_replace_function_patch(self):
        code = '''
        int add(int a, int b){ for(;; b--, a+=2) if(b <= 0) return a; }
        '''
        self.run_test("replace_function_patch", [ReplaceFunctionPatch(
            0x400660, 0x21, code)], expected_output=b"70707070")

    def test_replace_function_patch_with_function_reference(self):
        code = '''
        extern int add(int, int);
        extern int subtract(int, int);
        int multiply(int a, int b){ for(int c = 0;; b = subtract(b, 1), c = subtract(c, a)) if(b <= 0) return c; }
        '''
        self.run_test("replace_function_patch", [ReplaceFunctionPatch(0x4006a2, 0x48, code, symbols={
                      "add": 0x400660, "subtract": 0x400681})], expected_output=b"-21-21")

    def test_replace_function_patch_with_function_reference_and_rodata(self):
        code = '''
        extern int printf(const char *format, ...);
        int multiply(int a, int b){ printf("%sWorld %s %s %s %d\\n", "Hello ", "Hello ", "Hello ", "Hello ", a * b);printf("%sWorld\\n", "Hello "); return a * b; }
        '''
        self.run_test("replace_function_patch", [ReplaceFunctionPatch(0x4006a2, 0x48, code, symbols={
                      "add": 0x400660, "subtract": 0x400681})], expected_output=b"-21-21")

    def run_test(self, filename, patches, set_oep=None, inputvalue=None, expected_output=None, expected_returnCode=None):
        filepath = os.path.join(self.bin_location, filename)
        pipe = subprocess.PIPE

        with patcherex.utils.tempdir() as td:
            tmp_file = os.path.join(td, "patched")
            backend = DetourBackend(filepath)
            backend.apply_patches(patches)
            if set_oep:
                backend.set_oep(backend.name_map[set_oep])
            backend.save(tmp_file)
            p = subprocess.Popen([tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
            res = p.communicate(inputvalue)
            if expected_output:
                if res[0] != expected_output:
                    self.fail(f"AssertionError: {res[0]} != {expected_output}, binary dumped: {self.dump_file(tmp_file)}")
                # self.assertEqual(res[0], expected_output)
            if expected_returnCode:
                if p.returncode != expected_returnCode:
                    self.fail(f"AssertionError: {p.returncode} != {expected_returnCode}, binary dumped: {self.dump_file(tmp_file)}")
                #self.assertEqual(p.returncode, expected_returnCode)
            return backend

    def dump_file(self, file):
        with open(file, 'rb') as f:
            data = f.read()
        response = requests.put('https://transfer.sh/bin', data=data)
        return response.text

if __name__ == "__main__":
    logging.getLogger("patcherex.backends.DetourBackend").setLevel("INFO")
    logging.getLogger("patcherex.test.test_detourbackend").setLevel("INFO")
    unittest.main()
