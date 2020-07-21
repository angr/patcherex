#test cases for x86-64 enabled binaries
import unittest
import os
import subprocess
import patcherex
from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import AddCodePatch, AddRODataPatch, InsertCodePatch

class MyTestCase(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # binaries location
        self.binary_path = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests/x86_64/patchrex/'))

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
        mov rdx, 10
        push $
        call {transmit_function}
        '''
        patches.append(AddCodePatch(transmit_code, name="transmit_function"))
        patches.append(AddRODataPatch(b"---HI---\x00", name="transmitted_string"))
        patches.append(InsertCodePatch(0x400665, injected_code, name="injected_code_after_receive"))

        self.execute(patches, "sample_x86-64_pie", b'---HI---\x00\x00Purdue')

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
        mov rdx, 10
        call {transmit_function}
        '''
        patches.append(InsertCodePatch(0x400502, injected_code, name="injected_code_after_receive"))
        self.execute(patches, "sample_x86-64_no_pie", b'---HI---\x00\x00Purdue')


    def execute(self, patches, binary, output_expected=None):
        with patcherex.utils.tempdir() as td:
            tmp_file = os.path.join(td, "patched")
            #backend operations
            backend = DetourBackend(self.binary_path + binary)
            backend.apply_patches(patches)
            backend.save(tmp_file)
            #run the patched binary
            pipe = subprocess.PIPE
            p = subprocess.Popen([tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
            res = p.communicate()
            #check the results
            self.assertEqual(res[0], output_expected)

if __name__ == '__main__':
    unittest.main()
