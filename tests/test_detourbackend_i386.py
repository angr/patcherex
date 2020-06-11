#!/usr/bin/env python

import os
import struct
import subprocess
import logging
from functools import wraps

import patcherex
import shellphish_qemu
from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import *

l = logging.getLogger("patcherex.test.test_detourbackend")

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../test_binaries/intel'))
qemu_location = shellphish_qemu.qemu_path('i386')

def test_InlinePatch():
    run_test("simple_i386_nopie", [InlinePatch(0x08048442, "LEA EDX, [EAX + 0xffffe4f3]")], expected_output=b"%s", expected_returnCode=0)

def test_RemoveInstructionPatch():
    run_test("simple_i386_nopie", [RemoveInstructionPatch(0x08048449, 7), RemoveInstructionPatch(0x080484f0, 1)], expected_output=b"\x90i", expected_returnCode=0)

def test_AddCodePatch():
    added_code = '''
        mov eax, 1      ;sys_exit
        mov ebx, 0x32   ;return code
        int 0x80
    '''
    run_test("simple_i386_nopie", [AddCodePatch(added_code, "added_code")], set_oep="added_code", expected_returnCode=0x32)

def test_InsertCodePatch():
    test_str = b"qwertyuiop\n\x00"
    added_code = '''
        mov     eax, 4
        mov     ebx, 1
        mov     ecx, {added_data}
        mov     edx, %d
        int     0x80
    ''' % (len(test_str))
    p1 = InsertCodePatch(0x8048457, added_code)
    p2 = AddRODataPatch(test_str, "added_data")

    run_test("simple_i386_nopie", [p1,p2], expected_output=b"qwertyuiop\n\x00Hi", expected_returnCode=0)

def test_AddLabelPatch():
    p1 = AddLabelPatch(0x080484f4, "added_label")
    p2 = InlinePatch(0x08048442, "LEA EDX, [{added_label}]")

    run_test("simple_i386_nopie", [p1,p2], expected_output=b"s", expected_returnCode=0)

def test_RawFilePatch():
    run_test("simple_i386_nopie", [RawFilePatch(0x4f0, b"No")], expected_output=b"No", expected_returnCode=0)

def test_RawMemPatch():
    run_test("simple_i386_nopie", [RawMemPatch(0x080484f0, b"No")], expected_output=b"No", expected_returnCode=0)

def test_AddRODataPatch(tlen=5):
    p1 = AddRODataPatch(b"A"*tlen, "added_data")
    added_code = '''
        mov eax, 4              ;sys_write
        mov ebx, 1              ;fd = stdout
        mov ecx, {added_data}   ;buf
        mov edx, %d             ;len
        int 0x80
    ''' % tlen
    p2 = InsertCodePatch(0x8048457, added_code, "added_code")

    run_test("simple_i386_nopie", [p1,p2], expected_output=b"A"*tlen + b"Hi", expected_returnCode=0x0)

def test_AddRWDataPatch(tlen=5):
    p1 = AddRWDataPatch(tlen, "added_data_rw")
    added_code = '''
        mov eax, 4
        mov ebx, 1
        xor ecx, ecx
        mov edx, %d
        _loop:
            cmp ecx, edx
            je _exit
            mov BYTE [{added_data_rw}+ecx], 0x41
            add ecx, 1
            jmp _loop
        _exit
        mov ecx, {added_data_rw}
        int 0x80
    ''' % tlen
    p2 = InsertCodePatch(0x8048457, added_code,"modify_and_print")

    run_test("simple_i386_nopie", [p1, p2], expected_output=b"A"*tlen + b"Hi", expected_returnCode=0)

def test_AddRWInitDataPatch(tlen=5):
    p1 = AddRWInitDataPatch(b"A"*tlen, "added_data_rw")
    added_code = '''
        mov eax,0x4
        mov ebx,0x1
        mov edx, %d
        mov ecx, {added_data_rw}
        int 0x80
    ''' % tlen
    p2 = InsertCodePatch(0x8048457, added_code,"print")

    run_test("simple_i386_nopie", [p1, p2], expected_output=b"A"*tlen + b"Hi", expected_returnCode=0)

def test_AddEntryPointPatch():
    added_code = '''
        mov     eax, 4
        mov     ebx, 1
        mov     ecx, 0x080484f3
        mov     edx, 2
        int     0x80

        mov     eax, 1 ;sys_exit
        mov     ebx, 0x1 ;return code
        int     0x80
    '''
    run_test("simple_i386_nopie", [AddEntryPointPatch(added_code)], expected_output=b'%s', expected_returnCode=0x1)

def test_c_compilation():
    added_code = '''
        mov ecx, 0x4
        %s
        mov ebx, 1
        lea ecx, [0x080484f4]
        mov edx, 1
        int 0x80
    ''' % patcherex.utils.get_nasm_c_wrapper_code("c_function",get_return=True)

    run_test("simple_i386_nopie", [InsertCodePatch(0x8048457, added_code, name="p1", priority=1), AddCodePatch("__attribute__((fastcall)) int func(int a){ return a; }", "c_function", is_c=True)], expected_output=b"sHi", expected_returnCode=0x0)

def test_AddDataPatch_long():
    lengths = [0, 1, 5, 10, 100, 1000, 2000, 5000]
    for length in lengths:
        test_AddRODataPatch(length)
        test_AddRWDataPatch(length)
        test_AddRWInitDataPatch(length)

def test_complex1():
        patches = []
        added_code = '''
            mov     eax, 4
            mov     ebx, 1
            mov     ecx, 0x080484f3
            mov     edx, 2
            int     0x80
            call    {added_function}
        '''
        patches.append(AddEntryPointPatch(added_code))

        added_code = '''
            mov     eax, 1
            mov     ebx, 0x34
            int     0x80
        '''
        patches.append(AddEntryPointPatch(added_code))

        test_str = b"testtesttest\n\x00"
        added_code = '''
            mov     eax, 4
            mov     ebx, 1
            mov     ecx, {added_data}
            mov     edx, %d
            int     0x80
            ret
        ''' % (len(test_str))
        patches.append(AddCodePatch(added_code, "added_function"))
        patches.append(AddRODataPatch(test_str, "added_data"))

        run_test("simple_i386_nopie", patches, expected_output=b'%s' + test_str, expected_returnCode=0x34)

def test_double_patch_collision():
    test_str1 = b"1111111111\n\x00"
    test_str2 = b"2222222222\n\x00"
    added_code1 = '''
        pusha
        mov     eax, 4
        mov     ebx, 1
        mov     ecx, {str1}
        mov     edx, %d
        int     0x80
        popa
    ''' % (len(test_str1))
    added_code2 = '''
        pusha
        mov     eax, 4
        mov     ebx, 1
        mov     ecx, {str2}
        mov     edx, %d
        int     0x80
        popa
    ''' % (len(test_str2))

    p1 = InsertCodePatch(0x8048457, added_code1, name="p1", priority=100)
    p2 = InsertCodePatch(0x8048457, added_code2, name="p2", priority=1)
    p3 = AddRODataPatch(test_str1, "str1")
    p4 = AddRODataPatch(test_str2, "str2")
    run_test("simple_i386_nopie", [p1,p2,p3,p4], expected_output=test_str1 + b"Hi")

    p1 = InsertCodePatch(0x8048457, added_code1, name="p1", priority=1)
    p2 = InsertCodePatch(0x8048457, added_code2, name="p2", priority=100)
    p3 = AddRODataPatch(test_str1, "str1")
    p4 = AddRODataPatch(test_str2, "str2")
    backend = run_test("simple_i386_nopie", [p1,p2,p3,p4], expected_output=test_str2 + b"Hi")
    assert p1 not in backend.added_patches
    assert p2 in backend.added_patches

    p1 = InsertCodePatch(0x8048457, added_code1, name="p1", priority=1)
    p2 = InsertCodePatch(0x8048457+3, added_code2, name="p2", priority=100)
    p3 = AddRODataPatch(test_str1, "str1")
    p4 = AddRODataPatch(test_str2, "str2")
    backend = run_test("simple_i386_nopie", [p1,p2,p3,p4], expected_output=test_str2 + b"Hi")
    assert p1 not in backend.added_patches
    assert p2 in backend.added_patches

    p1 = InsertCodePatch(0x8048457, added_code1, name="p1", priority=1)
    p2 = InsertCodePatch(0x8048457+0x11, added_code2, name="p2", priority=100)
    p3 = AddRODataPatch(test_str1, "str1")
    p4 = AddRODataPatch(test_str2, "str2")
    backend = run_test("simple_i386_nopie", [p1,p2,p3,p4], expected_output=test_str1 + test_str2 + b"Hi")
    assert p1 in backend.added_patches
    assert p2 in backend.added_patches

def test_conflicting_symbols():
    filepath = os.path.join(bin_location, "simple_i386_nopie")

    patches = []
    backend = DetourBackend(filepath)
    patches.append(AddRODataPatch(b"0123456789abcdef", "aaa"))
    patches.append(AddRODataPatch(b"\n", "aaa"))
    exc = False
    try:
        backend.apply_patches(patches)
    except ValueError:
        exc = True
    assert exc

    patches = []
    backend = DetourBackend(filepath)
    patches.append(AddRODataPatch(b"0123456789abcdef", "aaa"))
    added_code = '''
        pusha
        mov ebx, eax
        mov eax,7
        mov ecx,4
        mov edx, {aaa}
        int 0x80
        popa
        ret
    '''
    patches.append(AddCodePatch(added_code,"aaa"))
    exc = False
    try:
        backend.apply_patches(patches)
    except ValueError:
        exc = True
    assert exc

def run_test(file, patches, set_oep=None, input=None, expected_output=None, expected_returnCode=None):
    filepath = os.path.join(bin_location, file)
    pipe = subprocess.PIPE

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath)
        backend.apply_patches(patches)
        if set_oep:
            backend.set_oep(backend.name_map[set_oep])
        backend.save(tmp_file)
        p = subprocess.Popen([tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(input)
        print(res, p.returncode)
        if expected_output:
            assert res[0] == expected_output
        if expected_returnCode:
            assert p.returncode == expected_returnCode
        return backend
        
def run_all():
    functions = globals()
    all_functions = dict(filter((lambda x: x[0].startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            l.info("testing %s" % str(f))
            all_functions[f]()

if __name__ == "__main__":
    import sys
    logging.getLogger("patcherex.backends.DetourBackend").setLevel("INFO")
    logging.getLogger("patcherex.test.test_detourbackend").setLevel("INFO")
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
