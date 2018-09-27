#!/usr/bin/env python

import os
import nose
import struct
import subprocess
import logging
from functools import wraps

import patcherex
import shellphish_qemu
from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import *
from tracer import QEMURunner

l = logging.getLogger("patcherex.test.test_detourbackend")

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../test_binaries'))
qemu_location = shellphish_qemu.qemu_path('cgc-tracer')

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
        global_data_fallback = True
        global_try_pdf_removal = True
        f()
        global_data_fallback = None
        global_try_pdf_removal = False
        f()
        global_data_fallback = True
        global_try_pdf_removal = False
        f()
    return wrapper


@add_fallback_strategy
def test_simple_inline():
    filepath = os.path.join(bin_location, "0b32aa01_01_2")

    pipe = subprocess.PIPE
    p = subprocess.Popen([qemu_location, filepath], stdin=pipe, stdout=pipe, stderr=pipe)
    res = p.communicate(b"A" * 100)
    print(res, p.returncode)
    nose.tools.assert_equal((p.returncode != 0), True)

    expected = "\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \t\tYes, that's a palindrome!\n\n\tPlease enter a possible palindrome: "
    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        p = InlinePatch(0x8048291, "mov DWORD [esp+8], 0x40;", name="asdf")
        backend.apply_patches([p])
        backend.save(tmp_file)
        # backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"A"*100)
        print(res, p.returncode)
        nose.tools.assert_equal((res[0] == expected and p.returncode == 0), True)


def test_added_code():
    filepath = os.path.join(bin_location, "0b32aa01_01_2")
    pipe = subprocess.PIPE

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        added_code = '''
            mov     eax, 1
            mov     ebx, 0x32
            int     80h
        '''
        p = AddCodePatch(added_code, "aaa")
        backend.apply_patches([p])
        backend.set_oep(backend.name_map["aaa"])
        backend.save(tmp_file)
        # backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"A"*10 + b"\n")
        print(res, p.returncode)
        nose.tools.assert_equal(p.returncode == 0x32, True)


def test_added_code_and_data():
    filepath = os.path.join(bin_location, "0b32aa01_01_2")
    pipe = subprocess.PIPE

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        test_str = "testtesttest\n\x00"
        added_code = '''
            mov     eax, 2
            mov     ebx, 0
            mov     ecx, {added_data}
            mov     edx, %d
            mov     esi, 0
            int     80h
            mov     eax, 1
            mov     ebx, 0x33
            int     80h
        ''' % (len(test_str))
        p1 = AddCodePatch(added_code, "aaa")
        p2 = AddRODataPatch(test_str, "added_data")
        backend.apply_patches([p1,p2])
        backend.set_oep(backend.name_map["aaa"])
        backend.save(tmp_file)

        # backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"A"*10 + b"\n")
        print(res, p.returncode)
        nose.tools.assert_equal(test_str in res[0] and p.returncode == 0x33, True)


@add_fallback_strategy
def test_rw_memory():
    filepath = os.path.join(bin_location, "CROMU_00070")
    pipe = subprocess.PIPE

    tlen=1
    lenlist = []
    lenlist.append(0)
    lenlist.append(1)
    #lenlist.append(4)
    #lenlist.append(5)
    #lenlist.append(0x501)
    #lenlist.append(0x1000)
    #lenlist.append(0x1000-1)
    #lenlist.append(0x1000+1)
    lenlist.append(0x2000+1)

    for tlen in lenlist:
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        patches = []
        patches.append(AddRWDataPatch(tlen, "added_data_rw"))

        patches.append(AddRODataPatch("0123456789abcdef", "hex_array"))
        added_code = '''
            ; eax=buf,ebx=len
            pusha
            mov ecx,eax
            mov edx,ebx
            mov eax,0x2
            mov ebx,0x1
            mov esi,0x0
            int 0x80
            popa
            ret
        '''
        patches.append(AddCodePatch(added_code,"print"))
        added_code = '''
            ; print eax as hex
            pusha
            mov ecx,32
            mov ebx,eax
            _print_reg_loop:
                rol ebx,4
                mov edi,ebx
                and edi,0x0000000f
                lea eax,[{hex_array}+edi]
                mov ebp,ebx
                mov ebx,0x1
                call {print}
                mov ebx,ebp
                sub ecx,4
                jnz _print_reg_loop
            popa
            ret
        '''
        patches.append(AddCodePatch(added_code,"print_hex_eax"))
        added_code = '''
            xor eax, eax
            mov edx, {added_data_rw}
            mov ecx, edx
            add ecx, %d
            _loop:
                cmp edx,ecx
                je _exit
                xor ebx, ebx
                mov bl, BYTE [edx]
                add eax, ebx
                mov BYTE [edx], 0x3
                add edx, 1
                jmp _loop
            _exit
            call {print_hex_eax}
        ''' % tlen
        patches.append(AddEntryPointPatch(added_code,"sum"))

        with patcherex.utils.tempdir() as td:
            tmp_file = os.path.join(td, "patched")
            backend.apply_patches(patches)
            backend.save(tmp_file)
            #backend.save("../../vm/shared/patched")
            p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
            res = p.communicate(b"\x00\x01\x01" + b"A"*1000 + b"\n")
            print(str(tlen) + ":")
            print(res, p.returncode)

        nose.tools.assert_true(p.returncode==255)
        nose.tools.assert_true(res[0].startswith("00000000"))


def test_ro_memory():
    filepath = os.path.join(bin_location, "CROMU_00070")
    pipe = subprocess.PIPE

    tlen=1
    lenlist = []
    lenlist.append(0)
    lenlist.append(1)
    #lenlist.append(4)
    #lenlist.append(5)
    #lenlist.append(0x501)
    #lenlist.append(0x1000)
    #lenlist.append(0x1000-1)
    #lenlist.append(0x1000+1)
    lenlist.append(0x2000+1)

    for tlen in lenlist:
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        patches = []
        patches.append(AddRODataPatch("\x01"*tlen, "added_data_rw"))

        patches.append(AddRODataPatch("0123456789abcdef", "hex_array"))
        added_code = '''
            ; eax=buf,ebx=len
            pusha
            mov ecx,eax
            mov edx,ebx
            mov eax,0x2
            mov ebx,0x1
            mov esi,0x0
            int 0x80
            popa
            ret
        '''
        patches.append(AddCodePatch(added_code,"print"))
        added_code = '''
            ; print eax as hex
            pusha
            mov ecx,32
            mov ebx,eax
            _print_reg_loop:
                rol ebx,4
                mov edi,ebx
                and edi,0x0000000f
                lea eax,[{hex_array}+edi]
                mov ebp,ebx
                mov ebx,0x1
                call {print}
                mov ebx,ebp
                sub ecx,4
                jnz _print_reg_loop
            popa
            ret
        '''
        patches.append(AddCodePatch(added_code,"print_hex_eax"))
        added_code = '''
            xor eax, eax
            mov edx, {added_data_rw}
            mov ecx, edx
            add ecx, %d
            _loop:
                cmp edx,ecx
                je _exit
                xor ebx, ebx
                mov bl, BYTE [edx]
                add eax, ebx
                ; mov BYTE [edx], 0x3
                add edx, 1
                jmp _loop
            _exit
            call {print_hex_eax}
        ''' % tlen
        patches.append(AddEntryPointPatch(added_code,"sum"))

        with patcherex.utils.tempdir() as td:
            tmp_file = os.path.join(td, "patched")
            backend.apply_patches(patches)
            backend.save(tmp_file)
            #backend.save("../../vm/shared/patched")
            p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
            res = p.communicate(b"\x00\x01\x01" + b"A"*1000 + b"\n")
            print(str(tlen) + ":")
            print(res, p.returncode)

        nose.tools.assert_true(p.returncode==255)
        expected = struct.pack(">I", tlen).hex()
        print(expected)
        nose.tools.assert_true(res[0].startswith(expected))


def test_rwinit_memory():
    filepath = os.path.join(bin_location, "CROMU_00070")
    pipe = subprocess.PIPE

    tlen=1
    lenlist = []
    lenlist.append(0)
    lenlist.append(1)
    #lenlist.append(4)
    #lenlist.append(5)
    #lenlist.append(0x501)
    #lenlist.append(0x1000)
    #lenlist.append(0x1000-1)
    #lenlist.append(0x1000+1)
    lenlist.append(0x2000+1)

    for tlen in lenlist:
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        patches = []
        patches.append(AddRWInitDataPatch("\x02"*tlen, "added_data_rwinit"))

        patches.append(AddRODataPatch("0123456789abcdef", "hex_array"))
        added_code = '''
            ; eax=buf,ebx=len
            pusha
            mov ecx,eax
            mov edx,ebx
            mov eax,0x2
            mov ebx,0x1
            mov esi,0x0
            int 0x80
            popa
            ret
        '''
        patches.append(AddCodePatch(added_code,"print"))
        added_code = '''
            ; print eax as hex
            pusha
            mov ecx,32
            mov ebx,eax
            _print_reg_loop:
                rol ebx,4
                mov edi,ebx
                and edi,0x0000000f
                lea eax,[{hex_array}+edi]
                mov ebp,ebx
                mov ebx,0x1
                call {print}
                mov ebx,ebp
                sub ecx,4
                jnz _print_reg_loop
            popa
            ret
        '''
        patches.append(AddCodePatch(added_code,"print_hex_eax"))
        added_code = '''
            xor eax, eax
            mov edx, {added_data_rwinit}
            mov ecx, edx
            add ecx, %d
            _loop:
                cmp edx,ecx
                je _exit
                xor ebx, ebx
                mov bl, BYTE [edx]
                add eax, ebx
                mov BYTE [edx], 0x3
                add edx, 1
                jmp _loop
            _exit
            call {print_hex_eax}
        ''' % tlen
        patches.append(AddEntryPointPatch(added_code,"sum"))

        with patcherex.utils.tempdir() as td:
            tmp_file = os.path.join(td, "patched")
            backend.apply_patches(patches)
            backend.save(tmp_file)
            #backend.save("../../vm/shared/patched")
            p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
            res = p.communicate(b"\x00\x01\x01" + b"A"*1000 + b"\n")
            print(str(tlen) + ":")
            print(res, p.returncode)

        nose.tools.assert_true(p.returncode==255)
        expected = struct.pack(">I", tlen * 2).hex()
        print(expected)
        nose.tools.assert_true(res[0].startswith(expected))


def test_added_code_and_data_complex():
    filepath = os.path.join(bin_location, "CROMU_00070")
    pipe = subprocess.PIPE

    common_patches = []
    patches = []
    common_patches.append(AddRODataPatch("ro1ro1ro1\n\x00", "added_data_ro1"))
    common_patches.append(AddRWDataPatch(10, "added_data_rw1"))
    common_patches.append(AddRWInitDataPatch("ri1ri1ri1\n\x00", "added_data_rwinit1"))
    common_patches.append(AddRODataPatch("ro2ro2ro2\n\x00", "added_data_ro2"))
    common_patches.append(AddRWDataPatch(10, "added_data_rw2"))
    common_patches.append(AddRWInitDataPatch("ri2ri2ri2\n\x00", "added_data_rwinit2"))
    common_patches.append(AddRODataPatch("ro3ro3ro3\n\x00", "added_data_ro3"))
    common_patches.append(AddRWDataPatch(10, "added_data_rw3"))
    common_patches.append(AddRWInitDataPatch("ri3ri3ri3\n\x00", "added_data_rwinit3"))
    added_code = '''
        ; eax=buf,ebx=len
        pusha
        mov ecx,eax
        mov edx,ebx
        mov eax,0x2
        mov ebx,0x1
        mov esi,0x0
        int 0x80
        popa
        ret
    '''
    common_patches.append(AddCodePatch(added_code,"print"))
    added_code='''
        mov eax, {added_data_ro1}
        mov ebx, 10
        call {print}
        mov eax, {added_data_rw1}
        mov ebx, 10
        call {print}
        mov eax, {added_data_rwinit1}
        mov ebx, 10
        call {print}
        mov eax, {added_data_ro2}
        mov ebx, 10
        call {print}
        mov eax, {added_data_rw2}
        mov ebx, 10
        call {print}
        mov eax, {added_data_rwinit2}
        mov ebx, 10
        call {print}
        mov eax, {added_data_ro3}
        mov ebx, 10
        call {print}
        mov eax, {added_data_rw3}
        mov ebx, 10
        call {print}
        mov eax, {added_data_rwinit3}
        mov ebx, 10
        call {print}
        ret
    '''
    common_patches.append(AddCodePatch(added_code,"dump"))

    with patcherex.utils.tempdir() as td:
        expected = "ro1ro1ro1\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00ri1ri1ri1\nro2ro2ro2\n\x00" \
                        "\x00\x00\x00\x00\x00\x00\x00\x00\x00ri2ri2ri2\nro3ro3ro3\n\x00\x00\x00\x00" \
                        "\x00\x00\x00\x00\x00\x00ri3ri3ri3\nro1ro1ro1\nDCBA\x00\x00\x00\x00\x00\x00" \
                        "ri1ri1ri1\nro2ro2ro2\nHGFE\x00\x00\x00\x00\x00\x00ri2ri2ri2\nro3ro3ro3\nLKJI" \
                        "\x00\x00\x00\x00\x00\x00ri3ri3ri3\nro1ro1ro1\nDCBA\x00\x00\x00\x00\x00\x00DCBA" \
                        "i1ri1\nro2ro2ro2\nHGFE\x00\x00\x00\x00\x00\x00HGFEi2ri2\nro3ro3ro3\nLKJI\x00\x00" \
                        "\x00\x00\x00\x00LKJIi3ri3\n\x00\x02\x00\x00\x02"
        tmp_file = os.path.join(td, "patched1")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        patches = [p for p in common_patches]
        added_code = '''
            call {dump}
            mov DWORD [{added_data_rw1}], 0x41424344
            mov DWORD [{added_data_rw2}], 0x45464748
            mov DWORD [{added_data_rw3}], 0x494a4b4c
            call {dump}
            mov DWORD [{added_data_rwinit1}], 0x41424344
            mov DWORD [{added_data_rwinit2}], 0x45464748
            mov DWORD [{added_data_rwinit3}], 0x494a4b4c
            call {dump}
        '''
        patches.append(AddEntryPointPatch(added_code))

        backend.apply_patches(patches)
        backend.save(tmp_file)
        # backend.save("../../vm/shared/patched")
        #for k,v in backend.name_map.iteritems():
            #print k,hex(v)
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"\x00\x01\x01" + b"A"*1000 + b"\n")
        print(res, p.returncode)
        nose.tools.assert_equal(expected == res[0] and p.returncode == 255, True)

        expected = "ro1ro1ro1\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00ri1ri1ri1\nro2ro2ro2\n\x00\x00\x00" \
                            "\x00\x00\x00\x00\x00\x00\x00ri2ri2ri2\nro3ro3ro3\n\x00\x00\x00\x00\x00\x00\x00" \
                            "\x00\x00\x00ri3ri3ri3\nro1ro1ro1\nDCBA\x00\x00\x00\x00\x00\x00ri1ri1ri1\nro2ro2ro2" \
                            "\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00HGFEi2ri2\nro3ro3ro3\nLKJI\x00\x00\x00\x00" \
                            "\x00\x00ri3ri3ri3\n"
        tmp_file = os.path.join(td, "patched2")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        patches = [p for p in common_patches]
        added_code = '''
            call {dump}
            mov DWORD [{added_data_rw1}], 0x41424344
            mov DWORD [{added_data_rwinit2}], 0x45464748
            mov DWORD [{added_data_rw3}], 0x494a4b4c
            call {dump}
            mov DWORD [{added_data_ro2}], 0x41424344 ;segfault with no fallback
        '''
        patches.append(AddEntryPointPatch(added_code))

        backend.apply_patches(patches)
        backend.save(tmp_file)
        # backend.save("../../vm/shared/patched")
        #for k,v in backend.name_map.iteritems():
        #    print k,hex(v)
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"\x00\x01\x01" + b"A" * 1000 + b"\n")
        print(res, p.returncode)

        # this is a special case in which fallback we get different results if data_fallback is used!
        if global_data_fallback==True:
            nose.tools.assert_equal(res[0].startswith(expected) and p.returncode == 255, True)
        else:
            nose.tools.assert_equal(expected == res[0] and p.returncode == -11, True)


def test_added_code_and_data_big():
    filepath = os.path.join(bin_location, "0b32aa01_01_2")
    pipe = subprocess.PIPE

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        test_str = "".join([chr(x) for x in range(256)])*40
        added_code = '''
            mov     eax, 2
            mov     ebx, 0
            mov     ecx, {added_data}
            mov     edx, %d
            mov     esi, 0
            int     80h
            mov     eax, 1
            mov     ebx, 0x33
            int     80h
        ''' % (len(test_str))
        p1 = AddCodePatch(added_code, "aaa")
        p2 = AddRODataPatch(test_str, "added_data")
        backend.apply_patches([p1,p2])
        backend.set_oep(backend.name_map["aaa"])
        backend.save(tmp_file)

        # backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"A" * 10 + b"\n")
        #print res, p.returncode
        nose.tools.assert_equal(test_str in res[0] and p.returncode == 0x33, True)


def test_detour():
    filepath = os.path.join(bin_location, "0b32aa01_01_2")
    pipe = subprocess.PIPE

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        test_str = "qwertyuiop\n\x00"
        added_code = '''
            mov     eax, 2
            mov     ebx, 0
            mov     ecx, {qq}
            mov     edx, %d
            mov     esi, 0
            int     80h
        ''' % (len(test_str))
        p1 = InsertCodePatch(0x80480A6, added_code)
        p2 = AddRODataPatch(test_str, "qq")
        backend.apply_patches([p1,p2])
        backend.save(tmp_file)
        # backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"A" * 10 + b"\n")
        #print res, p.returncode
        expected = "qwertyuiop\n\x00\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \t\tYes, " \
                   "that's a palindrome!\n\n\tPlease enter a possible palindrome: "
        nose.tools.assert_equal(res[0], expected)


def test_single_entry_point_patch():
    filepath = os.path.join(bin_location, "0b32aa01_01_2")
    pipe = subprocess.PIPE

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        added_code = '''
            mov     eax, 2
            mov     ebx, 0
            mov     ecx, 0x08048786
            mov     edx, 15
            mov     esi, 0
            int     80h
        '''
        p = AddEntryPointPatch(added_code)
        backend.apply_patches([p])
        backend.save(tmp_file)
        # backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"A" * 10 + b"\n")
        print(res, p.returncode)
        nose.tools.assert_equal("\n\nEASTER EGG!\n\n" in res[0] and p.returncode == 0, True)


def test_complex1():
    filepath = os.path.join(bin_location, "0b32aa01_01_2")
    pipe = subprocess.PIPE

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)

        patches = []
        added_code = '''
            mov     eax, 2
            mov     ebx, 0
            mov     ecx, 0x08048786
            mov     edx, 15
            mov     esi, 0
            int     80h
            call    {added_function}
        '''
        patches.append(AddEntryPointPatch(added_code))
        added_code = '''
            mov     eax, 1
            mov     ebx, 0x34
            int     80h
        '''
        patches.append(AddEntryPointPatch(added_code))
        test_str = "testtesttest\n\x00"
        added_code = '''
            mov     eax, 2
            mov     ebx, 0
            mov     ecx, {added_data}
            mov     edx, %d
            mov     esi, 0
            int     80h
            ret
        ''' % (len(test_str))
        patches.append(AddCodePatch(added_code, "added_function"))
        patches.append(AddRODataPatch(test_str, "added_data"))
        backend.apply_patches(patches)
        backend.save(tmp_file)
        # backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"A" * 10 + b"\n")
        print(res, p.returncode)
        nose.tools.assert_equal("\n\nEASTER EGG!\n\n"+test_str in res[0] and p.returncode == 52, True)


def test_double_patch_collision():
    filepath = os.path.join(bin_location, "CADET_00003")
    pipe = subprocess.PIPE

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        test_str1 = "1111111111\n\x00"
        test_str2 = "2222222222\n\x00"
        added_code1 = '''
            pusha
            mov     eax, 2
            mov     ebx, 0
            mov     ecx, {str1}
            mov     edx, %d
            mov     esi, 0
            int     80h
            popa
        ''' % (len(test_str1))
        added_code2 = '''
            pusha
            mov     eax, 2
            mov     ebx, 0
            mov     ecx, {str2}
            mov     edx, %d
            mov     esi, 0
            int     80h
            popa
        ''' % (len(test_str2))

        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        p1 = InsertCodePatch(0x080480A0, added_code1, name="p1", priority=100)
        p2 = InsertCodePatch(0x080480A0, added_code2, name="p2", priority=1)
        p3 = AddRODataPatch(test_str1, "str1")
        p4 = AddRODataPatch(test_str2, "str2")
        backend.apply_patches([p1,p2,p3,p4])
        backend.save(tmp_file)
        nose.tools.assert_equal(p1 in backend.added_patches, True)
        nose.tools.assert_equal(p2 in backend.added_patches, False)
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"A" * 10 + b"\n")
        print(res, p.returncode)
        print(map(hex,backend.touched_bytes))
        expected = test_str1 + "\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \t\tYes, " \
                   "that's a palindrome!\n\n\tPlease enter a possible palindrome: "
        nose.tools.assert_equal(res[0], expected)

        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        p1 = InsertCodePatch(0x080480A0, added_code1, name="p1", priority=1)
        p2 = InsertCodePatch(0x080480A0, added_code2, name="p2", priority=100)
        p3 = AddRODataPatch(test_str1, "str1")
        p4 = AddRODataPatch(test_str2, "str2")
        backend.apply_patches([p1,p2,p3,p4])
        backend.save(tmp_file)
        nose.tools.assert_equal(p1 in backend.added_patches, False)
        nose.tools.assert_equal(p2 in backend.added_patches, True)
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"A" * 10 + b"\n")
        print(res, p.returncode)
        print(map(hex,backend.touched_bytes))
        expected = test_str2 + "\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \t\tYes, " \
                   "that's a palindrome!\n\n\tPlease enter a possible palindrome: "
        nose.tools.assert_equal(res[0], expected)

        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        p1 = InsertCodePatch(0x080480A0, added_code1, name="p1", priority=1)
        #partial overlap
        p2 = InsertCodePatch(0x080480A0+3, added_code2, name="p2", priority=100)
        p3 = AddRODataPatch(test_str1, "str1")
        p4 = AddRODataPatch(test_str2, "str2")
        backend.apply_patches([p1,p2,p3,p4])
        backend.save(tmp_file)
        nose.tools.assert_equal(p1 in backend.added_patches, False)
        nose.tools.assert_equal(p2 in backend.added_patches, True)
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"A" * 10 + b"\n")
        print(res, p.returncode)
        print(map(hex,backend.touched_bytes))
        expected = test_str2 + "\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \t\tYes, " \
                   "that's a palindrome!\n\n\tPlease enter a possible palindrome: "
        nose.tools.assert_equal(res[0], expected)

        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        p1 = InsertCodePatch(0x080480A0, added_code1, name="p1", priority=1)
        #no overlap
        p2 = InsertCodePatch(0x080480A0+0x11, added_code2, name="p2", priority=100)
        p3 = AddRODataPatch(test_str1, "str1")
        p4 = AddRODataPatch(test_str2, "str2")
        backend.apply_patches([p1,p2,p3,p4])
        backend.save(tmp_file)
        nose.tools.assert_equal(p1 in backend.added_patches, True)
        nose.tools.assert_equal(p2 in backend.added_patches, True)
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"A"*10 + b"\n")
        print(res, p.returncode)
        print(map(hex,backend.touched_bytes))
        expected = test_str1 + test_str2 + "\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \t\tYes, " \
                   "that's a palindrome!\n\n\tPlease enter a possible palindrome: "
        nose.tools.assert_equal(res[0], expected)


def test_conflicting_symbols():
    filepath = os.path.join(bin_location, "0b32aa01_01_2")

    patches = []
    backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
    patches.append(AddRODataPatch("0123456789abcdef", "aaa"))
    patches.append(AddRODataPatch("\n", "aaa"))
    exc = False
    try:
        backend.apply_patches(patches)
    except ValueError:
        exc = True
    nose.tools.assert_true(exc)

    patches = []
    backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
    patches.append(AddRODataPatch("0123456789abcdef", "aaa"))
    added_code = '''
        ; put 4 random bytes in eax
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
    nose.tools.assert_true(exc)


def test_random_canary():
    def check_output(tstr):
        expected = "\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \t\tYes, that's a palindrome!\n\n\tPlease enter a possible palindrome: canary failure: 00000000 vs "
        init = "base canary value:"
        if not tstr.startswith(init):
            return False
        canary = tstr.split(init)[1].split()[0].strip()
        if expected not in tstr:
            return False
        if not tstr.endswith(canary):
            return False
        return True

    filepath = os.path.join(bin_location, "0b32aa01_01_2")
    pipe = subprocess.PIPE

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)

        patches = []
        patches.append(AddRODataPatch("0123456789abcdef", "hex_array"))
        patches.append(AddRODataPatch("\n", "new_line"))
        patches.append(AddRODataPatch("X"*4, "saved_canary"))
        patches.append(AddRODataPatch("base canary value: \x00","str_bcanary"))
        patches.append(AddRODataPatch("canary failure: \x00","str_fcanary"))
        patches.append(AddRODataPatch(" vs \x00","str_vs"))

        added_code = '''
            ; print eax as hex
            pusha
            mov ecx,32
            mov ebx,eax
            _print_reg_loop:
                rol ebx,4
                mov edi,ebx
                and edi,0x0000000f
                lea eax,[{hex_array}+edi]
                mov ebp,ebx
                mov ebx,0x1
                call {print}
                mov ebx,ebp
                sub ecx,4
                jnz _print_reg_loop
            popa
            ret
        '''
        patches.append(AddCodePatch(added_code,"print_hex_eax"))

        added_code = '''
            ; eax=buf,ebx=len
            pusha
            mov ecx,eax
            mov edx,ebx
            mov eax,0x2
            mov ebx,0x1
            mov esi,0x0
            int 0x80
            popa
            ret
        '''
        patches.append(AddCodePatch(added_code,"print"))

        added_code = '''
            mov     ebx, eax
            mov     eax, 0x1
            int     80h
        '''
        patches.append(AddCodePatch(added_code,"exit_eax"))

        added_code = '''
            ; put 4 random bytes in eax
            pusha
            mov ebx, eax
            mov eax,7
            mov ecx,4
            mov edx,0
            int 0x80
            popa
            ret
        '''
        patches.append(AddCodePatch(added_code,"random"))

        added_code = '''
            ; print a null terminated string pointed by eax
            pusha
            mov ecx, eax
            _loop:
                cmp BYTE [ecx],0
                je _out
                mov edx,1
                mov eax,0x2
                mov ebx,0x1
                mov esi,0x0
                int 0x80
                inc ecx
                jmp _loop
            _out:
            popa
            ret
        '''
        patches.append(AddCodePatch(added_code,"print_str"))

        added_code = '''
            ; print a null terminated string pointed by eax
            push eax
            mov eax, {str_fcanary}
            call {print_str}
            pop eax
            call {print_hex_eax}
            mov eax, {str_vs}
            call {print_str}
            mov eax, [{saved_canary}]
            call {print_hex_eax}
            mov eax, 0x44
            call {exit_eax}
        '''
        patches.append(AddCodePatch(added_code,"canary_check_fail"))

        added_code = '''
            mov eax, {saved_canary}
            call {random}
            xor eax, eax
            mov eax, {str_bcanary}
            call {print_str}
            mov eax, [{saved_canary}]
            call {print_hex_eax}
        '''
        patches.append(AddEntryPointPatch(added_code))

        added_code = '''
            push DWORD [{saved_canary}]
        '''
        patches.append(InsertCodePatch(0x08048230,added_code,"canary_push1"))
        added_code = '''
            push eax ; avoid changing eax
            mov eax, dword [esp+4]
            cmp eax, DWORD [{saved_canary}]
            jne {canary_check_fail}
            pop eax
            add esp, 4
        '''
        patches.append(InsertCodePatch(0x080483FF,added_code,"canary_pop1"))

        backend.apply_patches(patches)
        backend.save(tmp_file)
        # backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"A"*10 + b"\n" + b"\x00"*100)
        print(res, p.returncode)
        nose.tools.assert_equal(check_output(res[0]) and p.returncode == 0x44, True)


def test_patch_conflicts():
    def create_dpatch(tstr,addr,p):
        code = '''
            push ecx
            mov ecx, {s%s}
            call {print}
            pop ecx
        ''' % tstr
        return InsertCodePatch(addr,code,tstr,priority=p)

    def expected_str(plist):
        tstr = ""
        for p in plist:
            tstr += p.name + "\n\x00"
        return tstr + base_str

    def create_patches():
        p11=create_dpatch("11",0x08049920,2)
        p12=create_dpatch("12",0x08049920+1,1)
        p21=create_dpatch("21",0x0804992F,2)
        p22=create_dpatch("22",0x0804992F+0,1)
        p31=create_dpatch("31",0x08049947,2)
        p32=create_dpatch("32",0x08049947+0,1)
        p41=create_dpatch("41",0x08049953,2)
        p42=create_dpatch("42",0x08049953+3,1)
        return p11,p12,p21,p22,p31,p32,p41,p42

    filepath = os.path.join(bin_location, "CROMU_00071")
    pipe = subprocess.PIPE
    base_str = "Database checksum: "

    cpatches = []
    cpatches.append(AddRODataPatch("11\n\x00", "s11"))
    cpatches.append(AddRODataPatch("12\n\x00", "s12"))
    cpatches.append(AddRODataPatch("21\n\x00", "s21"))
    cpatches.append(AddRODataPatch("22\n\x00", "s22"))
    cpatches.append(AddRODataPatch("31\n\x00", "s31"))
    cpatches.append(AddRODataPatch("32\n\x00", "s32"))
    cpatches.append(AddRODataPatch("41\n\x00", "s41"))
    cpatches.append(AddRODataPatch("42\n\x00", "s42"))
    added_code = '''
        pusha
        mov     eax, 2
        mov     ebx, 0
        mov     edx, 4
        mov     esi, 0
        int     80h
        popa
        ret
    '''
    cpatches.append(AddCodePatch(added_code,"print"))

    with patcherex.utils.tempdir() as td:
        p11,p12,p21,p22,p31,p32,p41,p42 = create_patches()
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        backend.apply_patches(cpatches)
        backend.save(tmp_file)
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"A" * 10 + b"\n")
        print(res, p.returncode)
        nose.tools.assert_equal(p.returncode,1)
        estr = expected_str([])
        print(repr(estr))
        nose.tools.assert_true(res[0].startswith(estr))

        p11,p12,p21,p22,p31,p32,p41,p42 = create_patches()
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        backend.apply_patches(cpatches+[p11])
        backend.save(tmp_file)
        #backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"A"*10 + b"\n")
        print(res, p.returncode)
        nose.tools.assert_equal(p.returncode,1)
        estr = expected_str([p11])
        print(repr(estr))
        nose.tools.assert_true(res[0].startswith(estr))

        p11,p12,p21,p22,p31,p32,p41,p42 = create_patches()
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        backend.apply_patches(cpatches+[p11,p21,p31,p41])
        backend.save(tmp_file)
        #backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"A"*10 + b"\n")
        print(res, p.returncode)
        nose.tools.assert_equal(p.returncode,1)
        estr = expected_str([p11,p21,p31,p41])
        print(repr(estr))
        nose.tools.assert_true(res[0].startswith(estr))

        '''
        p11,p12,p21,p22,p31,p32,p41,p42 = create_patches()
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        backend.apply_patches(cpatches+[p12,p22,p32,p42])
        backend.save(tmp_file)
        #backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal(p.returncode,1)
        estr = expected_str([p12,p22,p32,p42])
        print repr(estr)
        nose.tools.assert_true(res[0].startswith(estr))

        p11,p12,p21,p22,p31,p32,p41,p42 = create_patches()
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        backend.apply_patches(cpatches+[p11,p21,p31,p41,p12])
        backend.save(tmp_file)
        #backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal(p.returncode,1)
        estr = expected_str([p11,p21,p31,p41])
        print repr(estr)
        nose.tools.assert_true(res[0].startswith(estr))

        p11,p12,p21,p22,p31,p32,p41,p42 = create_patches()
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        p31.dependencies = [p12]
        backend.apply_patches(cpatches+[p11,p21,p31,p41,p12])
        backend.save(tmp_file)
        #backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal(p.returncode,1)
        estr = expected_str([p11,p21,p41])
        print repr(estr)
        nose.tools.assert_true(res[0].startswith(estr))

        p11,p12,p21,p22,p31,p32,p41,p42 = create_patches()
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        p11.dependencies = [p12]
        p21.dependencies = [p12]
        p31.dependencies = [p12]
        p41.dependencies = [p12]
        backend.apply_patches(cpatches+[p11,p21,p31,p41,p12])
        backend.save(tmp_file)
        #backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal(p.returncode,1)
        estr = expected_str([])
        print repr(estr)
        nose.tools.assert_true(res[0].startswith(estr))

        p11,p12,p21,p22,p31,p32,p41,p42 = create_patches()
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        p31.dependencies = [p12]
        p12.dependencies = [p22]
        p22.dependencies = [p31]
        backend.apply_patches(cpatches+[p31,p12,p22])
        backend.save(tmp_file)
        #backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal(p.returncode,1)
        estr = expected_str([p12,p22,p31])
        print repr(estr)
        nose.tools.assert_true(res[0].startswith(estr))

        p11,p12,p21,p22,p31,p32,p41,p42 = create_patches()
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        p31.dependencies = [p12]
        p12.dependencies = [p22]
        p22.dependencies = [p31]
        backend.apply_patches(cpatches+[p31,p12,p22,p11])
        backend.save(tmp_file)
        #backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal(p.returncode,1)
        estr = expected_str([p11])
        print repr(estr)
        nose.tools.assert_true(res[0].startswith(estr))

        p11,p12,p21,p22,p31,p32,p41,p42 = create_patches()
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        p11.dependencies = [p12]
        backend.apply_patches(cpatches+[p11,p21,p31,p41,p12])
        backend.save(tmp_file)
        #backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal(p.returncode,1)
        estr = expected_str([p21,p31,p41])
        print repr(estr)
        nose.tools.assert_true(res[0].startswith(estr))

        p11,p12,p21,p22,p31,p32,p41,p42 = create_patches()
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        p21.dependencies = [p12]
        backend.apply_patches(cpatches+[p11,p21,p31,p41,p12])
        backend.save(tmp_file)
        #backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal(p.returncode,1)
        estr = expected_str([p11,p31,p41])
        print repr(estr)
        nose.tools.assert_true(res[0].startswith(estr))
        '''

        '''
        p11,p12,p21,p22,p31,p32,p41,p42 = create_patches()
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        p31.dependencies = [p12]
        backend.apply_patches(cpatches+[p11,p21,p31,p41,p12])
        backend.save(tmp_file)
        #backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal(p.returncode,1)
        estr = expected_str([p11,p21,p41])
        print repr(estr)
        nose.tools.assert_true(res[0].startswith(estr))

        p11,p12,p21,p22,p31,p32,p41,p42 = create_patches()
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        p41.dependencies = [p12]
        backend.apply_patches(cpatches+[p11,p21,p31,p41,p12])
        backend.save(tmp_file)
        #backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal(p.returncode,1)
        estr = expected_str([p11,p21,p31])
        print repr(estr)
        nose.tools.assert_true(res[0].startswith(estr))

        p11,p12,p21,p22,p31,p32,p41,p42 = create_patches()
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        p31.dependencies = [p12]
        p21.dependencies = [p42]
        backend.apply_patches(cpatches+[p11,p21,p31,p12,p42])
        backend.save(tmp_file)
        #backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal(p.returncode,1)
        estr = expected_str([p11,p21,p42])
        print repr(estr)
        nose.tools.assert_true(res[0].startswith(estr))

        p11,p12,p21,p22,p31,p32,p41,p42 = create_patches()
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        p31.dependencies = [p12]
        p21.dependencies = [p42]
        backend.apply_patches(cpatches+[p11,p21,p31,p12,p42,p41])
        backend.save(tmp_file)
        #backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal(p.returncode,1)
        estr = expected_str([p11,p41])
        print repr(estr)
        nose.tools.assert_true(res[0].startswith(estr))

        p11,p12,p21,p22,p31,p32,p41,p42 = create_patches()
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        p11.dependencies = [p42]
        p31.dependencies = [p12]
        p21.dependencies = [p42]
        backend.apply_patches(cpatches+[p11,p21,p31,p12,p42,p41])
        backend.save(tmp_file)
        #backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal(p.returncode,1)
        estr = expected_str([p41])
        print repr(estr)
        nose.tools.assert_true(res[0].startswith(estr))
        '''

        p11,p12,p21,p22,p31,p32,p41,p42 = create_patches()
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        p11.dependencies = [p21,p32]
        backend.apply_patches(cpatches+[p11,p21,p31,p32])
        backend.save(tmp_file)
        #backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate(b"A" * 10 + b"\n")
        print(res, p.returncode)
        nose.tools.assert_equal(p.returncode,1)
        estr = expected_str([p21,p31])
        print(repr(estr))
        nose.tools.assert_true(res[0].startswith(estr))


def test_c_compilation():
    filepath = os.path.join(bin_location, "CADET_00003")
    pipe = subprocess.PIPE

    common_patches = []
    added_code = '''
        ; print eax as hex
        pusha
        mov ecx,32
        mov ebx,eax
        _print_reg_loop:
            rol ebx,4
            mov edi,ebx
            and edi,0x0000000f
            lea eax,[{hex_array}+edi]
            mov ebp,ebx
            mov ebx,0x1
            call {print}
            mov ebx,ebp
            sub ecx,4
            jnz _print_reg_loop
        popa
        ret
    '''
    common_patches.append(AddCodePatch(added_code,"print_hex_eax"))
    added_code = '''
        ; eax=buf,ebx=len
        pusha
        mov ecx,eax
        mov edx,ebx
        mov eax,0x2
        mov ebx,0x1
        mov esi,0x0
        int 0x80
        popa
        ret
    '''
    common_patches.append(AddCodePatch(added_code,"print"))
    common_patches.append(AddRODataPatch("0123456789abcdef", "hex_array"))

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")

        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        patches = []
        patches.extend(common_patches)
        added_code = '''
        push ecx
        push edx
        mov ecx, 0x10
        mov edx, 0x20
        %s
        call {print_hex_eax}
        pop ecx
        pop edx
        ''' % patcherex.utils.get_nasm_c_wrapper_code("c_function",get_return=True)
        patches.append(InsertCodePatch(0x080480a0, added_code, name="p1", priority=1))
        added_code = '''
        __attribute__((fastcall)) int sub1(int a, int b){
            int c = a*b + 37;
            return c;
        }
        '''
        patches.append(AddCodePatch(added_code,"c_function",is_c=True))
        backend.apply_patches(patches)
        backend.save(tmp_file)
        #backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate()
        nose.tools.assert_equal(p.returncode,0)
        expected = "00000225\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: "
        nose.tools.assert_equal(res[0],expected)

        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        patches = []
        patches.append(AddRWDataPatch(10, "memory_area"))
        patches.extend(common_patches)
        added_code = '''
        push ecx
        push edx
        mov ecx, 0x10
        mov edx, {memory_area}
        mov eax, 0x100
        %s
        call {print_hex_eax}
        mov eax, DWORD [{memory_area}]
        call {print_hex_eax}
        pop ecx
        pop edx
        ''' % patcherex.utils.get_nasm_c_wrapper_code("c_function",get_return=False)
        patches.append(InsertCodePatch(0x080480a0, added_code, name="p1", priority=1))
        added_code = '''
        __attribute__((fastcall)) void sub1(int a, unsigned int* b){
            *b = a*3+2;
            return;
        }
        '''
        patches.append(AddCodePatch(added_code,"c_function",is_c=True))
        backend.apply_patches(patches)
        backend.save(tmp_file)
        #backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate()
        nose.tools.assert_equal(p.returncode,0)
        expected = "0000010000000032\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: "
        nose.tools.assert_equal(res[0],expected)

        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        patches = []
        patches.append(AddRWDataPatch(10, "memory_area"))
        patches.extend(common_patches)
        added_code = '''
        push ecx
        push edx
        mov ecx, 0x10
        mov edx, {memory_area}
        mov eax, 0x100
        %s
        call {print_hex_eax}
        mov eax, DWORD [{memory_area}]
        call {print_hex_eax}
        pop ecx
        pop edx
        ''' % patcherex.utils.get_nasm_c_wrapper_code("c_function",get_return=True)
        patches.append(InsertCodePatch(0x080480a0, added_code, name="p1", priority=1))
        added_code = '''
        __attribute__((fastcall)) void sub1(int a, unsigned int* b){
            *b = a*3+2;
            return;
        }
        '''
        patches.append(AddCodePatch(added_code,"c_function",is_c=True))
        backend.apply_patches(patches)
        backend.save(tmp_file)
        #backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate()
        nose.tools.assert_equal(p.returncode,0)
        expected = "0000003200000032\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: "
        nose.tools.assert_equal(res[0],expected)


def test_entrypointpatch_restore():
    filepath = os.path.join(bin_location, "0b32aa01_01_2")

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")

        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        patches = []
        patches.append(InsertCodePatch(0x80480a0, "jmp 0x4567890", "goto_crash"))
        backend.apply_patches(patches)
        backend.save(tmp_file)
        res = QEMURunner(tmp_file, "00000001\n", record_stdout=True, record_core=True)
        original_reg_value = res.reg_vals
        nose.tools.assert_equal(original_reg_value['eip'], 0x4567890)

        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        patches = []
        patches.append(InsertCodePatch(0x80480a0, "jmp 0x4567890", "goto_crash"))
        patches.append(AddEntryPointPatch("mov eax, 0x34567890", name="entry_patch1"))
        backend.apply_patches(patches)
        backend.save(tmp_file)
        res = QEMURunner(tmp_file, "00000001\n", record_stdout=True, record_core=True)
        nose.tools.assert_equal(original_reg_value, res.reg_vals)

        backend = DetourBackend(filepath,data_fallback=global_data_fallback,try_pdf_removal=global_try_pdf_removal)
        patches = []
        patches.append(InsertCodePatch(0x80480a0, "jmp 0x4567890", "goto_crash"))
        patches.append(AddEntryPointPatch("mov eax, 0x34567890", after_restore=True, name="entry_patch2"))
        backend.apply_patches(patches)
        backend.save(tmp_file)
        res = QEMURunner(tmp_file, "00000001\n", record_stdout=True, record_core=True)
        original_reg_value_mod = dict(original_reg_value)
        original_reg_value_mod['eax'] = 0x34567890
        nose.tools.assert_equal(original_reg_value_mod, res.reg_vals)


def test_piling():
    filepath = os.path.join(bin_location, "0b32aa01_01_2")

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")

        backend = DetourBackend(filepath,data_fallback=global_data_fallback)
        patches = []
        code_print_a = "mov eax, 2; \n" \
                       "mov ebx, 1; \n" \
                       "mov ecx, {the_first_string}; \n" \
                       "mov edx, 13; \n" \
                       "mov esi, 0; \n" \
                       "int 0x80;"
        code_print_b = "mov eax, 2; \n" \
                       "mov ebx, 1; \n" \
                       "mov ecx, {the_second_string}; \n" \
                       "mov edx, 8; \n" \
                       "mov esi, 0; \n" \
                       "int 0x80;"

        patches.append(AddRODataPatch("does it work\n", "the_first_string"))
        patches.append(AddRODataPatch("nope no\n", name="the_second_string"))
        patches.append(InsertCodePatch(0x80480a0, code_print_a, "test_code"))
        patches.append(InsertCodePatch(0x80480a0, code_print_b, name="second_add_code_patch", stackable=True))

        backend.apply_patches(patches)
        backend.save(tmp_file)
        res = QEMURunner(tmp_file, "abcdefg\n", record_stdout=True)
        expected = \
"""does it work
nope no

Welcome to Palindrome Finder

\tPlease enter a possible palindrome: 		Nope, that's not a palindrome

\tPlease enter a possible palindrome: """
        nose.tools.assert_true(res.stdout.startswith(expected))


def test_pdf_removal():
    # I am not using the decorator since I want to test for diffs between pdf removal or not
    # also, this test will obviously fail with any backend moving things in memory
    # I try to print all ro and rw data and compare between pdf and not pdf
    tests = [
                (os.path.join(bin_location, "CROMU_00071"),
                0x0804D790, 0x0804D9B8, 0x08062BD8, 0x08062BEC),
                (os.path.join(bin_location, "KPRCA_00046"),
                0x0804F868, 0x0805007C, 0x08064298, 0x0806891C)
            ]

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        for filepath, ro_start, ro_end, rw_start, rw_end in tests:
            patches = []
            osize = os.path.getsize(filepath)

            patches.append(AddRODataPatch("0123456789abcdef", "hex_array"))
            added_code = '''
                ; eax=buf,ebx=len
                pusha
                mov ecx,eax
                mov edx,ebx
                mov eax,0x2
                mov ebx,0x1
                mov esi,0x0
                int 0x80
                popa
                ret
            '''
            patches.append(AddCodePatch(added_code,"print"))
            added_code = '''
                ; print eax as hex
                pusha
                mov ecx,32
                mov ebx,eax
                _print_reg_loop:
                    rol ebx,4
                    mov edi,ebx
                    and edi,0x0000000f
                    lea eax,[{hex_array}+edi]
                    mov ebp,ebx
                    mov ebx,0x1
                    call {print}
                    mov ebx,ebp
                    sub ecx,4
                    jnz _print_reg_loop
                popa
                ret
            '''
            patches.append(AddCodePatch(added_code,"print_hex_eax"))
            code = '''
            mov ebx, 0x%08x
            mov ecx, 0x%08x
            mov edx, 0x%08x
            mov esi, 0x%08x
            mov edi, ebx
            _loop1:
                mov eax, DWORD [edi]
                call {print_hex_eax}
                cmp edi, ecx
                jg _exit1
                add edi, 4
                jmp _loop1
            _exit1:
            mov edi, edx
            _loop2:
                mov eax, DWORD [edi]
                mov DWORD [edi], 0
                call {print_hex_eax}
                cmp edi, esi
                jg _exit2
                add edi, 4
                jmp _loop2
            _exit2:
            ''' %(ro_start, ro_end, rw_start, rw_end)
            patches.append(AddEntryPointPatch(code))

            data_fallback = False
            backend = DetourBackend(filepath,data_fallback,try_pdf_removal=False)
            backend.apply_patches(patches)
            backend.save(tmp_file)
            # backend.save("../../vm/shared/patched")
            res = QEMURunner(tmp_file, "\n", record_stdout=True)
            nose.tools.assert_equal(res.reg_vals, None)
            original = res.stdout
            print(filepath)
            print(original)

            backend = DetourBackend(filepath,data_fallback,try_pdf_removal=True)
            backend.apply_patches(patches)
            backend.save(tmp_file)
            res = QEMURunner(tmp_file, "\n", record_stdout=True)
            nose.tools.assert_equal(res.reg_vals, None)
            mod = res.stdout
            fsize = os.path.getsize(tmp_file)
            print(hex(fsize), hex(osize))
            nose.tools.assert_true((osize - fsize) > 0x10000)
            nose.tools.assert_true(backend.pdf_removed)
            nose.tools.assert_equal(original,mod)

            data_fallback = True
            backend = DetourBackend(filepath,data_fallback,try_pdf_removal=True)
            backend.apply_patches(patches)
            backend.save(tmp_file)
            res = QEMURunner(tmp_file, "\n", record_stdout=True)
            nose.tools.assert_equal(res.reg_vals, None)
            mod = res.stdout
            fsize = os.path.getsize(tmp_file)
            print(hex(fsize), hex(osize))
            nose.tools.assert_true((osize - fsize) > 0x10000)
            nose.tools.assert_true(backend.pdf_removed)
            nose.tools.assert_equal(original,mod)


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

