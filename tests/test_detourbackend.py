#!/usr/bin/env python

import os
import nose
import struct
import subprocess
import logging

import patcherex
from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import *

l = logging.getLogger("patcherex.test.test_detourbackend")

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries-private'))
qemu_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../tracer/bin/tracer-qemu-cgc"))


def test_simple_inline():
    filepath = os.path.join(bin_location, "cgc_scored_event_2/cgc/0b32aa01_01")

    pipe = subprocess.PIPE
    p = subprocess.Popen([qemu_location, filepath], stdin=pipe, stdout=pipe, stderr=pipe)
    res = p.communicate("A"*100)
    print res, p.returncode
    nose.tools.assert_equal((p.returncode != 0), True)

    expected = "\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \t\tYes, that's a palindrome!\n\n\tPlease enter a possible palindrome: "
    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath)
        p = InlinePatch(0x8048291, "mov DWORD [esp+8], 0x40;", name="asdf")
        backend.apply_patches([p])
        backend.save(tmp_file)
        # backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*100)
        print res, p.returncode
        nose.tools.assert_equal((res[0] == expected and p.returncode == 0), True)


def test_added_code():
    filepath = os.path.join(bin_location, "cgc_scored_event_2/cgc/0b32aa01_01")
    pipe = subprocess.PIPE

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath)
        added_code = '''
            mov     eax, 1
            mov     ebx, 0x32
            int     80h
        '''
        p = AddCodePatch(added_code, "aaa")
        backend.apply_patches([p])
        backend.set_oep(backend.name_map["ADDED_CODE_START"])
        backend.save(tmp_file)
        # backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal(p.returncode == 0x32, True)


def test_added_code_and_data():
    filepath = os.path.join(bin_location, "cgc_scored_event_2/cgc/0b32aa01_01")
    pipe = subprocess.PIPE

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath)
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
        backend.set_oep(backend.name_map["ADDED_CODE_START"])
        backend.save(tmp_file)

        # backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal(test_str in res[0] and p.returncode == 0x33, True)


def test_added_code_and_data_complex():
    filepath = os.path.join(bin_location, "cgc_trials/last_trial/original/CROMU_00070")
    #TODO test with CADET, test with fallback, adapt all techinques, remove basebackend, full test detour backend with fallback (duplicate code in each function)
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
        tmp_file = os.path.join(td, "patched1")
        backend = DetourBackend(filepath)
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
        #backend.save("../../vm/shared/patched")
        for k,v in backend.name_map.iteritems():
            print k,hex(v)
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("\x00\x01\x01"+"A"*1000+"\n")
        print res, p.returncode
        #nose.tools.assert_equal(test_str in res[0] and p.returncode == 0x33, True)

        tmp_file = os.path.join(td, "patched2")
        backend = DetourBackend(filepath)
        patches = [p for p in common_patches]
        added_code = '''
            call {dump}
            mov DWORD [{added_data_rw1}], 0x41424344
            mov DWORD [{added_data_rwinit2}], 0x45464748
            mov DWORD [{added_data_rw3}], 0x494a4b4c
            call {dump}
            mov DWORD [{added_data_ro2}], 0x41424344 ;segfault
        '''
        patches.append(AddEntryPointPatch(added_code))

        backend.apply_patches(patches)
        backend.save(tmp_file)
        #backend.save("../../vm/shared/patched")
        for k,v in backend.name_map.iteritems():
            print k,hex(v)
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("\x00\x01\x01"+"A"*1000+"\n")
        print res, p.returncode
        #nose.tools.assert_equal(test_str in res[0] and p.returncode == 0x33, True)



def test_added_code_and_data_big():
    filepath = os.path.join(bin_location, "cgc_scored_event_2/cgc/0b32aa01_01")
    pipe = subprocess.PIPE

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath)
        test_str = "".join([chr(x) for x in xrange(256)])*40
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
        backend.set_oep(backend.name_map["ADDED_CODE_START"])
        backend.save(tmp_file)

        # backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        #print res, p.returncode
        nose.tools.assert_equal(test_str in res[0] and p.returncode == 0x33, True)


def test_added_code_and_data_fallback():
    filepath = os.path.join(bin_location, "cgc_scored_event_2/cgc/0b32aa01_01")
    pipe = subprocess.PIPE

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=True)
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
        backend.set_oep(backend.name_map["ADDED_CODE_START"])
        backend.save(tmp_file)

        # backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal(test_str in res[0] and p.returncode == 0x33, True)


def test_added_code_and_data_big_fallback():
    filepath = os.path.join(bin_location, "cgc_scored_event_2/cgc/0b32aa01_01")
    pipe = subprocess.PIPE

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath,data_fallback=True)
        test_str = "".join([chr(x) for x in xrange(256)])*40
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
        backend.set_oep(backend.name_map["ADDED_CODE_START"])
        backend.save(tmp_file)

        # backend.save("../../vm/shared/patched")
        p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        #print res, p.returncode
        nose.tools.assert_equal(test_str in res[0] and p.returncode == 0x33, True)


def test_detour():
    filepath = os.path.join(bin_location, "cgc_scored_event_2/cgc/0b32aa01_01")
    pipe = subprocess.PIPE

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath)
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
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        expected = "qwertyuiop\n\x00\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \t\tYes, " \
                   "that's a palindrome!\n\n\tPlease enter a possible palindrome: "
        nose.tools.assert_equal(res[0], expected)


def test_single_entry_point_patch():
    filepath = os.path.join(bin_location, "cgc_scored_event_2/cgc/0b32aa01_01")
    pipe = subprocess.PIPE

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath)
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
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal("\n\nEASTER EGG!\n\n" in res[0] and p.returncode == 0, True)


def test_complex1():
    filepath = os.path.join(bin_location, "cgc_scored_event_2/cgc/0b32aa01_01")
    pipe = subprocess.PIPE

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath)

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
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal("\n\nEASTER EGG!\n\n"+test_str in res[0] and p.returncode == 52, True)


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

    filepath = os.path.join(bin_location, "cgc_scored_event_2/cgc/0b32aa01_01")
    pipe = subprocess.PIPE

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = DetourBackend(filepath)

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
        res = p.communicate("A"*10+"\n"+"\x00"*100)
        print res, p.returncode
        nose.tools.assert_equal(check_output(res[0]) and p.returncode == 0x44, True)


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
    logging.getLogger("patcherex.test.test_detourbackend").setLevel("INFO")
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
