#!/usr/bin/env python

import os
import nose
import subprocess
import patcherex
from patcherex.patches import *


# TODO ideally these tests should be run in the vm

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries-private'))


def test_simple_inline():
    filepath = os.path.join(bin_location, "cgc_scored_event_2/cgc/0b32aa01_01")

    pipe = subprocess.PIPE
    p = subprocess.Popen(["../../tracer/bin/tracer-qemu-cgc", filepath], stdin=pipe, stdout=pipe, stderr=pipe)
    res = p.communicate("A"*100)
    print res, p.returncode
    nose.tools.assert_equal((p.returncode != 0), True)

    expected = "\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \t\tYes, that's a palindrome!\n\n\tPlease enter a possible palindrome: "
    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = patcherex.Patcherex(filepath)
        p = InlinePatch(0x8048291, "mov DWORD [esp+8], 0x40;", name="asdf")
        backend.apply_patches([p])
        backend.save(tmp_file)
        # backend.save("../../vm/shared/patched")
        p = subprocess.Popen(["../../tracer/bin/tracer-qemu-cgc", tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*100)
        print res, p.returncode
        nose.tools.assert_equal((res[0] == expected and p.returncode == 0), True)


def test_added_code():
    filepath = os.path.join(bin_location, "cgc_scored_event_2/cgc/0b32aa01_01")
    pipe = subprocess.PIPE

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = patcherex.Patcherex(filepath)
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
        p = subprocess.Popen(["../../tracer/bin/tracer-qemu-cgc", tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal(p.returncode == 0x32, True)


def test_added_code_and_data():
    filepath = os.path.join(bin_location, "cgc_scored_event_2/cgc/0b32aa01_01")
    pipe = subprocess.PIPE

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = patcherex.Patcherex(filepath)
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
        p2 = AddDataPatch(test_str, "added_data")
        backend.apply_patches([p1,p2])
        backend.set_oep(backend.name_map["ADDED_CODE_START"])
        backend.save(tmp_file)
        # backend.save("../../vm/shared/patched")
        p = subprocess.Popen(["../../tracer/bin/tracer-qemu-cgc", tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal(test_str in res[0] and p.returncode == 0x33, True)


def test_detour():
    filepath = os.path.join(bin_location, "cgc_scored_event_2/cgc/0b32aa01_01")
    pipe = subprocess.PIPE

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = patcherex.Patcherex(filepath)
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
        p2 = AddDataPatch(test_str, "qq")
        backend.apply_patches([p1,p2])
        backend.save(tmp_file)
        # backend.save("../../vm/shared/patched")
        p = subprocess.Popen(["../../tracer/bin/tracer-qemu-cgc", tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
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
        backend = patcherex.Patcherex(filepath)
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
        p = subprocess.Popen(["../../tracer/bin/tracer-qemu-cgc", tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal("\n\nEASTER EGG!\n\n" in res[0] and p.returncode == 0, True)


def test_complex1():
    filepath = os.path.join(bin_location, "cgc_scored_event_2/cgc/0b32aa01_01")
    pipe = subprocess.PIPE

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = patcherex.Patcherex(filepath)

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
        patches.append(AddDataPatch(test_str, "added_data"))
        backend.apply_patches(patches)
        backend.save(tmp_file)
        # backend.save("../../vm/shared/patched")
        p = subprocess.Popen(["../../tracer/bin/tracer-qemu-cgc", tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
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
        backend = patcherex.Patcherex(filepath)

        patches = []
        patches.append(AddDataPatch("0123456789abcdef", "hex_array"))
        patches.append(AddDataPatch("\n", "new_line"))
        patches.append(AddDataPatch("X"*4, "saved_canary"))
        patches.append(AddDataPatch("base canary value: \x00","str_bcanary"))
        patches.append(AddDataPatch("canary failure: \x00","str_fcanary"))
        patches.append(AddDataPatch(" vs \x00","str_vs"))

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
        p = subprocess.Popen(["../../tracer/bin/tracer-qemu-cgc", tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n"+"\x00"*100)
        print res, p.returncode
        nose.tools.assert_equal(check_output(res[0]) and p.returncode == 0x44, True)


def test_shadowstack():
    from patcherex.techniques.shadowstack import ShadowStack
    filepath = os.path.join(bin_location, "cgc_trials/CADET_00003")
    pipe = subprocess.PIPE

    p = subprocess.Popen(["../../tracer/bin/tracer-qemu-cgc", filepath], stdin=pipe, stdout=pipe, stderr=pipe)
    res = p.communicate("\x00"*1000+"\n")
    print res, p.returncode
    nose.tools.assert_equal((p.returncode == -11), True)

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        backend = patcherex.Patcherex(filepath)
        cp = ShadowStack(filepath)
        patches = cp.get_patches()
        backend.apply_patches(patches)
        backend.save(tmp_file)

        p = subprocess.Popen(["../../tracer/bin/tracer-qemu-cgc", tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("\x00"*100+"\n")
        print res, p.returncode
        nose.tools.assert_equal(p.returncode == 68, True)


def run_all():
    functions = globals()
    all_functions = dict(filter((lambda (k, v): k.startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
