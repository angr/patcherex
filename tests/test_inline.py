import patcherex

import os
import nose
import subprocess

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
        p = patcherex.Patcherex(filepath)
        p.replace_instruction_asm(0x8048291, "mov DWORD [esp+8], 0x40;", "asdf")
        p.compile_patches()
        p.save(tmp_file)
        # p.save("../../vm/shared/patched")
        p = subprocess.Popen(["../../tracer/bin/tracer-qemu-cgc", tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*100)
        print res, p.returncode
        nose.tools.assert_equal((res[0] == expected and p.returncode == 0), True)


def test_added_code():
    filepath = os.path.join(bin_location, "cgc_scored_event_2/cgc/0b32aa01_01")
    pipe = subprocess.PIPE

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        p = patcherex.Patcherex(filepath)
        added_code = '''
            mov     eax, 1
            mov     ebx, 0x32
            int     80h
        '''
        p.add_code(added_code, "aaa")
        p.compile_patches()
        p.set_oep(p.name_map["ADDED_CODE_START"])
        p.save(tmp_file)
        # p.save("../../vm/shared/patched")
        p = subprocess.Popen(["../../tracer/bin/tracer-qemu-cgc", tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal(p.returncode == 0x32, True)


def test_added_code_and_data():
    filepath = os.path.join(bin_location, "cgc_scored_event_2/cgc/0b32aa01_01")
    pipe = subprocess.PIPE

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        p = patcherex.Patcherex(filepath)
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
        p.add_code(added_code, "aaa")
        p.add_data(test_str, "added_data")
        p.compile_patches()
        p.set_oep(p.name_map["ADDED_CODE_START"])
        p.save(tmp_file)
        # p.save("../../vm/shared/patched")
        p = subprocess.Popen(["../../tracer/bin/tracer-qemu-cgc", tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal(test_str in res[0] and p.returncode == 0x33, True)


def test_detour():
    filepath = os.path.join(bin_location, "cgc_scored_event_2/cgc/0b32aa01_01")
    pipe = subprocess.PIPE

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        p = patcherex.Patcherex(filepath)
        test_str = "qwertyuiop\n\x00"
        added_code = '''
            mov     eax, 2
            mov     ebx, 0
            mov     ecx, {qq}
            mov     edx, %d
            mov     esi, 0
            int     80h
        ''' % (len(test_str))
        p.insert_into_block(0x80480A6, added_code)
        p.add_data(test_str, "qq")
        p.compile_patches()
        p.save(tmp_file)
        # p.save("../../vm/shared/patched")
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
        p = patcherex.Patcherex(filepath)
        added_code = '''
            mov     eax, 2
            mov     ebx, 0
            mov     ecx, 0x08048786
            mov     edx, 15
            mov     esi, 0
            int     80h
        '''
        p.add_entrypoint_code(added_code)
        p.compile_patches()
        p.save(tmp_file)
        #p.save("../../vm/shared/patched")
        p = subprocess.Popen(["../../tracer/bin/tracer-qemu-cgc", tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal("\n\nEASTER EGG!\n\n" in res[0] and p.returncode == 0, True)


def test_complex1():
    filepath = os.path.join(bin_location, "cgc_scored_event_2/cgc/0b32aa01_01")
    pipe = subprocess.PIPE

    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td, "patched")
        p = patcherex.Patcherex(filepath)

        added_code = '''
            mov     eax, 2
            mov     ebx, 0
            mov     ecx, 0x08048786
            mov     edx, 15
            mov     esi, 0
            int     80h
            call    {added_function}
        '''
        p.add_entrypoint_code(added_code)
        added_code = '''
            mov     eax, 1
            mov     ebx, 0x34
            int     80h
        '''
        p.add_entrypoint_code(added_code)
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
        p.add_code(added_code, "added_function")
        p.add_data(test_str, "added_data")
        p.compile_patches()

        p.compile_patches()
        p.save(tmp_file)
        p.save("../../vm/shared/patched")
        p = subprocess.Popen(["../../tracer/bin/tracer-qemu-cgc", tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
        res = p.communicate("A"*10+"\n")
        print res, p.returncode
        nose.tools.assert_equal("\n\nEASTER EGG!\n\n"+test_str in res[0] and p.returncode == 52, True)


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
