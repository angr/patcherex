import patcherex

import os
import nose
import subprocess

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries-private'))

def test_simple_inline():
    filepath = os.path.join(bin_location, "cgc_scored_event_2/cgc/0b32aa01_01")

    pipe = subprocess.PIPE
    p = subprocess.Popen(["../../tracer/bin/tracer-qemu-cgc", filepath],stdin=pipe,stdout=pipe,stderr=pipe)
    res = p.communicate("A"*100)
    print res, p.returncode
    nose.tools.assert_equal((p.returncode != 0), True)

    expected = "\nWelcome to Palindrome Finder\n\n\tPlease enter a possible palindrome: \t\tYes, that's a palindrome!\n\n\tPlease enter a possible palindrome: "
    with patcherex.utils.tempdir() as td:
        tmp_file = os.path.join(td,"patched")
        p = patcherex.Patcherex(filepath)
        p.replace_instruction_asm(0x8048291, "mov DWORD [esp+8], 0x40;", "asdf")
        p.compile_patches()
        p.save(tmp_file)
        p = subprocess.Popen(["../../tracer/bin/tracer-qemu-cgc", tmp_file],stdin=pipe,stdout=pipe,stderr=pipe)
        res = p.communicate("A"*100)
        print res, p.returncode
        nose.tools.assert_equal((res[0] == expected and p.returncode == 0), True)


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
