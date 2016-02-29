import patcherex

import os
import nose

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries-private'))

def test_simple_inline():

    filepath = os.path.join(bin_location, "cgc_scored_event_2/cgc/0b32aa01_01")
    p = patcherex.Patcher(filepath)
    p.replace_instruction_asm(0x8048291, "mov DWORD [esp+8], 0x40;", "asdf")
    p.compile_patches()
    p.save("/tmp/0b32aa01_01_patched")

    # TODO FIXME
    cmd = "echo '" + "A"*100 + "' | ../../tracer/bin/tracer-qemu-cgc /tmp/0b32aa01_01_patched"
    nose.tools.assert_equal(os.system(cmd), 0)


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
