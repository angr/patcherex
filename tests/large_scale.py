#!/usr/bin/env python

import os
import nose
import struct
import subprocess
import logging
from collections import defaultdict

import patcherex
import patcherex.cfg_utils as cfg_utils
from patcherex.patches import *
from patcherex.backends.detourbackend import DetourBackend


# these tests only verify that the cfg interface did not change much
# large scale testing of the CFGs is an open problem  

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries-private'))
qemu_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../tracer/bin/tracer-qemu-cgc"))
pipe = subprocess.PIPE


def test_pdf_removal():
    all_bins = patcherex.utils.find_files(os.path.join(bin_location,"cfe_original"),"*",only_exec=True)
    all_bins = [b for b in all_bins if not b.endswith(".py")]
    tinput = "\n"*10
    with patcherex.utils.tempdir() as td:
        for binary in all_bins:
            print "="*5,"testing",binary
            p = subprocess.Popen([qemu_location, binary], stdin=pipe, stdout=pipe, stderr=pipe)
            res = p.communicate(tinput)
            expected = (res[0],res[1],p.returncode)
            osize = os.path.getsize(binary)

            tmp_file = os.path.join(td, "patched1")
            backend = DetourBackend(binary)
            backend.apply_patches([AddEntryPointPatch("nop","sum")])
            backend.save(tmp_file)
            backend.save("../../vm/shared/patched")
            nose.tools.assert_true(not backend.data_fallback)
            #nose.tools.assert_true(backend.pdf_removed)

            p = subprocess.Popen([qemu_location, "../../vm/shared/patched"], stdin=pipe, stdout=pipe, stderr=pipe)
            res = p.communicate(tinput)
            real = (res[0],res[1],p.returncode)
            nose.tools.assert_equal(expected,real)
            nsize = os.path.getsize(tmp_file)
            #nose.tools.assert_true(nsize<(osize-0x10000))


def run_all():
    functions = globals()
    all_functions = dict(filter((lambda (k, v): k.startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()


if __name__ == "__main__":
    import sys
    logging.getLogger("patcherex.techniques.CpuId").setLevel("INFO")
    logging.getLogger("patcherex.techniques.Packer").setLevel("INFO")
    logging.getLogger("patcherex.techniques.QemuDetection").setLevel("INFO")
    logging.getLogger("patcherex.techniques.SimpleCFI").setLevel("INFO")
    logging.getLogger("patcherex.techniques.ShadowStack").setLevel("INFO")
    logging.getLogger("patcherex.backends.DetourBackend").setLevel("INFO")
    logging.getLogger("patcherex.techniques.StackRetEncryption").setLevel("DEBUG")
    logging.getLogger("patcherex.techniques.IndirectCFI").setLevel("DEBUG")
    logging.getLogger("patcherex.techniques.TransmitProtection").setLevel("DEBUG")
    logging.getLogger("patcherex.PatchMaster").setLevel("INFO")

    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()

