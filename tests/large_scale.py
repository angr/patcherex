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
    all_bins = patcherex.utils.find_files(os.path.join(bin_location,"cgc_samples_multiflags/"),"*",only_exec=True)
    #all_bins = [b for b in all_bins if "CADET_00003" in b]
    tinput = "\n"*10
    with patcherex.utils.tempdir() as td:
        for ibin,binary in enumerate(all_bins):
            print "="*25,"testing",str(ibin+1)+"/"+str(len(all_bins)),binary
            tmp_file = os.path.join(td, "patched")
            p = subprocess.Popen([qemu_location, binary], stdin=pipe, stdout=pipe, stderr=pipe)
            res = p.communicate(tinput)
            expected = (res[0],res[1],p.returncode)
            osize = os.path.getsize(binary)

            print "="*20,"1"
            backend = DetourBackend(binary,data_fallback=None,try_pdf_removal=False)
            backend.apply_patches([AddEntryPointPatch("nop","void")])
            backend.save(tmp_file)
            #backend.save("../../vm/shared/patched")
            nose.tools.assert_equal(backend.data_fallback,False)
            #nose.tools.assert_true(backend.pdf_removed)
            p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
            res = p.communicate(tinput)
            real = (res[0],res[1],p.returncode)
            nose.tools.assert_equal(expected,real)
            nsize = os.path.getsize(tmp_file)
            #nose.tools.assert_true(nsize<(osize-0x10000))

            print "="*20,"2"
            backend = DetourBackend(binary,data_fallback=True,try_pdf_removal=False)
            backend.apply_patches([AddEntryPointPatch("nop","void")])
            backend.save(tmp_file)
            #backend.save("../../vm/shared/patched")
            p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
            res = p.communicate(tinput)
            real = (res[0],res[1],p.returncode)
            nose.tools.assert_equal(expected,real)
            print expected
            print real
            nsize = os.path.getsize(tmp_file)

            print "="*20,"3"
            backend = DetourBackend(binary,data_fallback=None,try_pdf_removal=True)
            backend.apply_patches([AddEntryPointPatch("nop","void")])
            backend.save(tmp_file)
            #backend.save("../../vm/shared/patched")
            nose.tools.assert_equal(backend.data_fallback,False)
            nose.tools.assert_true(backend.pdf_removed)
            p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
            res = p.communicate(tinput)
            real = (res[0],res[1],p.returncode)
            nose.tools.assert_equal(expected,real)
            nsize = os.path.getsize(tmp_file)
            nose.tools.assert_true(nsize<(osize-0x11000))

            print "="*20,"4"
            backend = DetourBackend(binary,data_fallback=True,try_pdf_removal=True)
            backend.apply_patches([AddEntryPointPatch("nop","void")])
            backend.save(tmp_file)
            #backend.save("../../vm/shared/patched")
            nose.tools.assert_equal(backend.data_fallback,True)
            nose.tools.assert_true(backend.pdf_removed)
            p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
            res = p.communicate(tinput)
            real = (res[0],res[1],p.returncode)
            nose.tools.assert_equal(expected,real)
            nsize = os.path.getsize(tmp_file)
            nose.tools.assert_true(nsize<(osize-0x11000))

            print "="*20,"5"
            backend = DetourBackend(binary)
            backend.apply_patches([AddEntryPointPatch("nop","void")])
            backend.save(tmp_file)
            #backend.save("../../vm/shared/patched")
            nose.tools.assert_equal(backend.data_fallback,False)
            nose.tools.assert_true(backend.pdf_removed)
            p = subprocess.Popen([qemu_location, tmp_file], stdin=pipe, stdout=pipe, stderr=pipe)
            res = p.communicate(tinput)
            real = (res[0],res[1],p.returncode)
            nose.tools.assert_equal(expected,real)
            nsize = os.path.getsize(tmp_file)
            nose.tools.assert_true(nsize<(osize-0x11000))
            print real
            print expected


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

