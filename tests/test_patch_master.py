#!/usr/bin/env python

import os
import nose
import struct
import subprocess
import logging
import patcherex.utils as utils

import patcherex
import shellphish_qemu
from patcherex.patch_master import PatchMaster
from povsim import CGCPovSimulator


l = logging.getLogger("patcherex.test.test_patch_master")
logging.getLogger("povsim.cgc_pov_simulator").setLevel('DEBUG')

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries-private'))
qemu_location = shellphish_qemu.qemu_path('cgc-tracer')
self_location_folder = os.path.dirname(os.path.realpath(__file__))
backdoor_pov_location = os.path.join(self_location_folder,"../backdoor_stuff/backdoor_pov.pov")

os.environ["POSTGRES_DATABASE_NAME"] = "dummy"
os.environ["POSTGRES_DATABASE_USER"] = "dummy"
os.environ["POSTGRES_MASTER_SERVICE_HOST"] = "dummy"
os.environ["POSTGRES_MASTER_SERVICE_PORT"] = "dummy"
os.environ["POSTGRES_DATABASE_PASSWORD"] = "dummy"
from farnsworth.models.job import PatcherexJob
PATCH_TYPES = [str(p) for p in PatcherexJob.PATCH_TYPES]
print "PATCH_TYPES:", PATCH_TYPES

PATCH_TYPES_WITH_RULES = ["voidbitflip"]
PATCH_TYPES_WITH_BACKDOOR = ["medium_detour","medium_reassembler"]
PATCH_TYPES_AS_ORIGINAL = ["voidbitflip"]


def test_cfe_trials():
    def save_patch(fname,patch_content):
        fp = open(fname,"wb")
        fp.write(patch_content)
        fp.close()
        os.chmod(fname, 0755)

    #nose.tools.assert_true(all([p in PATCH_TYPES for p in PATCH_TYPES_WITH_RULES]))
    tfolder = os.path.join(bin_location, "cfe_original")
    tests = utils.find_files(tfolder,"*",only_exec=True)
    inputs = ["","A","\n"*100,"\x00"*100,"A"*100]

    bins = ["CROMU_00070","NRFIN_00073","CROMU_00071"] # ,"KPRCA_00016_1","KPRCA_00056",
    titerator = [t for t in tests if any([b in t for b in bins])]
    generated_patches = set()
    errors = []
    for tnumber,test in enumerate(titerator):
        with patcherex.utils.tempdir() as td:
            print "=====",str(tnumber+1)+"/"+str(len(titerator)),"building patches for",test
            pm = PatchMaster(test)

            for patch_type in PATCH_TYPES:
                if ("fidget"  in patch_type): continue
                patched_bin, nrule = pm.create_one_patch(patch_type)
                tmp_fname = os.path.join(td,patch_type)
                generated_patches.add(patched_bin)
                save_patch(tmp_fname,patched_bin)
                # save_patch("/tmp/aaa",patched_bin)
                # save_patch(os.path.join("/tmp/cfe1",os.path.basename(test)+"_"+patch_type),patched_bin)

                fp = open(test)
                ocontent = fp.read()
                fp.close()
                fp = open(tmp_fname)
                pcontent = fp.read()
                fp.close()

                if patch_type not in PATCH_TYPES_AS_ORIGINAL:
                    # it is not impossible that a patched binary is exactly as the original
                    # but it is worth investigation
                    nose.tools.assert_true(ocontent != pcontent)
                else:
                    nose.tools.assert_equal(ocontent, pcontent)

                nose.tools.assert_equal(type(patched_bin),str)
                nose.tools.assert_equal(type(nrule),str)

                if patch_type in PATCH_TYPES_WITH_RULES:
                    nose.tools.assert_true(len(nrule)>0)
                else:
                    nose.tools.assert_true(len(nrule)==0)

                if patch_type in PATCH_TYPES_WITH_BACKDOOR:
                    if "bitflip" in nrule:
                        bitflip = True
                    else:
                        bitflip = False
                    # see: https://git.seclab.cs.ucsb.edu/cgc/qemu/issues/5
                    pov_tester = CGCPovSimulator(qemu=shellphish_qemu.qemu_path("cgc-nxtracer"))
                    res = pov_tester.test_binary_pov(backdoor_pov_location,tmp_fname,bitflip=bitflip)
                    nose.tools.assert_true(res)

                for stdin in inputs:
                    # TODO: test properly multi-cb, right now they are tested as separate binaries
                    pipe = subprocess.PIPE
                    p = subprocess.Popen([qemu_location, test], stdin=pipe, stdout=pipe, stderr=pipe)
                    res = p.communicate(stdin)
                    expected = (res[0],p.returncode)
                    print expected

                    print "testing:",os.path.basename(test),"input:",stdin[:10].encode("hex"),patch_type
                    #save_patch("/tmp/",patch)
                    nose.tools.assert_true(os.path.getsize(tmp_fname) > 1000)

                    argv = [qemu_location, tmp_fname]
                    if "bitflip" in nrule:
                        argv = [argv[0]]+["-bitflip"]+argv[1:]
                    p = subprocess.Popen(argv, stdin=pipe, stdout=pipe, stderr=pipe)
                    # very very partial support to network rules
                    # TODO if we add other "interesting rules", handle them here
                    res = p.communicate(stdin)
                    real = (res[0],p.returncode)
                    # there may be special cases in which the behavior changes
                    # because the patch prevent exploitation
                    # this is unlikely, given the naive inputs
                    nose.tools.assert_equal(real,expected)

    # it is not impossible that two patches are exactly the same, but it is worth investigation
    print "\n".join(errors)
    # nose.tools.assert_equal(len(set(generated_patches)),len(bins)*len(PATCH_TYPES))
    print "Generated",len(generated_patches),"different patches of ",len(PATCH_TYPES),"types:",PATCH_TYPES


def run_all():
    functions = globals()
    all_functions = dict(filter((lambda (k, v): k.startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            l.info("testing %s" % str(f))
            all_functions[f]()


if __name__ == "__main__":
    import sys
    logging.getLogger("patcherex.test.test_patch_master").setLevel("INFO")
    logging.getLogger("patcherex.backends.DetourBackend").setLevel("INFO")
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()

