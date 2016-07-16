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

l = logging.getLogger("patcherex.test.test_patch_master")

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries-private'))
qemu_location = shellphish_qemu.qemu_path('cgc-tracer')


os.environ["POSTGRES_DATABASE_NAME"] = "dummy"
os.environ["POSTGRES_DATABASE_USER"] = "dummy"
os.environ["POSTGRES_MASTER_SERVICE_HOST"] = "dummy"
os.environ["POSTGRES_MASTER_SERVICE_PORT"] = "dummy"
os.environ["POSTGRES_DATABASE_PASSWORD"] = "dummy"
from farnsworth.models.job import PatcherexJob
PATCH_TYPES = [str(p) for p in PatcherexJob.PATCH_TYPES]
print "PATCH_TYPES:", PATCH_TYPES


def test_cfe_trials():
    def save_patch(fname,patch_content):
        fp = open(fname,"wb")
        fp.write(patch_content)
        fp.close()
        os.chmod(fname, 0755)

    tfolder = os.path.join(bin_location, "cfe_original")
    tests = utils.find_files(tfolder,"*",only_exec=True)
    inputs = ["","A","\n"*1000,"\x00"*1000,"A"*1000]

    bins = ["CROMU_00070","NRFIN_00073","CROMU_00071"] # ,"KPRCA_00016_1","KPRCA_00056",
    titerator = [t for t in tests if any([b in t for b in bins])]
    generated_patches = set()
    for tnumber,test in enumerate(titerator):
        with patcherex.utils.tempdir() as td:
            print "=====",str(tnumber+1)+"/"+str(len(titerator)),"building patches for",test
            pm = PatchMaster(test)

            for patch_type in PATCH_TYPES:
                patched_bin, nrule = pm.create_one_patch(patch_type)
                tmp_fname = os.path.join(td,patch_type)
                generated_patches.add(patched_bin)
                save_patch(tmp_fname,patched_bin)
                # save_patch("/tmp/cfe1/"+os.path.basename(test)+"_"+patch_type,patched_bin)

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
    nose.tools.assert_equal(len(generated_patches),len(bins)*len(PATCH_TYPES))
    print "GENERATED:",len(generated_patches),"patches"


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

