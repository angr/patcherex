#!/usr/bin/python

import sys
import os
import shutil

import cgrex.utils as utils
from cgrex.Fortifier import Fortifier
from cgrex.VagrantManager import VagrantManager


import IPython


def self_memory_oep_test():
    fname = sys.argv[1]

    ff = Fortifier(fname)
    #print ff.dump_segments()

    assert not ff.has_fortify_segment(),"%s already fortified"%fname
    if not ff.has_fortify_segment():
        ff.setup_headers()

    oep = ff.get_oep()
    print "--- original oep",oep,repr(hex(oep))
    ff.set_oep(Fortifier.fortify_segment1_base)

   
    injected_code = utils.compile_asm_template("memory_scanner.asm",
            {'code_loaded_address':hex(Fortifier.fortify_segment1_base),'code_return':hex(oep)})
    ff.set_fortify_segment(injected_code)
    ff.save(fname+"_cgrex")

    '''
    vgm = VagrantManager(sys.argv[2])
    with vgm.get_shared_tmpdir() as sd:
        save_fname = os.path.join(sd,os.path.basename(fname)+"_cgrex")
        ff.save(save_fname)    
        res = vgm.exec_cmd(["exec",save_fname],debug=True)
        raw_input()
    '''

def inject_helloworld_test():
    fname = sys.argv[1]

    ff = Fortifier(fname)
    #print ff.dump_segments()

    assert not ff.has_fortify_segment(),"%s already fortified"%fname
    if not ff.has_fortify_segment():
        ff.setup_headers()

    oep = ff.get_oep()
    print "--- original oep",oep,repr(hex(oep))
    ff.set_oep(Fortifier.fortify_segment1_base)

    injected_code = utils.compile_asm_template("helloworld.asm",
            {'code_loaded_address':hex(Fortifier.fortify_segment1_base),'code_return':hex(oep)})
    ff.set_fortify_segment(injected_code)
    ff.save(fname+"_cgrex")


if __name__ == "__main__":
    #IPython.embed()
    
    #./fortify.py  ../../cgc/vm/cgc/shared/CADET_00001
    #self_memory_oep_test()
    #inject_helloworld_test()
    
    fname = sys.argv[1]
    ff = Fortifier(fname)
    assert not ff.has_fortify_segment(),"%s already fortified"%fname
    if not ff.has_fortify_segment():
        ff.setup_headers()
    ff.set_fortify_segment("\x90"*1000)

    ff.dump_segments()
    print ff.get_maddress(0x8048f00,0x200).encode('hex')

    IPython.embed()
    






