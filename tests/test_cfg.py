#!/usr/bin/env python

import os
import nose
import struct
import subprocess

import patcherex
from patcherex.patches import *
from patcherex.backends.detourbackend import DetourBackend


# these tests only verify that the cfg interface did not change much
# large scale testing of the CFGs is an open problem  

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries-private'))


def is_sane_function(ff):
    return not ff.is_syscall and not ff.has_unresolved_calls and not ff.has_unresolved_jumps


def test_CADET_00003():
    print "Testing test_CADET_00003..."
    filepath = os.path.join(bin_location, "cgc_trials/CADET_00003")
    backend = DetourBackend(filepath)
    cfg = backend.cfg

    #how to get the list of functions from the IDA list:
    #print "["+",\n".join(map(hex,hex,[int(l.split()[2],16) for l in a.split("\n") if l.strip()]))+"]"
    legittimate_functions = set([
        0x80480a0,
        0x8048230,
        0x8048400,
        0x80484f0,
        0x80485fc,
        0x804860c,
        0x804861a,
        0x804863a,
        0x8048705,
        0x8048735,
        0x8048680L,
        0x80486e3L,
        0x80486c8L,
        0x80486aeL,
        0x8048618L,
        0x804865aL,
        0x804869aL])

    non_syscall_functions = [v for k,v in cfg.functions.iteritems() if not v.is_syscall]
    #check startpoints, I know that sometimes they could be None, but this should not happen in CADET_00003
    function_entrypoints = set([f.startpoint.addr for f in non_syscall_functions])
    print "additional:",map(hex,function_entrypoints-legittimate_functions)
    print "skipped:",map(hex,legittimate_functions-function_entrypoints)
    nose.tools.assert_equal(function_entrypoints == legittimate_functions, True)

    sane_functions = [v for k,v in cfg.functions.iteritems() if is_sane_function(v)]
    function_entrypoints = set([f.startpoint.addr for f in sane_functions])
    print "additional:",map(hex,function_entrypoints-legittimate_functions)
    print "skipped:",map(hex,legittimate_functions-function_entrypoints)
    nose.tools.assert_equal(function_entrypoints == legittimate_functions, True)

    #all sane functions ends with ret in CADET_00003
    for ff in sane_functions:
        node = cfg.get_any_node(ff.addr, is_syscall=False)
        nose.tools.assert_equal(node!=None,True)
        nose.tools.assert_equal(len(node.instruction_addrs)>0,True)
        node = cfg.get_any_node(ff.addr+1, is_syscall=False,anyaddr=True)
        nose.tools.assert_equal(node!=None,True)
        nose.tools.assert_equal(len(node.instruction_addrs)>0,True)
        nose.tools.assert_equal(ff.startpoint!=None,True)
        nose.tools.assert_equal(ff.endpoints!=None,True)
        if ff.addr == 0x080485FC or ff.addr==0x804860C:
            nose.tools.assert_equal(ff.returning==False,True)
        if ff.returning:
            nose.tools.assert_equal(len(ff.endpoints)>0,True)
        for endpoint in ff.endpoints:
            bb = backend.project.factory.block(endpoint.addr)
            last_instruction = bb.capstone.insns[-1]
            nose.tools.assert_equal(last_instruction.mnemonic == u"ret", True) 

    syscalls = [v for k,v in cfg.functions.iteritems() if v.is_syscall]

    for ff in syscalls:
        bb1 = cfg.get_any_node(ff.addr)
        nose.tools.assert_equal(len(bb1.predecessors) >= 1, True)
        bb2 = bb1.predecessors[0]
        bb = backend.project.factory.block(bb2.addr)
        ii = bb.capstone.insns[-1]
        nose.tools.assert_equal(ii.mnemonic ==  u"int" and ii.op_str == u"0x80", True)

    # the following is a case of a bb that should be split by normalization
    # because the bb is split by a "subsequent" jump 
    bb = cfg.get_any_node(0x804824F)
    nose.tools.assert_equal(bb != None, True)
    nose.tools.assert_equal(bb.size == 13, True)
    bb = cfg.get_any_node(0x08048230)
    nose.tools.assert_equal(bb != None, True)
    nose.tools.assert_equal(bb.size == 31, True)


def test_0b32aa01_01():
    print "Testing test_0b32aa01_01..."
    filepath = os.path.join(bin_location, "cgc_scored_event_2/cgc/0b32aa01_01")
    backend = DetourBackend(filepath)
    cfg = backend.cfg

    legittimate_functions = set([
        0x80480a0,
        0x8048230,
        0x8048400,
        0x80484f0,
        0x80485fc,
        0x8048607,
        0x8048615,
        0x8048635,
        0x80486c3,
        0x80486a9L,
        0x8048613L,
        0x8048655L,
        0x804867bL,
        0x80486deL,
        0x8048695L])

    non_syscall_functions = [v for k,v in cfg.functions.iteritems() if not v.is_syscall]
    #check startpoints, I know that sometimes they could be None, but this should not happen in CADET_00003
    function_entrypoints = set([f.startpoint.addr for f in non_syscall_functions])
    print "additional:",map(hex,function_entrypoints-legittimate_functions)
    print "skipped:",map(hex,legittimate_functions-function_entrypoints)
    nose.tools.assert_equal(function_entrypoints == legittimate_functions, True)

    sane_functions = [v for k,v in cfg.functions.iteritems() if is_sane_function(v)]
    function_entrypoints = set([f.startpoint.addr for f in sane_functions])
    print "additional:",map(hex,function_entrypoints-legittimate_functions)
    print "skipped:",map(hex,legittimate_functions-function_entrypoints)
    nose.tools.assert_equal(function_entrypoints == legittimate_functions, True)

    #all sane functions ends with ret in CADET_00003
    for ff in sane_functions:
        node = cfg.get_any_node(ff.addr, is_syscall=False)
        nose.tools.assert_equal(node!=None,True)
        nose.tools.assert_equal(len(node.instruction_addrs)>0,True)
        node = cfg.get_any_node(ff.addr+1, is_syscall=False,anyaddr=True)
        nose.tools.assert_equal(node!=None,True)
        nose.tools.assert_equal(len(node.instruction_addrs)>0,True)
        nose.tools.assert_equal(ff.startpoint!=None,True)
        nose.tools.assert_equal(ff.endpoints!=None,True)
        if ff.addr == 0x080485FC or ff.addr==0x8048607:
            nose.tools.assert_equal(ff.returning==False,True)
        if ff.returning:
            nose.tools.assert_equal(len(ff.endpoints)>0,True)
        for endpoint in ff.endpoints:
            bb = backend.project.factory.block(endpoint.addr)
            last_instruction = bb.capstone.insns[-1]
            nose.tools.assert_equal(last_instruction.mnemonic == u"ret", True) 

    syscalls = [v for k,v in cfg.functions.iteritems() if v.is_syscall]

    for ff in syscalls:
        bb1 = cfg.get_any_node(ff.addr)
        nose.tools.assert_equal(len(bb1.predecessors) >= 1, True)
        bb2 = bb1.predecessors[0]
        bb = backend.project.factory.block(bb2.addr)
        ii = bb.capstone.insns[-1]
        nose.tools.assert_equal(ii.mnemonic ==  u"int" and ii.op_str == u"0x80", True)


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

#TODO: CADET_00003, bb 80485EC should be 1 instruction
#TODO: EAGLE_00005, sub_8049120
