#!/usr/bin/env python

import os
import nose
import struct
import subprocess
from collections import defaultdict

import patcherex
import patcherex.cfg_utils as cfg_utils
from patcherex.patches import *
from patcherex.backends.detourbackend import DetourBackend


# these tests only verify that the cfg interface did not change much
# large scale testing of the CFGs is an open problem  

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries-private'))


def is_sane_function(ff):
    return not ff.is_syscall and not ff.has_unresolved_calls and not ff.has_unresolved_jumps


def map_callsites(cfg):
    callsites = dict()
    for f in cfg.functions.values():
        for callsite in f.get_call_sites():
            if f.get_call_target(callsite) is None:
                continue
            callsites[callsite] = f.get_call_target(callsite)

    # create inverse callsite map
    inv_callsites = defaultdict(set)
    for c, f in callsites.iteritems():
        inv_callsites[f].add(c)
    return inv_callsites


def is_last_returning_block(addr,cfg,project):
    node = cfg.get_any_node(addr)
    function = cfg.functions[node.function_address]
    if not function.returning:
        return False
    bb = project.factory.block(addr)
    last_instruction = bb.capstone.insns[-1]
    if last_instruction.mnemonic != u"ret":
        return False
    return True


def last_block_to_callers(addr,cfg,inv_callsites):
    node = cfg.get_any_node(addr)
    if node == None:
        return []
    function = cfg.functions[node.function_address]
    if node.addr not in [n.addr for n in function.ret_sites]:
        return []

    return_locations = []
    for site in inv_callsites[function.addr]:
        node = cfg.get_any_node(site)
        nlist = cfg.get_successors_and_jumpkind(node, excluding_fakeret=False)
        return_locations.extend([n[0] for n in nlist if n[1]=='Ijk_FakeRet'])
    return return_locations


def test_EAGLE_00005_bb():
    filepath = os.path.join(bin_location, "cgc_trials/last_trial/original/EAGLE_00005")
    backend = DetourBackend(filepath)
    cfg = backend.cfg
    # import IPython; IPython.embed()
    bbs = [(0x0804A73C,3),(0x0804BB3D,1),(0x0804A0E5,6),(0x0804A101,3),(0x0804B145,1),(0x0804BB42,2)]
    for addr,ni in bbs:
        n = cfg.get_any_node(addr)
        nose.tools.assert_true(n != None)
        nose.tools.assert_true(len(n.instruction_addrs) == ni)

    caller_map = [
        (0x8048D28,set([0x8048685,0x804877b])),
        (0x8048FEA,set([0x80483d2])),
    ]
    inv_callsites = map_callsites(cfg)
    for b,clist in caller_map:
        nose.tools.assert_true(is_last_returning_block(b,cfg,backend.project))
        node_addresses = set([n.addr for n in last_block_to_callers(b,cfg,inv_callsites)])
        print hex(b),"<--",map(hex,node_addresses)
        nose.tools.assert_equal(clist,node_addresses)


def test_CADET_00003():
    print "Testing test_CADET_00003..."
    filepath = os.path.join(bin_location, "cgc_trials/CADET_00003")
    backend = DetourBackend(filepath)
    cfg = backend.cfg

    #how to get the list of functions from the IDA list:
    #print "["+",\n".join(map(hex,hex,[int(l.split()[2],16) for l in a.split("\n") if l.strip()]))+"]"
    legitimate_functions = set([
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
    print "additional:",map(hex,function_entrypoints-legitimate_functions)
    print "skipped:",map(hex,legitimate_functions-function_entrypoints)
    nose.tools.assert_equal(function_entrypoints == legitimate_functions, True)

    sane_functions = [v for k,v in cfg.functions.iteritems() if is_sane_function(v)]
    function_entrypoints = set([f.startpoint.addr for f in sane_functions])
    print "additional:",map(hex,function_entrypoints-legitimate_functions)
    print "skipped:",map(hex,legitimate_functions-function_entrypoints)
    nose.tools.assert_equal(function_entrypoints == legitimate_functions, True)

    #something which was wrong in the past
    n = cfg.get_any_node(0x80485EC)
    nose.tools.assert_true(len(n.instruction_addrs) == 1)
    nose.tools.assert_true(n.instruction_addrs[0] == 0x80485EC)

    #all sane functions ends with ret in CADET_00003
    for ff in sane_functions:
        node = cfg.get_any_node(ff.addr, is_syscall=False)
        nose.tools.assert_equal(node!=None,True)
        nose.tools.assert_equal(len(node.instruction_addrs)>0,True)
        node = cfg.get_any_node(ff.addr+1, is_syscall=False,anyaddr=True)
        nose.tools.assert_equal(node!=None,True)
        nose.tools.assert_equal(len(node.instruction_addrs)>0,True)
        nose.tools.assert_equal(ff.startpoint!=None,True)
        nose.tools.assert_equal(ff.ret_sites!=None,True)
        if ff.addr == 0x080485FC or ff.addr==0x804860C:
            nose.tools.assert_equal(ff.returning==False,True)
        if ff.returning:
            nose.tools.assert_equal(len(ff.ret_sites)>0,True)
        for endpoint in ff.ret_sites:
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

    legitimate_functions = set([
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
    print "additional:",map(hex,function_entrypoints-legitimate_functions)
    print "skipped:",map(hex,legitimate_functions-function_entrypoints)
    nose.tools.assert_equal(function_entrypoints == legitimate_functions, True)

    sane_functions = [v for k,v in cfg.functions.iteritems() if is_sane_function(v)]
    function_entrypoints = set([f.startpoint.addr for f in sane_functions])
    print "additional:",map(hex,function_entrypoints-legitimate_functions)
    print "skipped:",map(hex,legitimate_functions-function_entrypoints)
    nose.tools.assert_equal(function_entrypoints == legitimate_functions, True)

    #all sane functions ends with ret in CADET_00003
    for ff in sane_functions:
        node = cfg.get_any_node(ff.addr, is_syscall=False)
        nose.tools.assert_equal(node!=None,True)
        nose.tools.assert_equal(len(node.instruction_addrs)>0,True)
        node = cfg.get_any_node(ff.addr+1, is_syscall=False,anyaddr=True)
        nose.tools.assert_equal(node!=None,True)
        nose.tools.assert_equal(len(node.instruction_addrs)>0,True)
        nose.tools.assert_equal(ff.startpoint!=None,True)
        nose.tools.assert_equal(ff.ret_sites!=None,True)
        if ff.addr == 0x080485FC or ff.addr==0x8048607:
            nose.tools.assert_equal(ff.returning==False,True)
        if ff.returning:
            nose.tools.assert_equal(len(ff.ret_sites)>0,True)
        for endpoint in ff.ret_sites:
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


def test_detect_syscall_wrapper():
    filepath = os.path.join(bin_location, "cgc_trials/last_trial/original/CROMU_00071")
    backend = DetourBackend(filepath)
    cfg = backend.cfg
    legitimate_syscall_wrappers = set([
        (0x804d483,1),
        (0x804d491,2),
        (0x804d4b1,3),
        (0x804d4d1,4),
        (0x804d4f7,5),
        (0x804d511,6),
        (0x804d525,7)
    ])

    syscall_wrappers = set([(ff.addr,cfg_utils.detect_syscall_wrapper(backend,ff)) \
            for ff in cfg.functions.values() if cfg_utils.detect_syscall_wrapper(backend,ff)!=None])
    print "syscall wrappers in CROMU_00071:"
    print map(lambda x:(hex(x[0]),x[1]),syscall_wrappers)
    nose.tools.assert_equal(syscall_wrappers,legitimate_syscall_wrappers)

    filepath = os.path.join(bin_location, "cgc_trials/last_trial/original/CROMU_00070")
    backend = DetourBackend(filepath)
    cfg = backend.cfg
    legitimate_syscall_wrappers = set([
        (0x804d690, 5),
        (0x804d66a, 4),
        (0x804d6be, 7),
        (0x804d6aa, 6),
        (0x804d61c, 1),
        (0x804d64a, 3),
        (0x804d62a, 2)
    ])

    syscall_wrappers = set([(ff.addr,cfg_utils.detect_syscall_wrapper(backend,ff)) \
            for ff in cfg.functions.values() if cfg_utils.detect_syscall_wrapper(backend,ff)!=None])
    print "syscall wrappers in CROMU_00070:"
    print map(lambda x:(hex(x[0]),x[1]),syscall_wrappers)
    nose.tools.assert_equal(syscall_wrappers,legitimate_syscall_wrappers)


def test_is_floatingpoint_function():
    filepath = os.path.join(bin_location, "cgc_trials/last_trial/original/CROMU_00071")
    backend = DetourBackend(filepath)
    cfg = backend.cfg
    floatingpoint_functions = [ff for ff in cfg.functions.values() if cfg_utils.is_floatingpoint_function(backend,ff)]
    floatingpoint_functions = sorted(floatingpoint_functions,key = lambda f:f.addr)
    #print "floatingpoint_functions in CROMU_00071"
    #print "\n".join(map(lambda f:hex(f.addr),floatingpoint_functions))
    first = floatingpoint_functions[0].addr
    ff = floatingpoint_functions[-1]
    if ff.ret_sites == None:
        last = ff.addr
    else:
        if len(ff.ret_sites) == 0:
            last = ff.addr
        else:
            last = max([e.addr for e in ff.blocks])
    print hex(first),hex(last)
    real_start = 0x804d5c6
    real_end = 0x0804D78b
    nose.tools.assert_true(first == real_start)
    nose.tools.assert_true(last <= real_end)
    nose.tools.assert_true(last > real_end-0x20) #I allow some imprecision

    filepath = os.path.join(bin_location, "cgc_trials/last_trial/original/CROMU_00070")
    backend = DetourBackend(filepath)
    cfg = backend.cfg
    floatingpoint_functions = [ff for ff in cfg.functions.values() if cfg_utils.is_floatingpoint_function(backend,ff)]
    floatingpoint_functions = sorted(floatingpoint_functions,key = lambda f:f.addr)
    #print "floatingpoint_functions in CROMU_00071"
    #print "\n".join(map(lambda f:hex(f.addr),floatingpoint_functions))
    first = floatingpoint_functions[0].addr
    ff = floatingpoint_functions[-1]
    if ff.ret_sites == None:
        last = ff.addr
    else:
        if len(ff.ret_sites) == 0:
            last = ff.addr
        else:
            last = max([e.addr for e in ff.blocks])
    print hex(first),hex(last)
    real_start = 0x0804D75f
    real_end = 0x0804D924
    nose.tools.assert_true(first == real_start)
    nose.tools.assert_true(last <= real_end)
    nose.tools.assert_true(last > real_end-0x20) #I allow some imprecision


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

