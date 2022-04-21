#!/usr/bin/env python

import os
import struct
import subprocess
from collections import defaultdict

import patcherex
import patcherex.cfg_utils as cfg_utils
from patcherex.patches import *
from patcherex.backends.detourbackend import DetourBackend


# these tests only verify that the cfg interface did not change much
# large scale testing of the CFGs is an open problem  

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../test_binaries'))


def is_sane_function(ff):
    return not ff.is_syscall and not ff.has_unresolved_calls and not ff.has_unresolved_jumps and not ff.alignment


def map_callsites(cfg):
    callsites = dict()
    for f in cfg.functions.values():
        for callsite in f.get_call_sites():
            if f.get_call_target(callsite) is None:
                continue
            callsites[callsite] = f.get_call_target(callsite)

    # create inverse callsite map
    inv_callsites = defaultdict(set)
    for c, f in callsites.items():
        inv_callsites[f].add(c)
    return inv_callsites


def is_last_returning_block(addr,cfg,project):
    node = cfg.model.get_any_node(addr)
    function = cfg.functions[node.function_address]
    if not function.returning:
        return False
    bb = project.factory.block(addr)
    last_instruction = bb.capstone.insns[-1]
    if last_instruction.mnemonic != u"ret":
        return False
    return True


def last_block_to_callers(addr,cfg,inv_callsites):
    node = cfg.model.get_any_node(addr)
    if node == None:
        return []
    function = cfg.functions[node.function_address]
    if node.addr not in [n.addr for n in function.ret_sites]:
        return []

    return_locations = []
    for site in inv_callsites[function.addr]:
        node = cfg.model.get_any_node(site)
        nlist = cfg.get_successors_and_jumpkind(node, excluding_fakeret=False)
        return_locations.extend([n[0] for n in nlist if n[1]=='Ijk_FakeRet'])
    return return_locations


def test_EAGLE_00005_bb():
    filepath = os.path.join(bin_location, "EAGLE_00005")
    backend = DetourBackend(filepath)
    cfg = backend.cfg
    # import IPython; IPython.embed()
    bbs = [(0x0804A73C,3),(0x0804BB3D,1),(0x0804A0E5,6),(0x0804A101,3),(0x0804B145,1),(0x0804BB42,2)]
    for addr,ni in bbs:
        n = cfg.model.get_any_node(addr)
        assert n != None
        assert len(n.instruction_addrs) == ni

    caller_map = [
        (0x8048D28,set([0x8048685,0x804877b])),
        (0x8048FEA,set([0x80483d2])),
    ]
    inv_callsites = map_callsites(cfg)
    for b,clist in caller_map:
        assert is_last_returning_block(b,cfg,backend.project)
        node_addresses = set([n.addr for n in last_block_to_callers(b,cfg,inv_callsites)])
        print(hex(b), "<--", map(hex, node_addresses))
        assert clist == node_addresses


def test_CADET_00003():
    print("Testing test_CADET_00003...")
    filepath = os.path.join(bin_location, "CADET_00003")
    backend = DetourBackend(filepath)
    cfg = backend.cfg

    #how to get the list of functions from the IDA list:
    #print "["+",\n".join(map(hex,hex,[int(l.split()[2],16) for l in a.split("\n") if l.strip()]))+"]"
    legitimate_functions = {
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
        0x8048680,
        0x80486e3,
        0x80486c8,
        0x80486ae,
        0x8048618,
        0x804865a,
        0x804869a,
    }

    non_syscall_functions = [v for k,v in cfg.functions.items() if not v.is_syscall and not v.alignment]
    #check startpoints, I know that sometimes they could be None, but this should not happen in CADET_00003
    function_entrypoints = set([f.startpoint.addr for f in non_syscall_functions])
    print("additional:", list(map(hex, function_entrypoints-legitimate_functions)))
    print("skipped:", list(map(hex, legitimate_functions-function_entrypoints)))
    assert function_entrypoints == legitimate_functions

    sane_functions = [v for k,v in cfg.functions.items() if is_sane_function(v)]
    function_entrypoints = set([f.startpoint.addr for f in sane_functions])
    print("additional:", list(map(hex, function_entrypoints-legitimate_functions)))
    print("skipped:", list(map(hex, legitimate_functions-function_entrypoints)))
    assert function_entrypoints == legitimate_functions

    #something which was wrong in the past
    n = cfg.model.get_any_node(0x80485EC)
    assert len(n.instruction_addrs) == 1
    assert n.instruction_addrs[0] == 0x80485EC

    #all sane functions ends with ret in CADET_00003
    for ff in sane_functions:
        node = cfg.model.get_any_node(ff.addr, is_syscall=False)
        assert node!=None
        assert len(node.instruction_addrs)>0
        node = cfg.model.get_any_node(ff.addr+1, is_syscall=False,anyaddr=True)
        assert node!=None
        assert len(node.instruction_addrs)>0
        assert ff.startpoint!=None
        assert ff.ret_sites!=None
        if ff.addr == 0x080485FC or ff.addr==0x804860C:
            assert ff.returning==False
        if ff.returning:
            assert len(ff.ret_sites)>0
        for endpoint in ff.ret_sites:
            bb = backend.project.factory.block(endpoint.addr)
            last_instruction = bb.capstone.insns[-1]
            assert last_instruction.mnemonic == u"ret"

    syscalls = [v for k,v in cfg.functions.items() if v.is_syscall]

    for ff in syscalls:
        bb1 = cfg.model.get_any_node(ff.addr)
        assert len(bb1.predecessors) >= 1
        bb2 = bb1.predecessors[0]
        bb = backend.project.factory.block(bb2.addr)
        ii = bb.capstone.insns[-1]
        assert ii.mnemonic ==  u"int" and ii.op_str == u"0x80"

    endpoint_set = set(map(lambda x:(x.addr,x.size),cfg.functions[0x08048230].endpoints))
    assert set([(0x080483F4,12),(0x080483D5,20)]) == endpoint_set
    ret_set = set(map(lambda x:(x.addr,x.size),cfg.functions[0x08048230].ret_sites))
    assert set([(0x080483F4,12)]) == ret_set

    # the following is a case of a bb that should be split by normalization
    # because the bb is split by a "subsequent" jump 
    bb = cfg.model.get_any_node(0x804824F)
    assert bb != None
    assert bb.size == 13
    bb = cfg.model.get_any_node(0x08048230)
    assert bb != None
    assert bb.size == 31


def test_0b32aa01_01():
    print("Testing test_0b32aa01_01...")
    filepath = os.path.join(bin_location, "0b32aa01_01_2")
    backend = DetourBackend(filepath)
    cfg = backend.cfg

    legitimate_functions = {
        0x80480a0,
        0x8048230,
        0x8048400,
        0x80484f0,
        0x80485fc,
        0x8048607,
        0x8048615,
        0x8048635,
        0x80486c3,
        0x80486a9,
        0x8048613,
        0x8048655,
        0x804867b,
        0x80486de,
        0x8048695
    }

    non_syscall_functions = [v for k,v in cfg.functions.items() if not v.is_syscall and not v.alignment]
    #check startpoints, I know that sometimes they could be None, but this should not happen in CADET_00003
    function_entrypoints = set([f.startpoint.addr for f in non_syscall_functions])
    print("additional:", list(map(hex,function_entrypoints-legitimate_functions)))
    print("skipped:", list(map(hex,legitimate_functions-function_entrypoints)))
    assert function_entrypoints == legitimate_functions

    sane_functions = [v for k,v in cfg.functions.items() if is_sane_function(v)]
    function_entrypoints = set([f.startpoint.addr for f in sane_functions])
    print("additional:", list(map(hex,function_entrypoints-legitimate_functions)))
    print("skipped:", list(map(hex,legitimate_functions-function_entrypoints)))
    assert function_entrypoints == legitimate_functions

    #all sane functions ends with ret in CADET_00003
    for ff in sane_functions:
        node = cfg.model.get_any_node(ff.addr, is_syscall=False)
        assert node!=None
        assert len(node.instruction_addrs)>0
        node = cfg.model.get_any_node(ff.addr+1, is_syscall=False,anyaddr=True)
        assert node!=None
        assert len(node.instruction_addrs)>0
        assert ff.startpoint!=None
        assert ff.ret_sites!=None
        if ff.addr == 0x080485FC or ff.addr==0x8048607:
            assert ff.returning==False
        if ff.returning:
            assert len(ff.ret_sites)>0
        for endpoint in ff.ret_sites:
            bb = backend.project.factory.block(endpoint.addr)
            last_instruction = bb.capstone.insns[-1]
            assert last_instruction.mnemonic == u"ret"

    syscalls = [v for k,v in cfg.functions.items() if v.is_syscall]

    for ff in syscalls:
        bb1 = cfg.model.get_any_node(ff.addr)
        assert len(bb1.predecessors) >= 1
        bb2 = bb1.predecessors[0]
        bb = backend.project.factory.block(bb2.addr)
        ii = bb.capstone.insns[-1]
        assert ii.mnemonic ==  u"int" and ii.op_str == u"0x80"


def test_detect_syscall_wrapper():
    filepath = os.path.join(bin_location, "CROMU_00071")
    backend = DetourBackend(filepath)
    cfg = backend.cfg
    legitimate_syscall_wrappers = {
        (0x804d483,1),
        (0x804d491,2),
        (0x804d4b1,3),
        (0x804d4d1,4),
        (0x804d4f7,5),
        (0x804d511,6),
        (0x804d525,7)
    }

    syscall_wrappers = set([(ff.addr,cfg_utils.detect_syscall_wrapper(backend,ff)) \
            for ff in cfg.functions.values() if cfg_utils.detect_syscall_wrapper(backend,ff)!=None])
    print("syscall wrappers in CROMU_00071:")
    print(map(lambda x:(hex(x[0]),x[1]),syscall_wrappers))
    assert syscall_wrappers == legitimate_syscall_wrappers

    filepath = os.path.join(bin_location, "CROMU_00070")
    backend = DetourBackend(filepath)
    cfg = backend.cfg
    legitimate_syscall_wrappers = {
        (0x804d690, 5),
        (0x804d66a, 4),
        (0x804d6be, 7),
        (0x804d6aa, 6),
        (0x804d61c, 1),
        (0x804d64a, 3),
        (0x804d62a, 2)
    }

    syscall_wrappers = set([(ff.addr,cfg_utils.detect_syscall_wrapper(backend,ff)) \
            for ff in cfg.functions.values() if cfg_utils.detect_syscall_wrapper(backend,ff)!=None])
    print("syscall wrappers in CROMU_00070:")
    print(map(lambda x:(hex(x[0]),x[1]),syscall_wrappers))
    assert syscall_wrappers == legitimate_syscall_wrappers


def test_is_floatingpoint_function():
    filepath = os.path.join(bin_location, "CROMU_00071")
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
    print(hex(first),hex(last))
    real_start = 0x804d5c6
    real_end = 0x0804D78b
    assert first == real_start
    assert last <= real_end
    assert last > real_end-0x20 #I allow some imprecision

    filepath = os.path.join(bin_location, "CROMU_00070")
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
    print(hex(first),hex(last))
    real_start = 0x0804D75f
    real_end = 0x0804D924
    assert first == real_start
    assert last <= real_end
    assert last > real_end-0x20 #I allow some imprecision


def test_fullcfg_properties():
    binaries = [ #"CROMU_00071",
                 "KPRCA_00009", #"KPRCA_00025","NRFIN_00004","CROMU_00071", "CADET_00003",
                 # "CROMU_00070",
                 # "EAGLE_00005",
                 # "KPRCA_00019"
                 ]

    # these are either "slides" into a call or jump to the beginning of a call
    # ("KPRCA_00025",0x804b041) is a very weird case, but Fish convinced me that it is correct
    legittimate_jumpouts = [("KPRCA_00025",0x80480bf),("KPRCA_00025",0x804b041),
            ("KPRCA_00025",0x804bd85),("KPRCA_00025",0x804c545),("KPRCA_00025",0x804c5b5), ("KPRCA_00025", 0x804c925),
            ("KPRCA_00019",0x8048326),
            ("KPRCA_00019",0x8048b41),("KPRCA_00019",0x804882e),("KPRCA_00019",0x8048cd1),
            ("KPRCA_00019",0x8048cca),("KPRCA_00019",0x8049408),
            ("KPRCA_00019", 0x8048846), ("KPRCA_00019", 0x804884b), ("KPRCA_00019", 0x804885f),
            ("KPRCA_00019", 0x804886f), ("KPRCA_00019", 0x8048877),
            ("CROMU_00071", 0x804d77d), ("CROMU_00071", 0x804d783),
                            ]

    for binary in binaries:
        print("testing", binary, "...")
        filepath = os.path.join(bin_location, binary)
        backend = DetourBackend(filepath)
        cfg = backend.cfg

        node_addrs_dict = defaultdict(set)
        for k,ff in cfg.functions.items():
            for node_addr in ff.block_addrs_set:
                node_addrs_dict[node_addr].add(ff)
            # check that endpoints are the union of callouts, rets, and jumpouts
            endpoint_union = set(ff.callout_sites).union(set(ff.ret_sites).union(set(ff.jumpout_sites)))
            assert set(ff.endpoints) == endpoint_union

            # check that we do not encounter any unexpected jumpout
            if not ff.is_syscall and ff.returning and not ff.has_unresolved_calls and \
                    not ff.has_unresolved_jumps and ff.startpoint is not None and not ff.alignment and ff.endpoints:
                if not cfg_utils.is_floatingpoint_function(backend,ff):
                    if len(ff.jumpout_sites) > 0:
                        unexpected_jumpout = [(binary,int(jo.addr)) for jo in ff.jumpout_sites \
                                if (binary,int(jo.addr)) not in legittimate_jumpouts]
                        if len(unexpected_jumpout)>0:
                            print("unexpected jumpouts in", binary,
                                  list(map(lambda x: hex(x[1]), unexpected_jumpout))
                                  )
                        assert len(unexpected_jumpout) == 0

        # check that every node only belongs to a single function
        for k,v in node_addrs_dict.items():
            if len(v)>1:
                print("Found node in multiple functions:", hex(k), repr(v))
            assert len(v) == 1

        # check that every node only appears once in the cfg
        nn = set()
        instruction_set = set()
        for n in cfg.model.nodes():
            assert n.addr not in nn
            nn.add(n.addr)
            # check that every instruction appears only in one node
            for iaddr in n.instruction_addrs:
                assert iaddr not in instruction_set
                instruction_set.add(iaddr)


def test_jumpouts_and_indirectcalls():
    expected_jumpouts = [("KPRCA_00034",0x08050140,[0x0805014f])]
    exptected_unresolved_calls = [("KPRCA_00025",0x8048ECC)]

    cfg_cache = {}
    for binary, function_addr, jmps in expected_jumpouts:
        if binary in cfg_cache:
            cfg = cfg_cache["binary"]
        else:
            filepath = os.path.join(bin_location, binary)
            backend = DetourBackend(filepath)
            cfg = backend.cfg
            cfg_cache["binary"] = cfg

        ff  = cfg.functions[function_addr]
        assert [ a.addr for a in ff.jumpout_sites] == jmps

    for binary, function_addr in exptected_unresolved_calls:
        if binary in cfg_cache:
            cfg = cfg_cache["binary"]
        else:
            filepath = os.path.join(bin_location, binary)
            backend = DetourBackend(filepath)
            cfg = backend.cfg
            cfg_cache["binary"] = cfg

        ff  = cfg.functions[function_addr]
        assert ff.has_unresolved_calls


def test_setlongjmp_detection():
    solutions = [
            ("CADET_00003",0x80486c8,0x80486e3),
            ("CROMU_00008",0x804C3AC,0x804C3C7),
            ("Ofast/CROMU_00008",0x804ABD7,0x804ABF2),

    ]

    for tbin, setjmp, longjmp in solutions:
        filepath = os.path.join(bin_location, tbin)
        backend = DetourBackend(filepath)
        cfg = backend.cfg

        for k,ff in cfg.functions.items():
            msg = "detection failure in %s (%#x vs %#x)"
            if cfg_utils.is_setjmp(backend,ff):
                assert setjmp,ff.addr == "setjmp " + msg %(tbin,setjmp,ff.addr)
            elif cfg_utils.is_longjmp(backend,ff):
                assert longjmp,ff.addr == "longjmp " + msg %(tbin,setjmp,ff.addr)


def run_all():
    functions = globals()
    all_functions = dict(filter((lambda x: x[0].startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
