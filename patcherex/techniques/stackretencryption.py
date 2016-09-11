
import logging
from collections import defaultdict
from itertools import chain

from angr.errors import SimEngineError, SimMemoryError

import patcherex.cfg_utils as cfg_utils
from patcherex.patches import *

l = logging.getLogger("patcherex.techniques.StackRetEncryption")

class CfgError(Exception):
    pass


class RegUsed(Exception):
    pass


class StackRetEncryption(object):

    def __init__(self,binary_fname,backend,allow_reg_reuse=True):
        self.binary_fname = binary_fname
        self.patcher = backend
        self.npatch = 0
        self.flag_page = 0x4347c000
        self.allow_reg_reuse = allow_reg_reuse
        self.cfg_exploration_depth = 8
        self.max_cfg_steps = 2000
        self.found_setjmp = None
        self.found_longjmp = None
        self.safe_functions = set()
        # any function that is called in more than this many places is assumed to be safe
        self.safe_calls_limit = 5

        self.relevant_registers = set(["eax","ebx","ecx","edx","esi","edi"])
        self.reg_free_map, self.reg_not_free_map = self.get_reg_free_map()

        self.inline_encrypt = '''
            pop %s;
            xor %s, DWORD [{rnd_xor_key}];
            push %s;
        '''

        self.safe_inline_encrypt = '''
            call {safe_encrypt}
        '''

        self.safe_encrypt = '''
            push ecx
            mov ecx, DWORD [esp+8]
            xor ecx, DWORD [{rnd_xor_key}]
            mov DWORD [esp+8], ecx
            pop ecx
            ret
        '''
        self.need_safe_encrypt = False

        self.inv_callsites = self.map_callsites()
        self.terminate_function = None

    def map_callsites(self):
        callsites = dict()
        for f in self.patcher.cfg.functions.values():
            for callsite in f.get_call_sites():
                if f.get_call_target(callsite) is None:
                    continue
                callsites[callsite] = f.get_call_target(callsite)

        # create inverse callsite map
        inv_callsites = defaultdict(set)
        for c, f in callsites.items():
            inv_callsites[f].add(c)
        return inv_callsites

    def get_common_patches(self):
        common_patches = []
        common_patches.append(AddRWDataPatch(4,"rnd_xor_key"))

        #I do not check if rnd actually returned 4 bytes
        added_code = '''
            xor eax, eax
            add al, 7
            mov ebx, {rnd_xor_key}
            xor ecx, ecx
            add cl, 4
            xor edx, edx
            int 0x80
        '''
        common_patches.append(AddEntryPointPatch(added_code,name="set_rnd_xor_key"))
        return common_patches


    def is_reg_free(self,addr,reg,ignore_current_bb,debug=False):
        tsteps = [0]
        try:
            chain = self._is_reg_free(addr,reg,ignore_current_bb,level=0,prev=[],total_steps=tsteps,debug=debug)
            if debug:
                print(chain) # the explored tree
                print(tsteps) # global number of steps
            return True
        except RegUsed as e:
            if debug:
                print(str(e))
                print(tsteps)
            return False

    def _is_reg_free(self,addr,reg,ignore_current_bb,level,total_steps,debug=False,prev=None):
        if level >= self.cfg_exploration_depth:
            raise RegUsed("Max depth %#x %s" % (addr,map(hex,prev)))

        if not ignore_current_bb:
            if not addr in self.reg_free_map:
                # we reached some weird bb
                raise RegUsed("Weird block %#x %s" % (addr,map(hex,prev)))
            if reg in self.reg_free_map[addr]:
                return [addr]
            if reg in self.reg_not_free_map[addr]:
                raise RegUsed("Not free in bb %#x %s" % (addr,map(hex,prev)))

        if prev is None:
            prev = [ ]

        try:
            succ, is_terminate = self.get_all_succ(addr)
            # if addr==0x0804B390:
            #    import IPython; IPython.embed()
            if is_terminate:
                return [addr]
            if len(succ)==0:
                # no successors is weird, the cfg may be incomplete (e.g., NRFIN_00026 original 0x0897F4D5)
                raise RegUsed("No successors  %#x %s" % (addr,map(hex,prev)))
            total_steps[0] += 1
            if total_steps[0] >= self.max_cfg_steps:
                raise RegUsed("Too many steps  %#x %s" % (addr,map(hex,prev)))
        except CfgError:
            # something weird is happening in the cfg, let's assume no reg is free
            raise RegUsed("CFG error %#x %s" % (addr,map(hex,prev)))

        free_regs_in_succ_list = []
        chain = []
        for s in succ:
            if s in prev:
                continue # avoid exploring already explored nodes (except the first one).
            new_prev = list(prev)
            new_prev.append(s)
            pchain = self._is_reg_free(s,reg,False,level=level+1,total_steps=total_steps,prev=new_prev,debug=debug)
            chain.append(pchain)
        chain.append(addr)
        return chain

    def add_patch_at_bb(self,addr,is_tail=False):
        if is_tail:
            relavent_regs = ["ecx", "edx"]
        else:
            relavent_regs = ["eax", "ecx", "edx"]

        for r in relavent_regs:
            if self.is_reg_free(addr, r, is_tail):
                inserted_code = self.make_inline_encrypt(r)
                if not is_tail:
                    # we add a nop so that indirectcfi will not see a pop at the beginning of a function
                    # this is a problem because indirectcfi does not like indirect calls to pop
                    inserted_code = "nop\n"+inserted_code
                return inserted_code
        self.need_safe_encrypt = True
        return self.safe_inline_encrypt

    # TODO check if it is possible to do insane trick to always overwrite the same stuff and merge things
    def add_stackretencryption_to_function(self,start,ends):
        # in the grand-plan these patches have higher priority than, for instance, indirect jump ones
        # this only matters in case of conflicts
        l.debug("Trying adding stackretencryption to %08x %s"%(start,map(lambda x:hex(int(x)),ends)))
        headp = InsertCodePatch(start,self.add_patch_at_bb(start),name="stackretencryption_head_%d_%#x"%(self.npatch,start),priority=100)

        tailp = []
        for i,e in enumerate(ends):
            bb_addr = self.patcher.cfg.get_any_node(e,anyaddr=True).addr
            code = self.add_patch_at_bb(bb_addr,is_tail=True)
            tailp.append(InsertCodePatch(e,code,name="stackretencryption_tail_%d_%d_%#x"%(self.npatch,i,start),priority=100))

        for p in tailp:
            headp.dependencies.append(p)
            p.dependencies.append(headp)
        self.npatch += 1
        return [headp]+tailp

    def function_to_patch_locations(self,ff):
        # TODO tail-call is handled lazily just by considering jumping out functions as not sane
        if cfg_utils.is_sane_function(ff) and cfg_utils.detect_syscall_wrapper(self.patcher,ff) == None \
                and not cfg_utils.is_floatingpoint_function(self.patcher,ff) and not ff.addr in self.safe_functions:
            if cfg_utils.is_longjmp(self.patcher,ff):
                self.found_longjmp = ff.addr
            elif cfg_utils.is_setjmp(self.patcher,ff):
                self.found_setjmp = ff.addr
            else:
                start = ff.startpoint
                ends = set()
                for ret_site in ff.ret_sites:
                    bb = self.patcher.project.factory.fresh_block(ret_site.addr, ret_site.size)
                    last_instruction = bb.capstone.insns[-1]
                    if last_instruction.mnemonic != u"ret":
                        msg = "bb at %s does not terminate with a ret in function %s"
                        l.debug(msg % (hex(int(bb.addr)),ff.name))
                        break
                    else:
                        ends.add(last_instruction.address)
                else:
                    if len(ends) == 0:
                        l.debug("cannot find any ret in function %s" %ff.name)
                    else:
                        return int(start.addr),map(int,ends) #avoid "long" problems

        l.debug("function %s has problems and cannot be patched" % ff.name)
        return None, None

    def is_last_returning_block(self,node):
        node = self.patcher.cfg.get_any_node(node.addr)
        try:
            function = self.patcher.cfg.functions[node.function_address]
        except KeyError:
            # TODO this is probably a cfg bug
            return False
        if any([node.addr == e.addr for e in function.ret_sites]):
            return True
        return False

    def last_block_to_return_locations(self,addr):
        node = self.patcher.cfg.get_any_node(addr)
        if node == None:
            return []
        function = self.patcher.cfg.functions[node.function_address]
        if node.addr not in [n.addr for n in function.endpoints]:
            return []

        return_locations = []
        for site in self.inv_callsites[function.addr]:
            node = self.patcher.cfg.get_any_node(site)
            nlist = self.patcher.cfg.get_successors_and_jumpkind(node, excluding_fakeret=False)
            return_locations.extend([n[0] for n in nlist if n[1]=='Ijk_FakeRet'])
        return return_locations

    @staticmethod
    def get_reg_name(arch, reg_offset):
        """
        :param reg_offset: Tries to find the name of a register given the offset in the registers.
        :return: The register name
        """
        if reg_offset is None:
            return None

        original_offset = reg_offset
        while reg_offset >= 0 and reg_offset >= original_offset - (arch.bits/8):
            if reg_offset in arch.register_names:
                return arch.register_names[reg_offset]
            else:
                reg_offset -= 1
        return None

    def get_reg_free_map(self):
        l.info("Checking reg writes and reads from the graph")

        # map all basic block addresses in the function to which regs are read or written
        reg_free_map = dict()
        reg_not_free_map = dict()
        for n in self.patcher.cfg.nodes():

            if self.patcher.project.is_hooked(n.addr):
                continue
            if self.patcher.project.simos.syscall_from_addr(n.addr) is not None:
                continue

            try:
                bl = self.patcher.project.factory.block(n.addr, size=n.size)
            except (SimEngineError, SimMemoryError):
                bl = None

            # no weird or duplicate nodes
            if bl == None or (n.addr in reg_free_map) or n.addr == 0:
                continue

            used_regs = set()
            free_regs = set()

            for s in bl.vex.statements:
                for e in chain([s], s.expressions):
                    if e.tag == "Iex_Get":
                        reg = self.get_reg_name(self.patcher.project.arch, e.offset)
                        if reg not in free_regs:
                            used_regs.add(reg)
                    elif e.tag == "Ist_Put":
                        reg = self.get_reg_name(self.patcher.project.arch, e.offset)
                        if reg not in used_regs:
                            free_regs.add(reg)
            free_regs = set([r for r in free_regs if r in self.relevant_registers])
            used_regs = set([r for r in used_regs if r in self.relevant_registers])
            reg_free_map[n.addr] = free_regs
            reg_not_free_map[n.addr] = used_regs

        return reg_free_map, reg_not_free_map

    def get_all_succ(self,addr):
        cfg = self.patcher.cfg
        all_nodes = cfg.get_all_nodes(addr)
        if len(all_nodes) != 1:
            raise CfgError()
        n = all_nodes[0]

        # this is "context insensitive": it does not consider call stack
        if self.is_last_returning_block(n):
            return [n.addr for n in self.last_block_to_return_locations(addr)], False

        all_succ = set()
        for s, jk in cfg.get_successors_and_jumpkind(n):
            if not jk.startswith("Ijk_Sys"):
                all_succ.add(s.addr)
                # a syscall writes in eax, I do not handle it explicitly
                # because the syscall wrappers already unfree everything
            elif s.name == "_terminate":
                return [], True
        return all_succ, False

    def _block_calls_safe_syscalls(self, block, func_info, var):
        # checks that the block only calls sycalls that aren't receive
        # receive is the only one that stack ret encryption is useful for
        # also only checks this var

        target_kind = block.vex.constant_jump_targets_and_jumpkinds
        if len(target_kind) != 1:
            return False
        if list(target_kind.keys())[0] not in self.patcher.cfg.functions:
            return False
        target = self.patcher.cfg.functions[list(target_kind.keys())[0]]
        if cfg_utils.detect_syscall_wrapper(self.patcher, target) and \
                cfg_utils.detect_syscall_wrapper(self.patcher, target) != 3:
            return True

        # if it is receive we need to do extra checks
        if cfg_utils.detect_syscall_wrapper(self.patcher, target) and \
                        cfg_utils.detect_syscall_wrapper(self.patcher, target) == 3:

            # execute the block
            s = self.patcher.identifier.base_symbolic_state.copy()
            s.regs.ip = block.addr
            if func_info.bp_based:
                s.regs.bp = s.regs.sp + func_info.bp_sp_diff
            simgr = self.patcher.project.factory.simulation_manager(s, save_unconstrained=True)
            simgr.step()
            if len(simgr.active + simgr.unconstrained) > 0:
                succ = (simgr.active + simgr.unconstrained)[0]
                rx_arg = succ.mem[succ.regs.sp+16].dword.resolved
                size_arg = succ.mem[succ.regs.sp+12].dword.resolved
                # we say the rx_bytes arg is okay
                if not rx_arg.symbolic:
                    if func_info.bp_based:
                        rx_bytes_off = 0-succ.solver.eval(s.regs.bp-rx_arg)
                    else:
                        rx_bytes_off = succ.solver.eval(rx_arg-s.regs.sp) - (func_info.frame_size + 4) + 4
                    if rx_bytes_off == var:
                        return True

        return False

    def _func_is_safe(self, ident, func):
        if func not in ident.func_info:
            return False
        func_info = ident.func_info[func]
        if len(func_info.buffers) == 0:
            return True

        # skip functions that have enough predecessors
        if len(self.patcher.cfg.get_predecessors(self.patcher.cfg.get_any_node(func.addr))) > self.safe_calls_limit:
            return True

        is_safe = True
        for v in func_info.buffers:
            if v in func_info.stack_var_accesses:
                # if it wasn't a load it's definitely not safe
                if not any(kind == "load" for _, kind in func_info.stack_var_accesses[v]):
                    is_safe = False
                # if it was a load form a safe syscall it's safe
                for addr, kind in func_info.stack_var_accesses[v]:
                    if kind == "load":
                        bbl = self.patcher.project.factory.block(addr)
                        if not self._block_calls_safe_syscalls(bbl, func_info, v):
                            is_safe = False
        return is_safe

    def get_safe_functions(self):
        ident = self.patcher.identifier

        # for now we consider functions called by printf or malloc to be safe
        ident_safe = cfg_utils._get_funcs_called_by_printf(self.patcher.project,
                                                           self.patcher.cfg, self.patcher.identifier)
        ident_safe |= cfg_utils._get_funcs_called_by_malloc(self.patcher.project,
                                                           self.patcher.cfg, self.patcher.identifier)

        safe_func_addrs = set()
        unsafe_func_addrs = set()
        for f in self.patcher.cfg.functions.values():
            if f.addr in ident_safe or self._func_is_safe(ident, f):
                l.debug("%#x is safe", f.addr)
                safe_func_addrs.add(f.addr)
            else:
                l.debug("%#x is unsafe", f.addr)
                unsafe_func_addrs.add(f.addr)
        return safe_func_addrs

    def make_inline_encrypt(self, reg):
        return self.inline_encrypt % (reg, reg, reg)

    def find_savedretaccess_functions(self,functions):
        def is_ebp_based_function(ff):
            def instruction_to_str(instr):
                return str(instr.mnemonic+" "+instr.op_str)

            if self.patcher.project.is_hooked(ff.addr):
                return False
            if self.patcher.project.simos.is_syscall_addr(ff.addr) is not None:
                return False

            instructions = self.patcher.project.factory.fresh_block(ff.addr, size=ff.startpoint.size).capstone.insns
            if instruction_to_str(instructions[0]) == "push ebp" and\
                    instruction_to_str(instructions[1]) == "mov ebp, esp":
                return True
            else:
                return False

        blacklist = set()
        for k, ff in functions.items():
            if not is_ebp_based_function(ff):
                continue

            for block in ff.blocks:
                state = 'find_ebp'
                vex = block.vex
                state = 'find_ebp'
                for s in vex.statements:
                    if state == 'find_ebp':
                        exprs = list(s.expressions)
                        if len(exprs)==1 and (s.tag=='Ist_Put' or s.tag=='IstStore') and\
                                s.offset==vex.arch.registers['ebp'][0]:
                            if hasattr(exprs[0],"tmp"):
                                ebp_tmp = exprs[0].tmp
                                state = 'deref_ebp'
                    elif state == 'deref_ebp':
                        exprs = list(s.expressions)
                        if len(exprs)==2 and s.tag=='Ist_WrTmp':
                            if hasattr(exprs[1],"tmp"):
                                if exprs[1].tmp == ebp_tmp:
                                    deref_tmp = s.tmp
                                    state = 'deref_ebp2'
                    elif state == 'deref_ebp2':
                        exprs = list(s.expressions)
                        if len(exprs)==3 and s.tag=='Ist_WrTmp' and 4 in {v.value for v in s.constants}:
                            plus4_tmp = s.tmp
                            state = 'deref_plus4'
                    elif state == 'deref_plus4':
                        exprs = list(s.expressions)
                        if len(exprs)==2 and s.tag=='Ist_WrTmp':
                            if hasattr(exprs[1],"tmp"):
                                if exprs[1].tmp == plus4_tmp:
                                    deref_tmp2 = s.tmp
                                    state = 'found_access'
                    elif state == 'found_access':
                        exprs = list(s.expressions)
                        if len(exprs)==2 and s.tag=='Ist_Store':
                            # print s
                            if hasattr(exprs[1],"tmp"):
                                if exprs[1].tmp == deref_tmp2:
                                    state = "found"
                                    break
                        elif len(exprs)==1 and s.tag=='Ist_Put':
                            #print s
                            if hasattr(exprs[0],"tmp"):
                                if exprs[0].tmp == deref_tmp2:
                                    state = 'found'
                                    break
                else:
                    continue
                break #double break

            if state == 'found':
                l.warning("found saved reg access at %#x", block.addr)
                blacklist.add(ff.addr)
                if ff.addr in self.inv_callsites:
                    blacklist.update(self.inv_callsites[ff.addr])
                    l.warning("saved reg access callers %s" % map(hex,(self.inv_callsites[ff.addr])))
                # l.warning("vex code: %s" % "\n".join(map(str,vex.statements)))
        if len(blacklist) > 0:
            l.warning("blacklisted functions because of reg access callers %s" % map(hex,blacklist))
        return blacklist

    def get_patches(self):
        common_patches = self.get_common_patches()

        self.safe_functions = self.get_safe_functions()

        cfg = self.patcher.cfg
        patches = []
        blacklisted_functions = self.find_savedretaccess_functions(cfg.functions)
        for k,ff in cfg.functions.items():
            if ff.addr in blacklisted_functions:
                continue
            start,ends = self.function_to_patch_locations(ff)
            if start!=None and ends !=None:
                new_patches = self.add_stackretencryption_to_function(start,ends)
                l.info("added StackRetEncryption to function %s (%s -> %s)",ff.name,hex(start),map(hex,ends))
                patches += new_patches

        if self.found_longjmp == None:
            l.warning("longjmp not found!")
        else:
            code_longjmp = '''
                mov bl, BYTE [ecx] ; ebp is free at this point of longjmp
            '''
            # unfortunately KPRCA_00026 manually creates setjmp structures
            # I just check that the place where we are jumping to is readable, this does not prevent ROP
            # a more sophosticated thing is to use cgrex or check that
            # we are jumping either after setjmp or to a function
            p1 = InsertCodePatch(self.found_longjmp+10,code_longjmp,name="longjmp_protection",priority=200)
            patches.append(p1)

        if self.need_safe_encrypt:
            common_patches.append(AddCodePatch(self.safe_encrypt,name="safe_encrypt"))

        return common_patches + patches

def init_technique(program_name, backend, options):
    return StackRetEncryption(program_name, backend, **options)
