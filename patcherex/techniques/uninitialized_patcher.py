
import logging
from itertools import chain

from collections import defaultdict
from angr.errors import SimEngineError, SimMemoryError

import patcherex.cfg_utils as cfg_utils
from patcherex.patches import InsertCodePatch

l = logging.getLogger("patcherex.techniques.uninitialized_patcher")


class CfgError(Exception):
    pass


class RegUsed(Exception):
    pass


class UninitializedPatcher:

    def __init__(self,binary_fname,backend):
        self.binary_fname = binary_fname
        self.patcher = backend
        self.npatch = 0
        self.ident = self.patcher.identifier
        self.cfg_exploration_depth = 8
        self.max_cfg_steps = 2000
        self.relevant_registers = {"eax","ebx","ecx","edx","esi","edi"}
        self.reg_free_map, self.reg_not_free_map = self.get_reg_free_map()
        self.inv_callsites = self.map_callsites()
        self.patches = []
        self.safe_addrs = None

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
            if self.patcher.project.simos.is_syscall_addr(n.addr):
                continue

            try:
                bl = self.patcher.project.factory.block(n.addr, size=n.size)
            except (SimEngineError, SimMemoryError):
                bl = None

            # no weird or duplicate nodes
            if bl is None or (n.addr in reg_free_map) or n.addr == 0:
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
            free_regs = {r for r in free_regs if r in self.relevant_registers}
            used_regs = {r for r in used_regs if r in self.relevant_registers}
            reg_free_map[n.addr] = free_regs
            reg_not_free_map[n.addr] = used_regs

        return reg_free_map, reg_not_free_map

    def _should_skip(self, ff):
        if cfg_utils.detect_syscall_wrapper(self.patcher, ff) or ff.is_syscall or ff.startpoint is None:
            return True
        if cfg_utils.is_floatingpoint_function(self.patcher, ff):
            return True
        all_pred_addrs = set(x.addr for x in self.patcher.cfg.get_predecessors(self.patcher.cfg.get_any_node(ff.addr)))
        if len(all_pred_addrs) > 5:
            return True

        return False

    @staticmethod
    def _invert_stack_var_accesses(func_info):
        inverted_dict = defaultdict(set)
        for arg, actions in func_info.stack_var_accesses.items():
            if arg in func_info.stack_args:
                continue
            for addr, action in actions:
                inverted_dict[addr].add((arg, action))
        return inverted_dict

    def is_reg_free(self,addr,reg,ignore_current_bb,debug=False):
        try:
            tsteps = [0]
            chain_ = self._is_reg_free(addr,reg,ignore_current_bb,level=0,prev=[],total_steps=tsteps,debug=debug)
            if debug:
                print(chain_) # the explored tree
                print(tsteps) # global number of steps
            return True
        except RegUsed as e:
            if debug:
                print(str(e))
            return False

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
        if node is None:
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

    def _is_reg_free(self,addr,reg,ignore_current_bb,level,total_steps,debug=False,prev=None):
        if prev is None:
            prev = []
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
        chain_ = []
        for s in succ:
            if s in prev:
                continue # avoid exploring already explored nodes (except the first one).
            new_prev = list(prev)
            new_prev.append(s)
            pchain = self._is_reg_free(s,reg,False,level=level+1,total_steps=total_steps,prev=new_prev,debug=debug)
            chain_.append(pchain)
        chain_.append(addr)
        return chain_

    @staticmethod
    def _make_groups(vals, step=-4):
        """Return list of consecutive lists of numbers from vals (number list)."""
        run = []
        result = [run]
        expect = None
        for v in vals:
            if (v == expect) or (expect is None):
                run.append(v)
            else:
                run = [v]
                result.append(run)
            expect = v + step
        return result

    @staticmethod
    def _fix_groups(groups, offset):
        new_groups = []
        for g in groups:
            gg = []
            for a in g:
                if a+offset < 0:
                    gg.append(a + offset)
            new_groups.append(gg)
        return new_groups

    def _handle_func(self, ff):
        if self._should_skip(ff):
            return

        func_info = self.ident.get_func_info(ff.addr)
        if func_info is None:
            return
        if func_info.frame_size > 0x2000:
            return

        inverted_stack_accesses = self._invert_stack_var_accesses(func_info)

        def_uninitialized_reads = set()
        possible_uninitialized_reads = set()

        to_process = [(ff.startpoint, set(), set())]  # block, seen addrs, written to stack vars
        while to_process:
            bl, seen, written = to_process.pop()
            seen.add(bl)

            cfg_node = self.patcher.cfg.get_any_node(bl.addr)
            if not cfg_node:
                continue
            insts = cfg_node.instruction_addrs

            for i in insts:
                if i in inverted_stack_accesses:
                    actions = inverted_stack_accesses[i]
                    for arg, action in actions:
                        if arg >= 0:
                            continue

                        if action == "write":
                            written.add(arg)
                        elif action == "read" and arg not in written and arg % 4 == 0:
                            def_uninitialized_reads.add(arg)
                        elif action == "load" and arg not in written and arg % 4 == 0:
                            # get the min > arg
                            subset_written = set(a for a in written if a > arg)
                            if len(subset_written) == 0:
                                the_next = 0
                            else:
                                the_next = min(subset_written)

                            uninitialized_size = the_next - arg

                            target_kind = self.patcher.project.factory.block(i).vex.constant_jump_targets_and_jumpkinds
                            if len(target_kind) == 1 and list(target_kind.keys())[0] in self.patcher.cfg.functions:
                                call_target = self.patcher.cfg.functions[list(target_kind.keys())[0]]
                            else:
                                call_target = None

                            # if the target is a syscall wrapper (not transmit) it's safe
                            if call_target is None or \
                                    cfg_utils.detect_syscall_wrapper(self.patcher, call_target) == 2 or \
                                    not cfg_utils.detect_syscall_wrapper(self.patcher, call_target):

                                if uninitialized_size < 0x40:
                                    possible_uninitialized_reads.update(arg+x for x in range(0, uninitialized_size, 4))
                                    written.update(arg+x for x in range(0, uninitialized_size, 4))
                            else:
                                written.add(arg)


            succs = ff.graph.successors(bl)
            for s in succs:
                if s not in seen:
                    seen.add(s)
                    to_process.append((s, set(seen), set(written)))

        def_uninitialized_reads = sorted(def_uninitialized_reads)
        possible_uninitialized_reads = sorted(possible_uninitialized_reads)

        if len(def_uninitialized_reads) > 0:
            l.debug("definite uninitialized read by func %#x of vars %s", ff.addr, map(hex, def_uninitialized_reads))

        if len(possible_uninitialized_reads) > 0:
            l.debug("possible uninitialized read by func %#x of vars %s", ff.addr, map(hex, possible_uninitialized_reads))

        to_zero = sorted(def_uninitialized_reads + possible_uninitialized_reads)[::-1]

        if len(to_zero) == 0:
            return

        to_zero = [x-4 for x in to_zero]

        free_regs = set()
        for r in self.relevant_registers:
            if self.is_reg_free(ff.addr, r, False):
                free_regs.add(r)
        free_regs = list(free_regs)

        # note that all of to_zero should be < 0
        if any(v >= 0 for v in to_zero):
            return

        patch_name = "uninit_patch%#x" % ff.addr

        if len(to_zero) == 1:
            code = "mov DWORD [esp%#x], 0; " % to_zero[0]
            l.debug("adding:\n%s", code)
            patch = InsertCodePatch(ff.addr, code, patch_name, stackable=True)
            self.patches.append(patch)
            return

        groups = self._make_groups(to_zero)

        prefix = ""
        suffix = ""
        body = ""
        # use a reg as 0
        if len(free_regs) == 0:
            prefix += "push eax; \n"
            zero_reg = "eax"
            suffix += "pop eax; "
            groups = self._fix_groups(groups, 4)
        else:
            prefix += ""
            zero_reg = free_regs[0]
            suffix += ""
        prefix += "xor %s, %s; \n" % (zero_reg, zero_reg)

        offset_reg = "XXX"  # these should not be used
        offset_reg_curr = 0xffff  # these should not be used
        min_group_size = 3
        if any(len(g) >= min_group_size for g in groups):
            # use a register for the offset
            if len(free_regs) > 1:
                offset_reg = free_regs[1]
            else:
                prefix += "push edi; \n"
                offset_reg = "edi"
                suffix = "pop edi; \n" + suffix
                groups = self._fix_groups(groups, 4)
                if not any(len(g) >= min_group_size for g in groups):
                    min_group_size = min(len(g) for g in groups)

            first_group_off = next(g[0] for g in groups if len(g) >= min_group_size)
            prefix += "lea %s, [esp%#x]; \n" % (offset_reg, first_group_off)
            offset_reg_curr = first_group_off

        for g in groups:
            if len(g) < min_group_size:
                for off in g:
                    body += "mov DWORD [esp%#x], %s; \n" % (off, zero_reg)
            else:
                if offset_reg_curr != g[0]:
                    if g[0]-offset_reg_curr > 0:
                        body += "add %s, %#x; \n" % (offset_reg, g[0]-offset_reg_curr)
                    else:
                        body += "sub %s, %#x; \n" % (offset_reg, offset_reg_curr-g[0])
                offset_reg_curr = g[0]
                for off in g:
                    if off == offset_reg_curr:
                        body += "mov DWORD [%s], %s; \n" % (offset_reg, zero_reg)
                    else:
                        if off-offset_reg_curr >= 0:
                            l.debug("bad error, skipping patch")
                            return
                        body += "mov DWORD [%s%#x], %s; \n" % (offset_reg, off-offset_reg_curr, zero_reg)

        code = prefix + body + suffix
        l.debug("adding:\n%s", code)
        self.patches.append(InsertCodePatch(ff.addr, code, patch_name, stackable=True))

    def get_safe_functions(self):
        # for now we consider functions called by printf or malloc to be safe
        ident_safe = cfg_utils._get_funcs_called_by_printf(self.patcher.project,
                                                           self.patcher.cfg, self.patcher.identifier)
        ident_safe |= cfg_utils._get_funcs_called_by_malloc(self.patcher.project,
                                                           self.patcher.cfg, self.patcher.identifier)
        return ident_safe


    def get_patches(self):

        cfg = self.patcher.cfg

        self.safe_addrs = self.get_safe_functions()

        self.patches = []
        for k, ff in cfg.functions.items():
            if k in self.safe_addrs:
                continue
            self._handle_func(ff)

        return list(self.patches)

def init_technique(program_name, backend, options):
    return UninitializedPatcher(program_name, backend, **options)
