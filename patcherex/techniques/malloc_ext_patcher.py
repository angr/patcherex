import patcherex
import angr
import logging
from collections import defaultdict
from itertools import chain

import patcherex.cfg_utils as cfg_utils
from patcherex.patches import AddRWDataPatch, AddEntryPointPatch, InsertCodePatch

l = logging.getLogger("patcherex.techniques.malloc_ext_patcher")


class CfgError(Exception):
    pass


class RegUsed(Exception):
    pass


class MallocExtPatcher:

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
            assert n.addr not in reg_free_map #no duplicated nodes
            assert n.addr != 0 #no weird nodes

            if self.patcher.project.is_hooked(n.addr):
                continue
            if self.patcher.project.simos.syscall_from_addr(n.addr) is not None:
                continue

            try:
                bl = self.patcher.project.factory.block(n.addr, size=n.size)
            except angr.errors.SimTranslationError:
                l.warning("angr translation at block %#x", n.addr)
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

    def is_reg_free(self,addr,reg,ignore_current_bb,debug=False):
        try:
            tsteps = [0]
            chain = self._is_reg_free(addr,reg,ignore_current_bb,level=0,prev=[],total_steps=tsteps,debug=debug)
            if debug:
                print(chain) # the explored tree
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

        # free_regs_in_succ_list = []
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

    def get_patches(self):

        matches = self.ident.matches
        malloc_addr = None
        for f, (name, _) in matches.items():
            if name == "malloc":
                malloc_addr = f.addr
                break

        if malloc_addr is None:
            l.warning("malloc not found")
            return []

        cfg = self.patcher.cfg

        # we need a data patch
        self.patches = []
        self.patches.append(AddRWDataPatch(4, "malloc_pseudorand"))
        added_code = '''
            xor eax, eax
            add al, 7
            mov ebx, {malloc_pseudorand}
            xor ecx, ecx
            add cl, 4
            xor edx, edx
            int 0x80
        '''
        self.patches.append(AddEntryPointPatch(added_code))


        ff = cfg.functions[malloc_addr]
        # get free regs
        free_regs = set()
        for r in self.relevant_registers:
            if self.is_reg_free(ff.addr, r, False):
                free_regs.add(r)
        free_regs = list(free_regs)

        # the malloc patch itself
        prefix = ""
        suffix = ""
        sp_off = 4
        if len(free_regs) == 0:
            use_reg = "eax"
            prefix += "push eax; \n"
            suffix += "pop eax; \n"
            sp_off += 4
        else:
            use_reg = free_regs[0]

        added_code = """
mov %s, DWORD [{malloc_pseudorand}];
add %s, 13;
mov DWORD [{malloc_pseudorand}], %s;
and %s, 0x8;
add %s, 0x8;
add DWORD [esp+%d], %s;
        """ % (use_reg, use_reg, use_reg, use_reg, use_reg, sp_off, use_reg)

        code = prefix + added_code + suffix
        l.debug("adding:\n%s", code)
        self.patches.append(InsertCodePatch(malloc_addr, code))

        return list(self.patches)

def init_technique(program_name, backend, options):
    return MallocExtPatcher(program_name, backend, **options)
