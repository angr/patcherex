import patcherex
import angr
import logging
from collections import defaultdict

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

        self.relevant_registers = set(["eax","ebx","ecx","edx","esi","edi"])
        self.reg_free_map, self.reg_not_free_map = self.get_reg_free_map()

        added_code = '''
            mov ecx, DWORD [esp+4]
            xor cx, WORD [%s]
            xor ecx, DWORD [{rnd_xor_key}]
            mov DWORD [esp+4], ecx
            ret
        ''' % hex(self.flag_page + 0x123)
        self.encrypt_using_ecx_patch = AddCodePatch(added_code,name="encrypt_using_ecx")
        added_code = '''
            mov edx, DWORD [esp+4]
            xor dx, WORD [%s]
            xor edx, DWORD [{rnd_xor_key}]
            mov DWORD [esp+4], edx
            ret
        ''' % hex(self.flag_page + 0x123)
        self.encrypt_using_edx_patch = AddCodePatch(added_code,name="encrypt_using_edx")
        added_code = '''
            push ecx
            mov ecx, DWORD [esp+8]
            xor cx, WORD [%s]
            xor ecx, DWORD [{rnd_xor_key}]
            mov DWORD [esp+8], ecx
            pop ecx
            ret
        ''' % hex(self.flag_page + 0x123)
        self.safe_encrypt_patch = AddCodePatch(added_code,name="safe_encrypt")

        self.used_ecx_patch = False
        self.used_edx_patch = False
        self.used_safe_patch = False
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
        for c, f in callsites.iteritems():
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
        try:
            tsteps = [0]
            chain = self._is_reg_free(addr,reg,ignore_current_bb,level=0,prev=[],total_steps=tsteps,debug=debug)
            if debug:
                print chain # the explored tree
                print tsteps # global number of steps
            return True
        except RegUsed as e:
            if debug:
                print e.message
                print tsteps
            return False

    def _is_reg_free(self,addr,reg,ignore_current_bb,level,total_steps,debug=False,prev=[]):
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
        if self.is_reg_free(addr,"ecx",is_tail) and self.allow_reg_reuse:
            l.debug("using encrypt_using_ecx method for bb at %s" % hex(int(addr)))
            self.used_ecx_patch = True
            inserted_code = "call {encrypt_using_ecx}"
        elif self.is_reg_free(addr,"edx",is_tail) and self.allow_reg_reuse:
            l.debug("using encrypt_using_edx method for bb at %s" % hex(int(addr)))
            self.used_edx_patch = True
            inserted_code = "call {encrypt_using_edx}"
        else:
            l.debug("using safe_encrypt method for bb at %s" % hex(int(addr)))
            self.used_safe_patch = True
            inserted_code = "call {safe_encrypt}"
        return inserted_code

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
                and not cfg_utils.is_floatingpoint_function(self.patcher,ff):
            if cfg_utils.is_longjmp(self.patcher,ff):
                self.found_longjmp = ff.addr
            elif cfg_utils.is_setjmp(self.patcher,ff):
                self.found_setjmp = ff.addr
            else:
                start = ff.startpoint
                ends = set()
                for ret_site in ff.ret_sites:
                    bb = self.patcher.project.factory.block(ret_site.addr)
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
        function = self.patcher.cfg.functions[node.function_address]
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
            assert n.addr not in reg_free_map #no duplicated nodes
            assert n.addr != 0 #no weird nodes

            bl = self.patcher.project.factory.block(n.addr)
            used_regs = set()
            free_regs = set()

            for s in bl.vex.statements:
                for e in [s] + s.expressions:
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

    def get_patches(self):
        common_patches = self.get_common_patches()

        cfg = self.patcher.cfg
        patches = []
        for k,ff in cfg.functions.iteritems():
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


        if self.used_safe_patch:
            patches.append(self.safe_encrypt_patch)
        if self.used_ecx_patch:
            patches.append(self.encrypt_using_ecx_patch)
        if self.used_edx_patch:
            patches.append(self.encrypt_using_edx_patch)
        return common_patches + patches
