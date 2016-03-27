import patcherex

import os
import nose
import subprocess
import logging
from patcherex.patches import *
from patcherex.backends.basebackend import BaseBackend

l = logging.getLogger("patcherex.techniques.ShadowStack")

#TODO this should be a subclass of a generic patcher class
class ShadowStack(object):

    def __init__(self,binary_fname):
        self.binary_fname = binary_fname
        self.patcher = BaseBackend(self.binary_fname)
        self.shadow_stack_size = 0x800
        self.ncanary = 0


    def get_common_patches(self):
        common_patches = []
        common_patches.append(AddDataPatch("0123456789abcdef",name="hex_array"))
        common_patches.append(AddDataPatch("X"*4,name="saved_canary"))
        common_patches.append(AddDataPatch("p"*4,name="shadow_stack_pointer"))
        common_patches.append(AddDataPatch("t"*4,name="tmp_reg1"))
        common_patches.append(AddDataPatch("t"*4,name="tmp_reg2"))
        common_patches.append(AddDataPatch("s"*self.shadow_stack_size,name="shadow_stack"))
        common_patches.append(AddDataPatch("canary failure: \x00",name="str_fcanary"))
        common_patches.append(AddDataPatch(" vs \x00",name="str_vs"))

        added_code = '''
            ; print eax as hex
            pusha
            mov ecx,32
            mov ebx,eax
            _print_reg_loop:
                rol ebx,4
                mov edi,ebx
                and edi,0x0000000f
                lea eax,[{hex_array}+edi]
                mov ebp,ebx
                mov ebx,0x1
                call {print}
                mov ebx,ebp
                sub ecx,4
                jnz _print_reg_loop
            popa
            ret
        '''
        common_patches.append(AddCodePatch(added_code,name="print_hex_eax"))

        added_code = '''
            ; eax=buf,ebx=len
            pusha
            mov ecx,eax
            mov edx,ebx
            mov eax,0x2
            mov ebx,0x1
            mov esi,0x0
            int 0x80
            popa
            ret
        '''
        common_patches.append(AddCodePatch(added_code,name="print"))

        added_code = '''
            mov     ebx, eax
            mov     eax, 0x1
            int     80h
        '''
        common_patches.append(AddCodePatch(added_code,name="exit_eax"))

        added_code = '''
            ; put 4 random bytes in eax
            pusha
            mov ebx, eax
            mov eax,7
            mov ecx,4
            mov edx,0
            int 0x80
            popa
            ret
        '''
        common_patches.append(AddCodePatch(added_code,name="random"))

        added_code = '''
            ; print a null terminated string pointed by eax
            pusha
            mov ecx, eax
            _loop:
                cmp BYTE [ecx],0
                je _out
                mov edx,1
                mov eax,0x2
                mov ebx,0x1
                mov esi,0x0
                int 0x80
                inc ecx
                jmp _loop
            _out:
            popa
            ret
        '''
        common_patches.append(AddCodePatch(added_code,name="print_str"))

        added_code = '''
            mov eax, 0x44
            call {exit_eax}
        '''
        common_patches.append(AddCodePatch(added_code,name="canary_check_fail"))

        #TODO add randomization of starting point
        added_code = '''
            mov DWORD [{shadow_stack_pointer}],{shadow_stack}
        '''
        common_patches.append(AddEntryPointPatch(added_code,name="set_shadowstack_pointer"))
        return common_patches


    #TODO more efficient (at least when ebx and eax are "free")
    def add_shadowstack_to_function(self,start,ends):
        added_code = '''
            mov DWORD [{tmp_reg1}], eax
            mov DWORD [{tmp_reg2}], ebx

            mov eax, DWORD [esp]
            mov ebx, DWORD [{shadow_stack_pointer}]
            mov DWORD [ebx], eax
            add DWORD [{shadow_stack_pointer}], 4

            mov eax,  DWORD [{tmp_reg1}]
            mov ebx,  DWORD [{tmp_reg2}]
        '''
        headp = InsertCodePatch(start,added_code,name="canary_push_%d"%self.ncanary)
        tailp = []
        for i,e in enumerate(ends):
            added_code = '''
                mov  DWORD [{tmp_reg1}], eax
                mov  DWORD [{tmp_reg2}], ebx

                mov eax, DWORD [esp]
                sub DWORD [{shadow_stack_pointer}], 4
                mov ebx, DWORD [{shadow_stack_pointer}]
                cmp eax, DWORD [ebx]
                jne {canary_check_fail}

                mov eax,  DWORD [{tmp_reg1}]
                mov ebx,  DWORD [{tmp_reg2}]
            '''
            tailp.append(InsertCodePatch(e,added_code,name="canary_pop_%d_%d"%(self.ncanary,i)))
            for p in tailp:
                headp.dependencies.append(p)
                p.dependencies.append(headp)
            self.ncanary += 1
            return [headp]+tailp

    #not used anymore
    def check_bb_size(self,bb):
        movable_instructions = self.patcher.get_movable_instructions(bb)
        movable_bb_size = self.patcher.project.factory.block(bb.addr, num_inst=len(movable_instructions)).size
        if movable_bb_size < 5:
            return False
        else:
            return True

    def function_to_canary_locations(self,ff):
        #TODO add more checks for validity
        if not ff.is_syscall and ff.returning and not ff.has_unresolved_calls and not ff.has_unresolved_jumps:
            start = ff.startpoint
            ends = set()
            for endpoint in ff.endpoints:
                bb = self.patcher.project.factory.block(endpoint)
                last_instruction = bb.capstone.insns[-1]
                if last_instruction.mnemonic != u"ret":
                    l.debug("bb at %s does not terminate with a ret in function %s" % (hex(int(bb.addr)),ff.name))
                    break
                else:
                    ends.add(last_instruction.address)
            else:
                if len(ends) == 0:
                    l.debug("cannot find any ret in function %s" %ff.name)
                else:
                    return int(start),map(int,ends) #avoid "long" problems
            
        l.debug("function %s has problems and cannot be patched" % ff.name)
        return None, None


    def get_patches(self):
        common_patches = self.get_common_patches()

        cfg = self.patcher.cfg

        patches = []
        for k,ff in cfg.function_manager.functions.iteritems():
            start,ends = self.function_to_canary_locations(ff)
            if start!=None and ends !=None:
                new_patches = self.add_shadowstack_to_function(start,ends)
                l.info("added shadowstack to function %s (%s -> %s)",ff.name,hex(start),map(hex,ends))
                for p1 in new_patches:
                    for p2 in common_patches: 
                        p1.dependencies.append(p2)
                patches += new_patches
        return common_patches + patches
