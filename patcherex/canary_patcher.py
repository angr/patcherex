import patcherex

import os
import nose
import subprocess
import logging

l = logging.getLogger("patcherex.CanaryPatcher")

#TODO this should be a subclass of a generic patcher class
class CanaryPatcher(object):

    def __init__(self,binary_fname):
        self.binary_fname = binary_fname
        self.patcher = patcherex.Patcherex(self.binary_fname)
        self.shadow_stack_size = 0x800
        self.ncanary = 0


    def add_common_patches(self):
        self.patcher.add_data("0123456789abcdef", "hex_array")
        self.patcher.add_data("X"*4, "saved_canary")
        self.patcher.add_data("p"*0x4, "shadow_stack_pointer")
        self.patcher.add_data("t"*0x4, "tmp_reg1")
        self.patcher.add_data("t"*0x4, "tmp_reg2")
        self.patcher.add_data("s"*self.shadow_stack_size, "shadow_stack")
        self.patcher.add_data("canary failure: \x00","str_fcanary")
        self.patcher.add_data(" vs \x00","str_vs")

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
        self.patcher.add_code(added_code,"print_hex_eax")

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
        self.patcher.add_code(added_code,"print")

        added_code = '''
            mov     ebx, eax
            mov     eax, 0x1
            int     80h
        '''
        self.patcher.add_code(added_code,"exit_eax")

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
        self.patcher.add_code(added_code,"random")

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
        self.patcher.add_code(added_code,"print_str")

        added_code = '''
            mov eax, 0x44
            call {exit_eax}
        '''
        self.patcher.add_code(added_code,"canary_check_fail")

        #TODO add randomization of starting point
        added_code = '''
            mov DWORD [{shadow_stack_pointer}],{shadow_stack}
        '''
        self.patcher.add_entrypoint_code(added_code)


    #TODO more efficient (at least when ebx and eax are "free")
    def add_canary_to_function(self,start,ends):
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
        self.patcher.insert_into_block(start,added_code,"canary_push_%d"%self.ncanary)
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
            self.patcher.insert_into_block(e,added_code,"canary_pop_%d_%d"%(self.ncanary,i))


    #TODO this is in hack, this should be solved with patch dependencies or by changing patching strategy
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
            if self.check_bb_size(self.patcher.project.factory.block(start)):
                ends = set()
                for endpoint in ff.endpoints:
                    bb = self.patcher.project.factory.block(endpoint)
                    last_instruction = bb.capstone.insns[-1]
                    if last_instruction.mnemonic != u"ret":
                        l.debug("bb at %s does not terminate with a ret in function %s" % (hex(int(bb.addr)),ff.name))
                        break
                    elif not self.check_bb_size(bb):
                        l.debug("end bb at %s is too small in function %s" % (hex(int(bb.addr)),ff.name))
                        break
                    else:
                        ends.add(last_instruction.address)
                else:
                    if len(ends) == 0:
                        l.debug("cannot find any ret in function %s" %ff.name)
                    else:
                        return int(start),map(int,ends) #avoid "long" problems
            else:
                l.debug("start bb is too small in function %s" % ff.name)
            
        l.debug("function %s has problems and cannot be patched" % ff.name)
        return None, None


    def apply_to_entire_bin(self):
        self.add_common_patches()

        cfg = self.patcher.cfg
 
        for k,ff in cfg.function_manager.functions.iteritems():
            start,ends = self.function_to_canary_locations(ff)
            if start!=None and ends !=None:
                #TODO fix patch dependencies problem
                l.info("added canary to function %s (%s -> %s)",ff.name,hex(start),map(hex,ends))
                self.add_canary_to_function(start,ends)

        #import IPython; IPython.embed()

        

        self.patcher.compile_patches()
        return self.patcher.get_final_content()



#TODO this should be called by a "patcher" strategy component
#to do this any patcher class should return a list of patches
#TODO cfg creation should probably not be in patcherex
#TODO communicate with "the crs"
if __name__ == "__main__":
    pass

