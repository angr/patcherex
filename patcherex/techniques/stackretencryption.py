import patcherex

import logging
from patcherex.patches import *

l = logging.getLogger("patcherex.techniques.StackRetEncryption")

class StackRetEncryption(object):

    def __init__(self,binary_fname,backend):
        self.binary_fname = binary_fname
        self.patcher = backend
        self.ncanary = 0
        self.flag_page = 0x4347c000

    def get_common_patches(self):
        common_patches = []
        common_patches.append(AddDataPatch("AbCd","rnd_xor_canary"))
        common_patches.append(AddDataPatch("XXXX","saved_reg"))

        added_code = '''
            mov DWORD [{saved_reg}], ecx
            mov ecx, DWORD [esp+4]
            xor cx, WORD [%s]
            xor ecx, DWORD [{rnd_xor_canary}]
            mov DWORD [esp+4], ecx
            mov ecx, [{saved_reg}]
            ret
        ''' % hex(self.flag_page + 0x123)
        common_patches.append(AddCodePatch(added_code,name="safe_encrypt"))

        #I do not check if rnd actually returned 4 bytes
        added_code = '''
            xor eax, eax
            add al, 7
            mov ebx, {rnd_xor_canary}
            xor ecx, ecx
            add cl, 4
            xor edx, edx
            int 0x80
        '''
        common_patches.append(AddEntryPointPatch(added_code,name="set_shadowstack_pointer"))
        return common_patches


    # TODO detect situation in which it is possible to be sure a register is free
    # best candidates seem eax on entry point and ebx on exit
    # TODO check if it is possible to do insane trick to always overwrite the same stuff and merge things
    def add_shadowstack_to_function(self,start,ends):
        added_code = '''
            call {safe_encrypt}
        '''
        headp = InsertCodePatch(start,added_code,name="canary_push_%d"%self.ncanary)

        tailp = []
        for i,e in enumerate(ends):
            added_code = '''
                call {safe_encrypt}
            '''
            tailp.append(InsertCodePatch(e,added_code,name="canary_pop_%d_%d"%(self.ncanary,i)))
            for p in tailp:
                headp.dependencies.append(p)
                p.dependencies.append(headp)
            self.ncanary += 1

            return [headp]+tailp

    def function_to_canary_locations(self,ff):
        #TODO add more checks for validity
        if not ff.is_syscall and ff.returning and not ff.has_unresolved_calls and not ff.has_unresolved_jumps:
            start = ff.startpoint
            if start == None:
                #Not sure if I can just use ff.addr in these cases... I prefer to err on the safe side
                return None,None
            ends = set()
            for endpoint in ff.endpoints:
                bb = self.patcher.project.factory.block(endpoint.addr)
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
                    return int(start.addr),map(int,ends) #avoid "long" problems
            
        l.debug("function %s has problems and cannot be patched" % ff.name)
        return None, None

    def get_patches(self):
        common_patches = self.get_common_patches()

        cfg = self.patcher.cfg

        patches = []
        for k,ff in cfg.functions.iteritems():
            start,ends = self.function_to_canary_locations(ff)
            if start!=None and ends !=None:
                new_patches = self.add_shadowstack_to_function(start,ends)
                l.info("added shadowstack to function %s (%s -> %s)",ff.name,hex(start),map(hex,ends))
                for p1 in new_patches:
                    for p2 in common_patches: 
                        p1.dependencies.append(p2)
                patches += new_patches
        return common_patches + patches
