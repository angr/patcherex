import patcherex

import logging
import patcherex.cfg_utils as cfg_utils
from patcherex.patches import *

l = logging.getLogger("patcherex.techniques.SimpleCFI")

class SimpleCFI(object):

    def __init__(self,binary_fname,backend):
        self.binary_fname = binary_fname
        self.patcher = backend

    def get_common_patches(self):
        common_patches = []

        # roughly in order of frequency. x86 encoding is just insane.
        # it assumes that eax points to the "after call" instruction
        added_code = '''
            cmp BYTE [eax-0x5], 0xE8 ; call 0x11223344
            je _exit_sc
            cmp BYTE [eax-0x6], 0xFF ; call [0x11223344]
            je _exit_sc
            cmp BYTE [eax-0x2], 0xFF ; call eax
            je _exit_sc
            cmp BYTE [eax-0x3], 0xFF ; call [eax+edx]
            je _exit_sc
            cmp BYTE [eax-0x4], 0xFF ; call [eax+edx+0x1]
            je _exit_sc
            cmp BYTE [eax-0x7], 0xFF ; call [eax*8+edx+0x11223344]
            je _exit_sc
            cmp BYTE [eax-0x3], 0xE8 ; call 0x1122 (using 0x66 as prefix before E8)
            je _exit_sc
            cmp BYTE [eax-0x5], 0xFF ; not sure if possible
            je _exit_sc
            ; terminate(0x45)
            xor ebx, ebx
            mov bl, 0x45
            xor eax, eax
            inc eax
            int 0x80
            _exit_sc:
            ret
        '''
        common_patches.append(AddCodePatch(added_code,name="simplecfi_test_int"))

        added_code = '''
            push eax
            mov eax, DWORD [esp+0x8]
            call {simplecfi_test_int}
            pop eax
            ret
        '''
        common_patches.append(AddCodePatch(added_code,name="simplecfi_test_no_offset"))

        return common_patches

    def add_simplecfi_test(self,end):
        #the idea is to keep this code as small as possible, since it will be injected in a lot of places
        added_code = '''
            call {simplecfi_test_no_offset}
        '''

        patch = InsertCodePatch(end,added_code,name="simplecfi_check_%08X"%end)
        return [patch]

    def function_to_ret_locations(self,ff):
        if cfg_utils.is_sane_function(ff):
            start = ff.startpoint
            ends = set()
            for ret_site in ff.ret_sites:
                bb = self.patcher.project.factory.block(ret_site.addr)
                last_instruction = bb.capstone.insns[-1]
                if last_instruction.mnemonic != u"ret":
                    l.debug("bb at %s does not terminate with a ret in function %s" % (hex(int(bb.addr)),ff.name))
                    break
                else:
                    if last_instruction.op_str == "":
                        offset = 0
                    else:
                        offset = int(last_instruction.op_str,16)
                    ends.add((int(last_instruction.address),offset))
            else:
                if len(ends) == 0:
                    l.debug("cannot find any ret in function %s" % ff.name)
                else:
                    return ends #avoid "long" problems

        l.debug("function %s has problems and cannot be patched" % ff.name)
        return []

    def get_patches(self):
        common_patches = self.get_common_patches()

        patches = []
        cfg = self.patcher.cfg
        for k,ff in cfg.functions.items():
            ends = self.function_to_ret_locations(ff)
            for end,offset in ends:
                #I realize that we do not really care about the offset in the "ret imm16" case
                new_patch = self.add_simplecfi_test(end)
                l.info("added simplecfi patch to function %s, ret %s, offset %s",ff.name,hex(end),hex(offset))
                patches += new_patch

        return common_patches + patches

def init_technique(program_name, backend, options):
    return SimpleCFI(program_name, backend, **options)
