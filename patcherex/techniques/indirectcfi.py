import patcherex
import angr
import patcherex.utils as utils

import capstone
import logging
from patcherex.patches import *

l = logging.getLogger("patcherex.techniques.IndirectCFI")


class CfgError(Exception):
    pass


class IndirectCFI(object):

    def __init__(self,binary_fname,backend,allow_reg_reuse=True):
        self.binary_fname = binary_fname
        self.patcher = backend

    def get_common_patches(self):
        # nothing for now, may need 4 RW bytes if we stop using push/pop method to save/restore used reg
        common_patches = []
        return common_patches

    def classify_cj(self, instruction):
        # TODO handle special cases
        # a common pattern is: 
        # mov     ecx, ds:off_83C4B88[eax*4]
        # jmp     ecx
        # in this case we could protect eax to be less than about 500
        return "standard"

    def handle_standard_cj(self,instruction):
        def compile_mem_access(instruction):
            # I could use some compiler-like approach like the old cgrex, but I think it is overkill
            # instead, I just "copy" the code from capstone
            tstr = instruction.op_str.encode('ascii','ignore')
            instruction_str = instruction.mnemonic + " " + instruction.op_str
            # TODO if we move to keystone removing " ptr " may not be necessary
            # the problem here is that capstone writes prt and NASM does not like it
            mem_access_str = "mov edx, %s" % (instruction.op_str.lower().replace(" ptr ",""))
            l.info("Checking mem access of: %s --> %s" % (str(instruction),mem_access_str))
            mem_access_code = utils.compile_asm(mem_access_str)
            return mem_access_code, mem_access_str

        # I cannot check if edx is free since after this instruction there is an indirect call/jump
        # and I do not trust the cfg in this case
        # I use push/pop instead of move to RW data, because it is shorter
        # TODO check if it is faster
        mem_access_code, mem_access_str = compile_mem_access(instruction)
        new_code = '''
        push edx
        %s
        mov dl, BYTE [edx]
        pop edx
        ''' % utils.bytes_to_asm(mem_access_code, comment=mem_access_str)
        # possible tester:
        # nc = utils.decompile(compile_mem_access(utils.decompile(utils.compile_asm("call DWORD [edx+0x11332244+ecx*4]"))[0])[0])[0]; nc.mnemonic+" "+nc.op_str

        # TODO should we forbids other stuff?
        # e.g., jumps to stack, jump to ret, jump to unaligned, ...
        return InsertCodePatch(int(instruction.address),new_code,name="indirect_cfi_for_%08x"%instruction.address)

    def get_patches(self):
        patches = []
        patches.extend(self.get_common_patches())
        cfg = self.patcher.cfg

        sci = []
        for function in cfg.functions.values():
            for bb in function.blocks:
                for ci in bb.capstone.insns:
                    if ci.group(capstone.x86_const.X86_GRP_CALL) or ci.group(capstone.x86_const.X86_GRP_JUMP):
                        if len(ci.operands) != 1:
                            l.warning("Unexpected operand size for CALL/JUMP: %s" % str(ci))
                        else:
                            op = ci.operands[0]
                            if op.type != capstone.x86_const.X86_OP_IMM:
                                sci.append(ci)

        for instruction in sci:
            l.info("Found indirect CALL/JUMP: %s" % str(instruction))
            cj_type = self.classify_cj(instruction)
            if cj_type == "standard":
                try:
                    new_patch = self.handle_standard_cj(instruction)
                except utils.NasmException:
                    l.warning("NASM exception while compiling mem_access for %s" % instruction)
                    continue
            patches.append(new_patch)

        return patches
