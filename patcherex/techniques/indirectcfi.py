import patcherex
import angr
import patcherex.utils as utils
import patcherex.cfg_utils as cfg_utils

import capstone
import logging
from patcherex.patches import *

l = logging.getLogger("patcherex.techniques.IndirectCFI")


class CfgError(Exception):
    pass


class IndirectCFI(object):
    global_counter = 0

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
            rvalue = instruction.op_str.lower().replace(" ptr ","").encode("ascii")
            # this is a weird case it should never happen
            # if it happens it is better not to do anything since we change esp in our patch
            # TODO handle this better
            if "esp" in rvalue:
                l.warning("found an indirect cj based on esp, it is better not to touch it")
                return None, None
            mem_access_str = "mov edx, %s" % rvalue
            l.info("Checking mem access of: %s --> %s" % (str(instruction),mem_access_str))
            mem_access_code = utils.compile_asm(mem_access_str)
            return mem_access_code, mem_access_str

        data_patch_name = "saved_first_target_%08x"%instruction.address
        # I cannot check if edx is free since after this instruction there is an indirect call/jump
        # and I do not trust the cfg in this case

        # three protections are applied
        # 1) the target must be mapped (readable) memory
        # 2) if a interact cj jumped to main/heap/stack the first time should jump to main/heap/stack also in the future
        # I think this is a fair assumptions
        # 3) no indirect call to pop (avoid some gadgets)

        # TODO instead of relying on "dynamic first usage" we can get this information from fuzzer
        # TODO to protect vtables we can check where the target is coming from (it should be from rodata)
        # however there are two problem: 1) identifying target's origin and 2) are we sure that it is always on rodata? 
        # TODO check more stuff than just no indirect call to pop
        mem_access_code, mem_access_str = compile_mem_access(instruction)
        if mem_access_code == None:
            return []
        target_resolver = utils.bytes_to_asm(mem_access_code, comment=mem_access_str)

        if instruction.mnemonic == u"call":
            gadget_protection = '''
            cmp dl,0x58
            jb _gadget_exit_%d
            cmp dl,0x5f
            jbe 0x8047332
            _gadget_exit_%d:
            ''' % (IndirectCFI.global_counter,IndirectCFI.global_counter)
        else:
            gadget_protection = ""

        # I assume that something that does not jump above 0x43 will never jump below and viceversa
        # this is true unless there are binaries bigger than 1GB or allocate bigger than 1GB
        new_code = '''
        push edx
        %s
        mov dl, BYTE [edx] ;less significant byte of target in dl (and check access)
        %s
        shr edx,24 ;most significant byte of target in dl
        mov dh, BYTE [{%s}]
        cmp dh,0
        jne _check_%d
            mov BYTE [{%s}], dl
            jmp _exit_%d

        _check_%d:
        cmp dl,0x43
        jb _cond2_%d
        cmp dh, 0x43
        jb _bad_%d ; < >
        jmp _exit_%d ; > >

        _cond2_%d:
        cmp dh, 0x43
        jb _exit_%d

        _bad_%d:
        jmp 0x8047333; > <
        _exit_%d: ; < <
        pop edx
        ''' % (target_resolver,gadget_protection,data_patch_name,IndirectCFI.global_counter,data_patch_name,\
                IndirectCFI.global_counter,IndirectCFI.global_counter,IndirectCFI.global_counter,IndirectCFI.global_counter, \
                IndirectCFI.global_counter,IndirectCFI.global_counter,IndirectCFI.global_counter,IndirectCFI.global_counter, \
                IndirectCFI.global_counter)
        # the memory regions should be correct with binaries up to 8MB of stack, 1GB of heap, about 930 MB of binary
        IndirectCFI.global_counter+=1

        code_patch = InsertCodePatch(int(instruction.address),new_code,name="indirect_cfi_for_%08x"%instruction.address)
        data_patch = AddRWDataPatch(1,"saved_first_target_%08x"%instruction.address)
        return [code_patch,data_patch]

    def get_patches(self):
        patches = []
        patches.extend(self.get_common_patches())
        cfg = self.patcher.cfg

        # the overlapping instruction issue seems to be fixed, at least partially
        # I am still using a dict and raising warnings in case of problems.
        sci = {}
        for function in cfg.functions.values():
            for bb in function.blocks:
                for ci in bb.capstone.insns:
                    if ci.group(capstone.x86_const.X86_GRP_CALL) or ci.group(capstone.x86_const.X86_GRP_JUMP):
                        if len(ci.operands) != 1:
                            l.warning("Unexpected operand size for CALL/JUMP: %s" % str(ci))
                        else:
                            op = ci.operands[0]
                            if op.type != capstone.x86_const.X86_OP_IMM:
                                if ci.address in sci:
                                    old_ci = sci[ci.address]
                                    tstr = "instruction at %08x (bb: %08x, function %08x) " % \
                                            (ci.address,bb.addr,function.addr)
                                    tstr += "previously found at bb: %08x in function: %08x" % \
                                            (old_ci[1].addr,old_ci[2].addr)
                                    l.warning(tstr)
                                else:
                                    sci[ci.address] = (ci,bb,function)

        for instruction,bb,function in sci.values():
            l.info("Found indirect CALL/JUMP: %s" % str(instruction))
            cj_type = self.classify_cj(instruction)
            if cj_type == "standard":
                try:
                    new_patches = self.handle_standard_cj(instruction)
                except utils.NasmException:
                    l.warning("NASM exception while compiling mem_access for %s" % instruction)
                    continue
            patches.extend(new_patches)

        return patches
