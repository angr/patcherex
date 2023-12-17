import capstone
from .disassembler import Disassembler


class CapstoneArm(Disassembler):
    def __init__(self, p):
        super().__init__(p)
        self.cs_arm = capstone.Cs(
            capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM + capstone.CS_MODE_LITTLE_ENDIAN
        )
        self.cs_thumb = capstone.Cs(
            capstone.CS_ARCH_ARM,
            capstone.CS_MODE_THUMB + capstone.CS_MODE_LITTLE_ENDIAN,
        )

    def disassemble(self, input, base=0, is_thumb=False, **kwargs):
        cs = self.cs_thumb if is_thumb else self.cs_arm
        cs_insns = cs.disasm(input, base)
        result = []
        for insn in cs_insns:
            result.append(
                {
                    "address": insn.address,
                    "size": insn.size,
                    "mnemonic": insn.mnemonic,
                    "op_str": insn.op_str,
                }
            )
        return result
