class Disassembler:
    def __init__(self, p):
        self.p = p

    def disassemble(self, input, base=0, **kwargs):
        raise NotImplementedError()

    def to_asm_string(self, insn):
        return "{} {}".format(insn["mnemonic"], insn["op_str"])
