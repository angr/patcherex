from .compiler import Compiler
import logging

logger = logging.getLogger(__name__)


class ClangArm(Compiler):
    def __init__(self, p, clang_version=15, compiler_flags=[]):
        super().__init__(p)
        self._compiler = f"clang-{clang_version}"
        self._linker = f"ld.lld-{clang_version}"
        self._compiler_flags = compiler_flags

    def compile(
        self,
        code,
        base=0,
        symbols={},
        extra_compiler_flags=[],
        is_thumb=False,
        **kwargs,
    ):
        if is_thumb:
            extra_compiler_flags += ["-mthumb"]
        else:
            extra_compiler_flags += ["-mno-thumb"]
        compiled = super().compile(
            code,
            base=base,
            symbols=symbols,
            extra_compiler_flags=extra_compiler_flags,
            **kwargs,
        )

        # FIXME: damn this is too hacky
        _symbols = {}
        _symbols.update(self.p.symbols)
        _symbols.update(self.p.binary_analyzer.get_all_symbols())
        _symbols.update(symbols)
        symbols = _symbols
        disasm = self.p.disassembler.disassemble(compiled, base=base, is_thumb=is_thumb)
        reassembled = b""
        for instr in disasm:
            if (
                is_thumb
                and instr["mnemonic"] == "bl"
                and int(instr["op_str"][1:], 0) in symbols.values()
            ):
                disasm_str = (
                    self.p.disassembler.to_asm_string(instr).replace("bl", "blx") + "\n"
                )
                reassembled += self.p.assembler.assemble(
                    disasm_str, base=instr["address"], is_thumb=is_thumb
                )
            elif (
                is_thumb
                and instr["mnemonic"] == "blx"
                and (int(instr["op_str"][1:], 0) + 1) in symbols.values()
            ):
                disasm_str = (
                    self.p.disassembler.to_asm_string(instr).replace("blx", "bl") + "\n"
                )
                reassembled += self.p.assembler.assemble(
                    disasm_str, base=instr["address"], is_thumb=is_thumb
                )
            elif (
                not is_thumb
                and instr["mnemonic"] == "bl"
                and (int(instr["op_str"][1:], 0) + 1) in symbols.values()
            ):
                disasm_str = (
                    self.p.disassembler.to_asm_string(instr).replace("bl", "blx") + "\n"
                )
                reassembled += self.p.assembler.assemble(
                    disasm_str, base=instr["address"], is_thumb=is_thumb
                )
            elif (
                not is_thumb
                and instr["mnemonic"] == "blx"
                and int(instr["op_str"][1:], 0) in symbols.values()
            ):
                disasm_str = (
                    self.p.disassembler.to_asm_string(instr).replace("blx", "bl") + "\n"
                )
                reassembled += self.p.assembler.assemble(
                    disasm_str, base=instr["address"], is_thumb=is_thumb
                )
            else:
                reassembled += compiled[
                    instr["address"] - base : instr["address"] - base + instr["size"]
                ]
        compiled = reassembled + compiled[len(reassembled) :]
        if len(compiled) % 2 != 0:
            compiled += b"\x00"
        return compiled
