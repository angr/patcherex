import logging
from ..allocation_managers.allocation_manager import MemoryFlag

logger = logging.getLogger(__name__)


class Utils:
    def __init__(self, p, binary_path):
        self.p = p
        self.binary_path = binary_path

    def insert_trampoline_code(self, addr, instrs, force_insert=False, detour_pos=-1):
        logger.debug(f"Inserting trampoline code at {hex(addr)}: {instrs}")
        assert force_insert or self.is_valid_insert_point(
            addr
        ), f"Cannot insert instruction at {hex(addr)}"
        trempoline_instrs_with_jump_back = (
            instrs
            + "\n"
            + self.get_instrs_to_be_moved(addr)
            + "\n"
            + self.p.target.JMP_ASM.format(dst=hex(addr + self.p.target.JMP_SIZE))
        )
        trempoline_size = (
            len(
                self.p.assembler.assemble(
                    trempoline_instrs_with_jump_back,
                    addr,  # TODO: we don't really need this addr, but better than 0x0 because 0x0 is too far away from the code
                    is_thumb=self.p.binary_analyzer.is_thumb(addr),
                )
            )
            + 4  # TODO: some time actual size is larger, but we need a better way to calculate it
        )
        if detour_pos == -1:
            trampoline_block = self.p.allocation_manager.allocate(
                trempoline_size, align=0x4, flag=MemoryFlag.RX
            )  # TODO: get alignment from arch info
            logger.debug(f"Allocated trampoline block: {trampoline_block}")
            mem_addr = trampoline_block.mem_addr
            file_addr = trampoline_block.file_addr
        else:
            mem_addr = detour_pos
            file_addr = self.p.binary_analyzer.mem_addr_to_file_offset(mem_addr)
        self.p.sypy_info["patcherex_added_functions"].append(hex(mem_addr))
        trempoline_bytes = self.p.assembler.assemble(
            trempoline_instrs_with_jump_back,
            mem_addr,
            is_thumb=self.p.binary_analyzer.is_thumb(addr),
        )
        self.p.binfmt_tool.update_binary_content(file_addr, trempoline_bytes)
        jmp_to_trempoline = self.p.assembler.assemble(
            self.p.target.JMP_ASM.format(dst=hex(mem_addr)),
            addr,
            is_thumb=self.p.binary_analyzer.is_thumb(addr),
        )
        self.p.binfmt_tool.update_binary_content(
            self.p.binary_analyzer.mem_addr_to_file_offset(addr), jmp_to_trempoline
        )

    def get_instrs_to_be_moved(self, addr):
        basic_block = self.p.binary_analyzer.get_basic_block(addr)
        idx = basic_block["instruction_addrs"].index(addr)
        end = addr + self.p.target.JMP_SIZE
        instrs = b""
        for insn_addr in basic_block["instruction_addrs"][idx:]:
            if end <= insn_addr:
                # we have enough space to insert a jump
                disasms = self.p.disassembler.disassemble(
                    instrs, addr, is_thumb=self.p.binary_analyzer.is_thumb(addr)
                )
                disasm_str = "\n".join(
                    [self.p.disassembler.to_asm_string(d) for d in disasms]
                )
                return disasm_str
            if not self.is_movable_instruction(insn_addr):
                logger.error(f"Instruction at {hex(insn_addr)} is not movable")
                # we cannot insert a jump here
                return None
            instrs += self.p.binary_analyzer.get_instr_bytes_at(insn_addr)
        return None

    def is_valid_insert_point(self, addr):
        return self.get_instrs_to_be_moved(addr) is not None

    def is_movable_instruction(self, addr):
        is_thumb = self.p.binary_analyzer.is_thumb(addr)
        insn = self.p.binary_analyzer.get_instr_bytes_at(addr)
        asm = self.p.disassembler.disassemble(insn, addr, is_thumb=is_thumb)[0]
        asm = self.p.disassembler.to_asm_string(asm)
        for addr in [0x0, 0x7F00000, 0xFE000000]:
            if self.p.assembler.assemble(asm, addr, is_thumb=is_thumb) != insn:
                return False
        return True
