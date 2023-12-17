from .patch import Patch
from ..components.allocation_managers.allocation_manager import MemoryFlag
import logging

logger = logging.getLogger(__name__)


class ModifyInstructionPatch(Patch):
    def __init__(self, addr, instr) -> None:
        self.addr = addr
        self.instr = instr

    def apply(self, p):
        # TODO: check size, insert jump if necessary
        asm_bytes = p.assembler.assemble(
            self.instr, self.addr, is_thumb=p.binary_analyzer.is_thumb(self.addr)
        )
        offset = p.binary_analyzer.mem_addr_to_file_offset(self.addr)
        p.binfmt_tool.update_binary_content(offset, asm_bytes)


class InsertInstructionPatch(Patch):
    def __init__(
        self, addr_or_name, instr, force_insert=False, detour_pos=-1, is_thumb=False
    ) -> None:
        self.addr = None
        self.name = None
        if isinstance(addr_or_name, int):
            self.addr = addr_or_name
        elif isinstance(addr_or_name, str):
            self.name = addr_or_name
        self.instr = instr
        self.force_insert = force_insert
        self.detour_pos = detour_pos
        self.is_thumb = is_thumb

    def apply(self, p):
        if self.addr:
            p.utils.insert_trampoline_code(
                self.addr,
                self.instr,
                force_insert=self.force_insert,
                detour_pos=self.detour_pos,
            )
        elif self.name:
            assembled_size = len(
                p.assembler.assemble(self.instr, is_thumb=self.is_thumb)
            )
            if self.detour_pos == -1:
                block = p.allocation_manager.allocate(
                    assembled_size, align=0x4, flag=MemoryFlag.RX
                )  # TODO: get alignment from arch info
                p.symbols[self.name] = block.mem_addr
                p.binfmt_tool.update_binary_content(
                    block.file_addr,
                    p.assembler.assemble(
                        self.instr, block.mem_addr, is_thumb=self.is_thumb
                    ),
                )
            else:
                p.symbols[self.name] = self.detour_pos
                p.binfmt_tool.update_binary_content(
                    self.detour_pos,
                    p.assembler.assemble(
                        self.instr, self.detour_pos, is_thumb=self.is_thumb
                    ),
                )


class RemoveInstructionPatch(Patch):
    def __init__(self, addr, num_instr=None, num_bytes=None) -> None:
        self.addr = addr
        self.num_instr = num_instr
        self.num_bytes = num_bytes
        if self.num_instr is None and self.num_bytes is None:
            self.num_instr = 1

    def apply(self, p):
        if self.num_bytes is None:
            raise NotImplementedError()
        if self.num_bytes and self.num_bytes % p.target.NOP_SIZE != 0:
            raise Exception(
                f"Cannot remove {self.num_bytes} bytes, must be a multiple of {p.target.NOP_SIZE}"
            )
        num_nops = self.num_bytes // p.target.NOP_SIZE
        offset = p.binary_analyzer.mem_addr_to_file_offset(self.addr)
        p.binfmt_tool.update_binary_content(offset, p.target.NOP_BYTES * num_nops)
