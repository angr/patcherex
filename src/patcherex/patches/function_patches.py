from .patch import Patch
from ..components.allocation_managers.allocation_manager import MemoryFlag
import logging

logger = logging.getLogger(__name__)


class ModifyFunctionPatch(Patch):
    def __init__(self, addr_or_name, code, detour_pos=-1) -> None:
        self.code = code
        self.detour_pos = detour_pos
        self.addr_or_name = addr_or_name

    def apply(self, p):
        func = p.binary_analyzer.get_function(self.addr_or_name)
        compiled_size = len(
            p.compiler.compile(
                self.code, is_thumb=p.binary_analyzer.is_thumb(func["addr"])
            )
        )
        if compiled_size < func["size"]:
            mem_addr = func["addr"]
            file_addr = p.binary_analyzer.mem_addr_to_file_offset(mem_addr)
        else:
            # TODO: mark the function as free (exclude jump instr)
            if self.detour_pos == -1:
                block = p.allocation_manager.allocate(
                    compiled_size + 0x20, align=0x4, flag=MemoryFlag.RX
                )
                mem_addr = block.mem_addr
                file_addr = block.file_addr
            else:
                mem_addr = self.detour_pos
                file_addr = p.binary_analyzer.mem_addr_to_file_offset(mem_addr)
            jmp_instr = p.target.JMP_ASM.format(dst=hex(mem_addr))
            jmp_bytes = p.assembler.assemble(
                jmp_instr,
                func["addr"],
                is_thumb=p.binary_analyzer.is_thumb(func["addr"]),
            )
            p.binfmt_tool.update_binary_content(
                p.binary_analyzer.mem_addr_to_file_offset(func["addr"]),
                jmp_bytes,
            )
        p.binfmt_tool.update_binary_content(
            file_addr,
            p.compiler.compile(
                self.code, mem_addr, is_thumb=p.binary_analyzer.is_thumb(func["addr"])
            ),
        )


class InsertFunctionPatch(Patch):
    def __init__(self, addr_or_name, code, detour_pos=-1, is_thumb=False) -> None:
        self.addr = None
        self.name = None
        if isinstance(addr_or_name, int):
            self.addr = addr_or_name
        elif isinstance(addr_or_name, str):
            self.name = addr_or_name
        self.code = code
        self.detour_pos = detour_pos
        self.is_thumb = is_thumb

    def apply(self, p):
        if self.addr:
            raise NotImplementedError()
        elif self.name:
            compiled_size = len(p.compiler.compile(self.code, is_thumb=self.is_thumb))
            if self.detour_pos == -1:
                block = p.allocation_manager.allocate(
                    compiled_size + 0x20, align=0x4, flag=MemoryFlag.RX
                )  # TODO: get alignment from arch info, TODO: adjust that 0x20 part
                mem_addr = block.mem_addr
                file_addr = block.file_addr
            else:
                mem_addr = self.detour_pos
                file_addr = p.binary_analyzer.mem_addr_to_file_offset(mem_addr)
            p.symbols[self.name] = mem_addr
            p.binfmt_tool.update_binary_content(
                file_addr,
                p.compiler.compile(self.code, mem_addr, is_thumb=self.is_thumb),
            )


class RemoveFunctionPatch(Patch):
    def __init__(self, parent=None) -> None:
        raise NotImplementedError()
