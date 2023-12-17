from .target import Target
from ..components.assemblers.keystone_sparc import KeystoneSparc, keystone
from ..components.compilers.bcc import Bcc as BccCompiler
from ..components.assemblers.bcc import Bcc as BccAssembler
from ..components.disassemblers.capstone import Capstone, capstone
from ..components.binfmt_tools.elf import ELF
from ..components.binary_analyzers.angr import Angr
from ..components.utils.utils import Utils
from ..components.allocation_managers.allocation_manager import *

import logging

logger = logging.getLogger(__name__)


class CustomElf(ELF):
    def _init_memory_analysis(self):
        # remove all non-RWX segments
        self._segments = [s for s in self._segments if s["p_flags"] & 0b111 == 0b111]
        block = MappedBlock(
            self._segments[0]["p_offset"],
            self._segments[0]["p_vaddr"],
            self._segments[0]["p_memsz"],
            is_free=False,
            flag=MemoryFlag.RWX,
        )
        self.p.allocation_manager.add_block(block)

        unused_funcs = self.p.binary_analyzer.get_unused_funcs()

        for func in unused_funcs:
            file_offset = self.p.binary_analyzer.mem_addr_to_file_offset(func["addr"])
            block = MappedBlock(
                file_offset,
                func["addr"],
                func["size"],
                is_free=True,
                flag=MemoryFlag.RWX,
            )
            self.p.allocation_manager.add_block(block)


class ElfLeon3Bare(Target):
    NOP_BYTES = b"\x01\x00\x00\x00"
    NOP_SIZE = 4
    JMP_ASM = "b {dst}\nnop"  # nop due to delay slot
    JMP_SIZE = 8

    @staticmethod
    def detect_target(binary_path):
        with open(binary_path, "rb") as f:
            magic = f.read(0x14)
            # NOTE: probably should not default sparc to this target, but it's fine for now
            if magic.startswith(b"\x7fELF") and magic.startswith(
                b"\x00\x02", 0x12
            ):  # EM_SPARC
                return True
        return False

    def get_assembler(self, assembler):
        assembler = assembler or "keystone"
        if assembler == "keystone":
            return KeystoneSparc(
                self.p,
                keystone.KS_ARCH_SPARC,
                keystone.KS_MODE_SPARC32 + keystone.KS_MODE_BIG_ENDIAN,
            )
        elif assembler == "bcc":
            return BccAssembler(self.p)
        raise NotImplementedError()

    def get_allocation_manager(self, allocation_manager):
        allocation_manager = allocation_manager or "default"
        if allocation_manager == "default":
            return AllocationManager(self.p)
        raise NotImplementedError()

    def get_compiler(self, compiler):
        compiler = compiler or "bcc"
        if compiler == "bcc":
            return BccCompiler(self.p)
        raise NotImplementedError()

    def get_disassembler(self, disassembler):
        disassembler = disassembler or "capstone"
        if disassembler == "capstone":
            return Capstone(capstone.CS_ARCH_SPARC, capstone.CS_MODE_BIG_ENDIAN)
        raise NotImplementedError()

    def get_binfmt_tool(self, binfmt_tool):
        binfmt_tool = binfmt_tool or "custom"
        if binfmt_tool == "custom":
            return CustomElf(self.p, self.binary_path)
        raise NotImplementedError()

    def get_binary_analyzer(self, binary_analyzer):
        binary_analyzer = binary_analyzer or "angr"
        if binary_analyzer == "angr":
            return Angr(self.binary_path)
        raise NotImplementedError()

    def get_utils(self, utils):
        utils = utils or "default"
        if utils == "default":
            return Utils(self.p, self.binary_path)
        raise NotImplementedError()
