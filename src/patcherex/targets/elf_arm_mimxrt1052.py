from ..components.allocation_managers.allocation_manager import *
from .elf_arm_linux import ElfArmLinux
from ..components.binfmt_tools.elf import ELF
import copy


class CustomElf(ELF):
    def _init_memory_analysis(self):
        """
        Information from NXP's MCUXpresso IDE:
        Flash is code, RAM4 is data

        Type   | Name          | Alias | Location   | Size
        -------|---------------|-------|------------|----------
        Flash  | BOARD_FLASH   | Flash | 0x60000000 | 0x4000000
        RAM    | SRAM_DTC      | RAM   | 0x20000000 | 0x20000
        RAM    | SRAM_ITC      | RAM2  | 0x0        | 0x20000
        RAM    | SRAM_OC       | RAM3  | 0x20200000 | 0x20000
        RAM    | BOARD_SDRAM   | RAM4  | 0x80000000 | 0x1e00000
        RAM    | NCACHE_REGION | RAM5  | 0x81e00000 | 0x200000
        """
        # Extend LOAD (0x60000000) segment
        # Extend LOAD (0x80000000) segment
        for segment in self._segments:
            if segment["p_vaddr"] == 0x60000000:
                block = MappedBlock(
                    segment["p_offset"],
                    segment["p_vaddr"],
                    segment["p_memsz"],
                    is_free=False,
                    flag=MemoryFlag.RX,
                )
                self.p.allocation_manager.add_block(block)

                round_up = (segment["p_memsz"] + 0xFFFF) & ~0xFFFF
                block = MappedBlock(
                    segment["p_offset"] + segment["p_memsz"],
                    segment["p_vaddr"] + segment["p_memsz"],
                    round_up - segment["p_memsz"],
                    is_free=True,
                    flag=MemoryFlag.RX,
                )
                self.p.allocation_manager.add_block(block)
                self.p.allocation_manager.new_mapped_blocks.append(copy.deepcopy(block))
                # segment["p_memsz"] = round_up
                # segment["p_filesz"] = round_up
            if segment["p_vaddr"] == 0x80000000:
                block = MappedBlock(
                    segment["p_offset"],
                    segment["p_vaddr"],
                    segment["p_memsz"],
                    is_free=False,
                    flag=MemoryFlag.RW,
                )
                self.p.allocation_manager.add_block(block)

                round_up = (segment["p_memsz"] + 0xFFFF) & ~0xFFFF
                block = MappedBlock(
                    segment["p_offset"] + segment["p_memsz"],
                    segment["p_vaddr"] + segment["p_memsz"],
                    round_up - segment["p_memsz"],
                    is_free=True,
                    flag=MemoryFlag.RW,
                )
                self.p.allocation_manager.add_block(block)
                self.p.allocation_manager.new_mapped_blocks.append(copy.deepcopy(block))
                # segment["p_memsz"] = round_up
                # segment["p_filesz"] = round_up

    def finalize(self):
        # remove EXIDX segment
        self._segments = [s for s in self._segments if s["p_type"] != "PT_ARM_EXIDX"]
        super().finalize()

        # extend .text, .data section
        code_size, data_size = None, None
        for segment in self._segments:
            if segment["p_vaddr"] == 0x60000000:
                code_size = segment["p_memsz"]
            if segment["p_vaddr"] == 0x80000000:
                data_size = segment["p_memsz"]
        assert code_size is not None and data_size is not None
        for idx, section in enumerate(self._elf.iter_sections()):
            if section.name == ".text":
                section_header = section.header
                section_header["sh_size"] = (
                    code_size + 0x60000000 - section_header["sh_addr"]
                )
                self.p.binfmt_tool.update_binary_content(
                    self._elf.header["e_shoff"] + idx * self._elf.header["e_shentsize"],
                    self._elf.structs.Elf_Shdr.build(section_header),
                )
            if section.name == ".data":
                section_header = section.header
                section_header["sh_size"] = (
                    data_size + 0x80000000 - section_header["sh_addr"]
                )
                self.p.binfmt_tool.update_binary_content(
                    self._elf.header["e_shoff"] + idx * self._elf.header["e_shentsize"],
                    self._elf.structs.Elf_Shdr.build(section_header),
                )


class ElfArmMimxrt1052(ElfArmLinux):
    def get_binfmt_tool(self, binfmt_tool):
        binfmt_tool = binfmt_tool or "default"
        if binfmt_tool == "default":
            return ELF(self.p, self.binary_path)
        if binfmt_tool == "custom":
            return CustomElf(self.p, self.binary_path)
        raise NotImplementedError()
