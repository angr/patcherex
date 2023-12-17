from .binfmt_tool import BinFmtTool
from ..allocation_managers import *
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import P_FLAGS, SH_FLAGS
from elftools.construct.lib import Container

import logging, os

logger = logging.getLogger(__name__)


class ELF(BinFmtTool):
    def __init__(self, p, binary_path):
        super().__init__(p, binary_path)
        self._file = open(binary_path, "rb")
        self._elf = ELFFile(self._file)
        self._segments = [segment.header for segment in self._elf.iter_segments()]
        self.file_updates = []

        self.file_size = os.stat(self.binary_path).st_size
        with open(self.binary_path, "rb") as f:
            self.original_binary_content = f.read()
        self.updated_binary_content = self.original_binary_content
        self._init_memory_analysis()

    def __del__(self):
        self._file.close()

    def _find_space_between_sections(self):
        load_segments = sorted(
            (
                segment
                for segment in self._elf.iter_segments()
                if segment["p_type"] == "PT_LOAD"
            ),
            key=lambda x: x["p_offset"],
        )

        alloc_sections = sorted(
            (
                section
                for section in self._elf.iter_sections()
                if section["sh_flags"] & SH_FLAGS.SHF_ALLOC
            ),
            key=lambda x: (x["sh_offset"], x["sh_size"]),
        )

        # Spaces in LOAD segments AND between sections
        for segment in load_segments:
            for curr_sec, next_sec in zip(alloc_sections, alloc_sections[1:]):
                if segment.section_in_segment(curr_sec) and segment.section_in_segment(
                    next_sec
                ):
                    gap_start = curr_sec["sh_addr"] + curr_sec["sh_size"]
                    gap_size = next_sec["sh_addr"] - gap_start
                    if gap_size > 0:
                        flag = (
                            MemoryFlag.RW
                            if segment["p_flags"] & P_FLAGS.PF_W
                            else MemoryFlag.RX
                        )
                        block = MappedBlock(
                            curr_sec["sh_offset"] + curr_sec["sh_size"],
                            gap_start,
                            gap_size,
                            is_free=True,
                            flag=flag,
                        )
                        self.p.allocation_manager.add_block(block)
            for sec in alloc_sections:
                if segment.section_in_segment(sec):
                    flag = (
                        MemoryFlag.RW
                        if segment["p_flags"] & P_FLAGS.PF_W
                        else MemoryFlag.RX
                    )
                    block = MappedBlock(
                        sec["sh_offset"],
                        sec["sh_addr"],
                        sec["sh_size"],
                        is_free=False,
                        flag=flag,
                    )
                    self.p.allocation_manager.add_block(block)

        # of course also before and after the first and last section in a LOAD segment
        for segment in load_segments:
            first_sec = next(
                (
                    section
                    for section in alloc_sections
                    if segment.section_in_segment(section)
                ),
                None,
            )
            last_sec = next(
                (
                    section
                    for section in reversed(alloc_sections)
                    if segment.section_in_segment(section)
                ),
                None,
            )
            if first_sec:
                gap_start = segment["p_vaddr"]
                gap_size = first_sec["sh_addr"] - gap_start
                if (
                    gap_size > 0 and segment["p_offset"] != 0
                ):  # TODO: file addr 0 is kinda special, but does this check good enough?
                    flag = (
                        MemoryFlag.RW
                        if segment["p_flags"] & P_FLAGS.PF_W
                        else MemoryFlag.RX
                    )
                    block = MappedBlock(
                        segment["p_offset"],
                        gap_start,
                        gap_size,
                        is_free=True,
                        flag=flag,
                    )
                    self.p.allocation_manager.add_block(block)
            if last_sec:
                gap_start = last_sec["sh_addr"] + last_sec["sh_size"]
                gap_size = segment["p_vaddr"] + segment["p_memsz"] - gap_start
                if gap_size > 0:
                    flag = (
                        MemoryFlag.RW
                        if segment["p_flags"] & P_FLAGS.PF_W
                        else MemoryFlag.RX
                    )
                    block = MappedBlock(
                        last_sec["sh_offset"] + last_sec["sh_size"],
                        gap_start,
                        gap_size,
                        is_free=True,
                        flag=flag,
                    )
                    self.p.allocation_manager.add_block(block)

    def _find_space_between_segments(self):
        load_segments = sorted(
            (
                segment
                for segment in self._elf.iter_segments()
                if segment["p_type"] == "PT_LOAD"
            ),
            key=lambda x: x["p_offset"],
        )

        # Find Space Between Segments
        for curr, next in zip(load_segments, load_segments[1:]):
            if next["p_offset"] > (curr["p_offset"] + curr["p_filesz"]):
                block = FileBlock(
                    curr["p_offset"] + curr["p_filesz"],
                    next["p_offset"] - (curr["p_offset"] + curr["p_filesz"]),
                )
                self.p.allocation_manager.add_block(block)
            if next["p_vaddr"] > (curr["p_vaddr"] + curr["p_memsz"]):
                block = MemoryBlock(
                    curr["p_vaddr"] + curr["p_memsz"],
                    next["p_vaddr"] - (curr["p_vaddr"] + curr["p_memsz"]),
                )
                self.p.allocation_manager.add_block(block)

    def _add_end_of_file_block(self):
        load_segments = sorted(
            (
                segment
                for segment in self._elf.iter_segments()
                if segment["p_type"] == "PT_LOAD"
            ),
            key=lambda x: x["p_offset"],
        )

        block = FileBlock(self.file_size, -1)
        self.p.allocation_manager.add_block(block)

        addr = load_segments[-1]["p_vaddr"] + load_segments[-1]["p_memsz"]
        addr = (addr + 0xFFF) & ~0xFFF  # round up to 0x1000
        block = MemoryBlock(addr, -1)
        self.p.allocation_manager.add_block(block)

    def _init_memory_analysis(self):
        self._find_space_between_sections()
        self._find_space_between_segments()
        self._add_end_of_file_block()

        logger.debug(
            "_init_memory_analysis: "
            + "\n".join(map(str, self.p.allocation_manager.blocks.values()))
        )

        # # Is is possible to extend the existing segment?
        # for curr, next in zip(load_segments, load_segments[1:]):
        #     # mem
        #     mem_curr_end = curr['p_vaddr'] + curr['p_memsz']
        #     mem_curr_end_rounded = mem_curr_end + (curr['p_align'] - (mem_curr_end % curr['p_align'])) % curr['p_align']
        #     mem_next_start = next['p_vaddr']
        #     mem_max_extend_size = mem_curr_end_rounded - mem_curr_end
        #     if (mem_next_start - mem_curr_end_rounded) // curr['p_align'] > 0:
        #         mem_max_extend_size += (mem_next_start - mem_curr_end_rounded) // curr['p_align'] * curr['p_align']

        #     # file
        #     file_curr_end = curr['p_offset'] + curr['p_filesz']
        #     file_next_start = next['p_offset']
        #     max_extend_size = min(mem_max_extend_size, file_next_start - file_curr_end)

        #     if curr['p_flags'] & P_FLAGS.PF_R and curr['p_flags'] & P_FLAGS.PF_X:
        #         self.free_space['loaded'].append({
        #             "file_start": file_curr_end,
        #             "mem_start": mem_curr_end,
        #             "size": max_extend_size,
        #             "flag": MemoryFlag.RX,
        #             "callback": self._extend_segment
        #         })

    def finalize(self):
        self.p.allocation_manager.finalize()

        if len(self.p.allocation_manager.new_mapped_blocks) == 0:
            return

        load_segment_count = len(
            [segment for segment in self._segments if segment["p_type"] == "PT_LOAD"]
        )
        max_align = max([segment["p_align"] for segment in self._segments] + [0])

        # create new load segment for each new mapped block
        for block in self.p.allocation_manager.new_mapped_blocks:
            self._segments.append(
                Container(
                    **{
                        "p_type": "PT_LOAD",
                        "p_offset": block.file_addr,
                        "p_filesz": block.size,
                        "p_vaddr": block.mem_addr,
                        "p_paddr": block.mem_addr,
                        "p_memsz": block.size,
                        "p_flags": block.flag,
                        "p_align": max_align,  # TODO: what could be a good value for this?
                    }
                )
            )

        # sort segments by p_offset
        self._segments = sorted(self._segments, key=lambda x: x["p_offset"])

        # try to merge load segments if they are adjacent and have the same flags and same alignment
        # new size = sum of sizes of the two segments + gap between them
        while True:
            new_segments = []
            i = 0
            while i < len(self._segments) - 1:
                prev_seg = self._segments[i]
                next_seg = self._segments[i + 1]
                if (
                    prev_seg["p_offset"] + prev_seg["p_filesz"] == next_seg["p_offset"]
                    and prev_seg["p_vaddr"] + prev_seg["p_memsz"] == next_seg["p_vaddr"]
                    and prev_seg["p_flags"] == next_seg["p_flags"]
                    and prev_seg["p_align"] == next_seg["p_align"]
                ):
                    new_segments.append(
                        Container(
                            **{
                                "p_type": "PT_LOAD",
                                "p_offset": prev_seg["p_offset"],
                                "p_filesz": prev_seg["p_filesz"]
                                + next_seg["p_filesz"]
                                + (
                                    next_seg["p_offset"]
                                    - (prev_seg["p_offset"] + prev_seg["p_filesz"])
                                ),
                                "p_vaddr": prev_seg["p_vaddr"],
                                "p_paddr": prev_seg["p_paddr"],
                                "p_memsz": prev_seg["p_memsz"]
                                + next_seg["p_memsz"]
                                + (
                                    next_seg["p_vaddr"]
                                    - (prev_seg["p_vaddr"] + prev_seg["p_memsz"])
                                ),
                                "p_flags": prev_seg["p_flags"],
                                "p_align": prev_seg["p_align"],
                            }
                        )
                    )
                    i += 2
                else:
                    new_segments.append(prev_seg)
                    i += 1
            if i == len(self._segments) - 1:
                new_segments.append(self._segments[i])
            if new_segments == self._segments:
                break
            self._segments = new_segments

        if (
            len(
                [
                    segment
                    for segment in self._segments
                    if segment["p_type"] == "PT_LOAD"
                ]
            )
            <= load_segment_count
        ):
            # just rebuild segment headers, it will be in place so we don't care if there is PHDR or not
            new_phdr = b""
            for segment in self._segments:
                new_phdr += self._elf.structs.Elf_Phdr.build(segment)
            self.p.binfmt_tool.update_binary_content(
                self._elf.header["e_phoff"], new_phdr
            )
            ehdr = self._elf.header
            ehdr["e_phnum"] = len(self._segments)
            new_ehdr = self._elf.structs.Elf_Ehdr.build(ehdr)
            self.p.binfmt_tool.update_binary_content(0, new_ehdr)
        else:
            # create new load segment for phdr (values are undetermined yet)
            phdr_load_segment = Container(
                **{
                    "p_type": "PT_LOAD",
                    "p_offset": 0,
                    "p_filesz": 0,
                    "p_vaddr": 0,
                    "p_paddr": 0,
                    "p_memsz": 0,
                    "p_flags": 0x4,
                    "p_align": 0x1000,
                }
            )
            self._segments.append(phdr_load_segment)

            # magic
            load_segments_rounded = []
            first_load_segment = None
            for segment in self._segments:
                if segment["p_type"] == "PT_LOAD":
                    if first_load_segment is None:
                        first_load_segment = segment
                    load_segments_rounded.append(
                        (
                            # start of the segment, round down to multiple of 0x1000
                            (segment["p_vaddr"] - first_load_segment["p_vaddr"])
                            - (
                                (segment["p_vaddr"] - first_load_segment["p_vaddr"])
                                % 0x1000
                            ),
                            # end of the segment, round up to multiple of 0x1000
                            int(
                                (
                                    segment["p_vaddr"]
                                    + segment["p_memsz"]
                                    - first_load_segment["p_vaddr"]
                                    + 0x1000
                                    - 1
                                )
                                / 0x1000
                            )
                            * 0x1000,
                        )
                    )
            load_segments_rounded = sorted(load_segments_rounded, key=lambda x: x[0])

            # combine overlapping load segments
            while True:
                new_load_segments_rounded = []
                i = 0
                while i < len(load_segments_rounded) - 1:
                    prev_seg = load_segments_rounded[i]
                    next_seg = load_segments_rounded[i + 1]
                    if prev_seg[1] > next_seg[0]:  # two segments overlap
                        new_load_segments_rounded.append(
                            (prev_seg[0], next_seg[1])
                        )  # append combine of two segments
                        i += 2
                    else:
                        new_load_segments_rounded.append(
                            prev_seg
                        )  # append segment without overlap
                        i += 1
                if i == len(load_segments_rounded) - 1:
                    new_load_segments_rounded.append(
                        load_segments_rounded[i]
                    )  # append last segment if without overlapping
                if new_load_segments_rounded == load_segments_rounded:  # if no overlap
                    break
                load_segments_rounded = (
                    new_load_segments_rounded  # combined segments, run again
                )

            for prev_seg, next_seg in zip(
                load_segments_rounded[:-1], load_segments_rounded[1:]
            ):
                potential_base = (
                    max(prev_seg[1], self.p.binfmt_tool.file_size) + 0xFFF
                ) & ~0xFFF  # round up to 0x1000
                if next_seg[0] - potential_base > self._elf.header["e_phentsize"] * len(
                    self._segments
                ):  # if there is space between segments, put phdr here
                    phdr_start = potential_base
                    break
            else:
                phdr_start = load_segments_rounded[-1][
                    1
                ]  # otherwise put it after the last load segment
            # this is to workaround a weird issue in the dynamic linker of glibc
            # we want to make sure p_vaddr (phdr_start) == p_offset (len(ncontent))
            if phdr_start <= self.p.binfmt_tool.file_size:
                # p_vaddr <= p_offset: pad the file (p_offset) to page size, and let p_vaddr = p_offset
                self.p.binfmt_tool.file_size = (
                    self.p.binfmt_tool.file_size + 0xFFF
                ) & ~0xFFF  # round up to 0x1000
                phdr_start = self.p.binfmt_tool.file_size

            # update phdr segment and its corresponding load segment
            for segment in self._segments:
                if segment["p_type"] == "PT_PHDR" or segment == phdr_load_segment:
                    segment["p_filesz"] = self._elf.header["e_phentsize"] * len(
                        self._segments
                    )
                    segment["p_memsz"] = self._elf.header["e_phentsize"] * len(
                        self._segments
                    )
                    segment["p_offset"] = phdr_start
                    segment["p_vaddr"] = phdr_start + first_load_segment["p_vaddr"]
                    segment["p_paddr"] = phdr_start + first_load_segment["p_vaddr"]

            # create new phdr segment to be put in the new load segment above
            # make sure PHDR is the first segment
            self._segments = sorted(
                self._segments, key=lambda x: (x["p_type"] != "PT_PHDR", x["p_offset"])
            )
            new_phdr = b""
            for segment in self._segments:
                new_phdr += self._elf.structs.Elf_Phdr.build(segment)
            self.p.binfmt_tool.update_binary_content(phdr_start, new_phdr)

            ehdr = self._elf.header
            ehdr["e_phnum"] = len(self._segments)
            ehdr["e_phoff"] = phdr_start
            new_ehdr = self._elf.structs.Elf_Ehdr.build(ehdr)
            self.p.binfmt_tool.update_binary_content(0, new_ehdr)

    def save_binary(self, filename=None):
        self.updated_binary_content = self.updated_binary_content.ljust(
            self.file_size, b"\x00"
        )
        for update in self.file_updates:
            self.updated_binary_content = (
                self.updated_binary_content[: update["offset"]]
                + update["content"]
                + self.updated_binary_content[
                    update["offset"] + len(update["content"]) :
                ]
            )
        if filename is None:
            filename = f"{self.binary_path}.patched"
        with open(filename, "wb") as f:
            f.write(self.updated_binary_content)
        os.chmod(filename, 0o755)

    def update_binary_content(self, offset, new_content):
        logger.debug(
            f"Updating offset {hex(offset)} with content ({len(new_content)} bytes) {new_content}"
        )
        for update in self.file_updates:
            if offset >= update["offset"] and offset < update["offset"] + len(
                update["content"]
            ):
                raise ValueError(
                    f"Cannot update offset {hex(offset)} with content {new_content}, it overlaps with a previous update"
                )
        self.file_updates.append({"offset": offset, "content": new_content})
        if offset + len(new_content) > self.file_size:
            self.file_size = offset + len(new_content)

    def get_binary_content(self, offset, size):
        # check if it's in file_updates
        for update in self.file_updates:
            if offset >= update["offset"] and offset + size <= update["offset"] + len(
                update["content"]
            ):
                return update["content"][offset - update["offset"] :]
        # otherwise return from original binary
        return self.original_binary_content[offset : offset + size]

    def append_to_binary_content(self, new_content):
        self.file_updates.append({"offset": self.file_size, "content": new_content})
        self.file_size += len(new_content)
