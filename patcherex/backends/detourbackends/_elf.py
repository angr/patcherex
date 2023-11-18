import bisect
import json
import logging
import os
import re
from collections import OrderedDict
from enum import IntFlag

from elftools.construct.lib import Container
from elftools.elf.constants import P_FLAGS, SH_FLAGS
from elftools.elf.elffile import ELFFile
from patcherex import utils
from patcherex.backend import Backend
from patcherex.backends.detourbackends._utils import (DetourException,
                                                      InvalidVAddrException,
                                                      MissingBlockException,
                                                      RejectingDict)
from patcherex.utils import (CLangException, ObjcopyException,
                             UndefinedSymbolException)

l = logging.getLogger("patcherex.backends.DetourBackend")

class Perm(IntFlag):
    UNDEF = 8
    R = 4
    W = 2
    E = 1
    RW = R | W
    RE = R | E
    RWE = R | W | E


class DetourBackendElf(Backend):
    # how do we want to design this to track relocations in the blocks...
    def __init__(self, filename, base_address=None, try_reuse_unused_space=False, replace_note_segment=False, try_without_cfg=False, cfg=None):
        super().__init__(filename, project_options={"main_opts": {"base_addr": base_address}})

        self.elf = ELFFile(open(filename, "rb"))
        self.modded_segments = self.dump_segments() # dump_segments also set self.structs

        self.try_without_cfg = try_without_cfg
        if self.try_without_cfg:
            self.cfg = None
        elif cfg is not None:
            # Use pre-generated CFG provided
            self.cfg = cfg
        else:
            # Generate CFG of binary
            self.cfg = self._generate_cfg()

        self.ordered_nodes = self._get_ordered_nodes(self.cfg) if not self.try_without_cfg else None

        # header stuff
        self.ncontent = self.ocontent
        self.segments = None
        self.original_header_end = None

        # tag to track if already patched
        self.patched_tag = b"SHELLPHISH\x00"  # should not be longer than 0x20

        self.name_map = RejectingDict()

        # where to put the segments in memory
        self.added_code_segment = 0x06000000
        self.added_data_segment = 0x07000000
        current_hdr = self.structs.Elf_Ehdr.parse(self.ncontent)
        self.single_segment_header_size = current_hdr["e_phentsize"]
        assert self.single_segment_header_size >= self.structs.Elf_Phdr.sizeof()
        # we may need up to 3 additional segments (patch code, patch data, phdr)
        self.additional_headers_size = 3 * self.single_segment_header_size

        self.added_code = b""
        self.added_data = b""
        self.added_code_file_start = None
        self.added_data_file_start = None
        self.added_patches = []
        self.added_rwdata_len = 0
        self.added_rwinitdata_len = 0
        self.phdr_segment = None
        self.to_init_data = b""
        self.max_convertible_address = (1 << (32 if self.structs.elfclass == 32 else 48)) - 1

        self.saved_states = OrderedDict()
        # not all the touched bytes are bad, they are only a serious problem in case of InsertCodePatch
        self.touched_bytes = set()

        self.name_map["ADDED_DATA_START"] = (len(self.ncontent) % 0x1000) + self.added_data_segment
        self.first_load = None
        self.phdr_start = None
        self.replace_note_segment = replace_note_segment
        self.try_reuse_unused_space = try_reuse_unused_space
        self.free_space = []
        self.loaded_free_space = []
        self.find_space()

        self.patch_info = {"regions": {"original": [], "patched": []}, "new_segments": [], "function_starts": {"original": [], "patched": []}}

    def find_space(self):
        # FUTURE: we might want to split LOAD segment for finer granularity of permission control
        # We may generate new free space, when we have jumping ReplaceFunctionPatch, it creates lots of NOPs

        # only consider load_segments & SHF_ALLOC sections
        l.info("Finding available space for patches")
        load_segments = [segment for segment in self.elf.iter_segments() if segment["p_type"] == "PT_LOAD"]
        sorted_segments = sorted(load_segments, key=lambda x: x['p_offset'])
        alloc_sections = [section for section in self.elf.iter_sections() if section['sh_flags'] & SH_FLAGS.SHF_ALLOC]
        sorted_sections = sorted(alloc_sections, key=lambda x: (x['sh_offset'], x['sh_size']))

        # Find Space Between Sections
        for prev_sec, next_sec in zip(sorted_sections, sorted_sections[1:]):
            # The Space must be within the same segment
            for segment in sorted_segments:
                if segment.section_in_segment(prev_sec) and segment.section_in_segment(next_sec):
                    if next_sec['sh_offset'] > (prev_sec['sh_offset'] + prev_sec['sh_size']):
                        self.free_space.append({
                            "type": "loaded",
                            "file_start": prev_sec['sh_offset'] + prev_sec['sh_size'],
                            "file_size": next_sec['sh_offset'] - (prev_sec['sh_offset'] + prev_sec['sh_size']),
                            "mem_start": prev_sec['sh_addr'] + prev_sec['sh_size'],
                            "mem_size": next_sec['sh_addr'] - (prev_sec['sh_addr'] + prev_sec['sh_size']),
                            "perm": Perm.RW if segment['p_flags'] & P_FLAGS.PF_W else Perm.RE
                        })
                

        # Find Space Between Segments
        for prev, next in zip(sorted_segments, sorted_segments[1:]):
            if next['p_offset'] > (prev['p_offset'] + prev['p_filesz']):
                self.free_space.append({
                    "type": "file",
                    "file_start": prev['p_offset'] + prev['p_filesz'],
                    "file_size": next['p_offset'] - (prev['p_offset'] + prev['p_filesz']),
                    "perm": Perm.UNDEF
                })
            if next['p_vaddr'] > (prev['p_vaddr'] + prev['p_memsz']):
                self.free_space.append({
                    "type": "memory",
                    "mem_start": prev['p_vaddr'] + prev['p_memsz'],
                    "mem_size": next['p_vaddr'] - (prev['p_vaddr'] + prev['p_memsz']),
                    "perm": Perm.UNDEF
                })

        self.free_space.append({
            "type": "file",
            "file_start": sorted_segments[-1]['p_offset'] + sorted_segments[-1]['p_filesz'],
            "file_size": -1,
            "perm": Perm.UNDEF
        })
        self.free_space.append({
            "type": "memory",
            "mem_start": sorted_segments[-1]['p_vaddr'] + sorted_segments[-1]['p_memsz'],
            "mem_size": -1,
            "perm": Perm.UNDEF
        })
        self.loaded_free_space = sorted([space for space in self.free_space if space['type'] == "loaded"], key=lambda x: -x['file_size'])
        l.debug("List of all avilable spaces: %s", self.loaded_free_space)

        if self.try_reuse_unused_space:
            for space in self.loaded_free_space:
                if space['perm'] == Perm.RW:
                    self.reuse_data = space
                    l.info("Found RW space to reuse: %s", self.reuse_data)
                    break
            else:
                raise Exception("No RW space to reuse")
            for space in self.loaded_free_space:
                if space['perm'] == Perm.RE:
                    self.reuse_code = space
                    l.info("Found RE space to reuse: %s", self.reuse_code)
                    break
            else:
                raise Exception("No RE space to reuse")

    def setup_headers(self, segments):
        if self.try_reuse_unused_space:
            if len(self.added_code) > 0:
                if len(self.added_code) < self.reuse_code["file_size"]:
                    self.added_code_file_start = self.reuse_code["file_start"]
                    self.reuse_code["file_start"] += len(self.added_code)
                    self.reuse_code["file_size"] -= len(self.added_code)
                    l.info("Reusing space for code: 0x%x", self.added_code_file_start)
                else:
                    raise Exception("Not enough RE space to reuse")
            if len(self.added_data) > 0:
                if len(self.added_data) < self.reuse_data["file_size"]:
                    self.added_data_file_start = self.reuse_data["start"]
                    self.reuse_data["file_start"] += len(self.added_data)
                    self.reuse_data["file_size"] -= len(self.added_data)
                    l.info("Reusing space for data: 0x%x", self.added_data_file_start)
                else:
                    raise Exception("Not enough RW space to reuse")
            self.ncontent = utils.bytes_overwrite(self.ncontent, self.added_code, self.added_code_file_start)
            self.ncontent = utils.bytes_overwrite(self.ncontent, self.added_data, self.added_data_file_start)
        elif self.replace_note_segment:
            l.info("Replacing note segment to load segment")
            current_hdr = self.structs.Elf_Ehdr.parse(self.ncontent)
            note_segment_header_loc = current_hdr["e_phoff"]

            for segment in segments:
                if segment["p_type"] == "PT_NOTE":
                    segment = Container(**{ "p_type":   1,                                            "p_offset": self.added_data_file_start,
                                            "p_vaddr":  self.name_map["ADDED_DATA_START"],            "p_paddr":  self.name_map["ADDED_DATA_START"],
                                            "p_filesz": self.added_code_file_start - self.added_data_file_start + len(self.added_code),
                                            "p_memsz":  self.added_code_file_start - self.added_data_file_start + len(self.added_code),
                                            "p_flags":  0x7,                                          "p_align":  0x1000})
                    self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Phdr.build(segment), note_segment_header_loc)
                    break

                note_segment_header_loc += current_hdr["e_phentsize"]
        else:
            # copying original program headers (potentially modified by patches)
            # in the new place (at the  end of the file)
            l.info("Copying original program headers")
            load_segments_rounded = []
            for segment in segments:
                if segment["p_type"] == "PT_LOAD":
                    if self.first_load is None:
                        self.first_load = segment
                    load_segments_rounded.append((
                            # start of the segment, round down to multiple of 0x1000
                            (segment["p_vaddr"] - self.first_load["p_vaddr"]) - ((segment["p_vaddr"] - self.first_load["p_vaddr"]) % 0x1000),
                            # end of the segment, round up to multiple of 0x1000
                            int((segment["p_vaddr"] + segment["p_memsz"] - self.first_load["p_vaddr"] + 0x1000 - 1) / 0x1000) * 0x1000 ))

            for segment in segments:
                if segment["p_type"] == "PT_PHDR":
                    if self.phdr_segment is not None:
                        raise ValueError("Multiple PHDR segments!")
                    self.phdr_segment = segment

                    segment["p_filesz"] += self.additional_headers_size
                    segment["p_memsz"]  += self.additional_headers_size

                    phdr_size = max(segment["p_filesz"], segment["p_memsz"])

                    load_segments_rounded = sorted(load_segments_rounded, key=lambda x: x[0])

                    # combine overlapping load segments
                    while True:
                        new_load_segments_rounded = []
                        i = 0
                        while i < len(load_segments_rounded) - 1:
                            prev_seg = load_segments_rounded[i]
                            next_seg = load_segments_rounded[i + 1]
                            if prev_seg[1] > next_seg[0]: # two segments overlap
                                new_load_segments_rounded.append((prev_seg[0], next_seg[1])) # append combine of two segments
                                i += 2
                            else:
                                new_load_segments_rounded.append(prev_seg) # append segment without overlap
                                i += 1
                        if i == len(load_segments_rounded) - 1:
                            new_load_segments_rounded.append(load_segments_rounded[i]) # append last segment if without overlapping
                        if new_load_segments_rounded == load_segments_rounded: # if no overlap
                            break
                        load_segments_rounded = new_load_segments_rounded # combined segments, run again

                    for prev_seg, next_seg in zip(load_segments_rounded[:-1], load_segments_rounded[1:]):
                        potential_base = ((max(prev_seg[1], len(self.ncontent)) + 0xfff) & ~0xfff) # round up to 0x1000
                        if next_seg[0] - potential_base > phdr_size: # if there is space between segments, put phdr here
                            self.phdr_start = potential_base
                            break
                    else:
                        self.phdr_start = load_segments_rounded[-1][1] # otherwise put it after the last load segment

                    # try to map self.phdr_start to the next page-aligned position so that p_offset is the same as
                    # phdr_start if the base address of this binary is 0
                    # this is to workaround a weird issue in the dynamic linker of glibc
                    # Note taht self.phdr_start is page-aligned at this moment.
                    # and now we want to make sure p_vaddr (self.phdr_start) == p_offset (len(self.ncontent))
                    if self.phdr_start > len(self.ncontent):
                        # p_vaddr > p_offset: pad the file (p_offset)
                        self.ncontent = self.ncontent.ljust(self.phdr_start, b"\x00")
                    else:
                        # p_vaddr <= p_offset: pad the file (p_offset) to page size, and let p_vaddr = p_offset
                        self.ncontent += b"\x00" * (0x1000 - (len(self.ncontent) % 0x1000))
                        self.phdr_start = len(self.ncontent)

                    segment["p_offset"]  = self.phdr_start
                    segment["p_vaddr"]   = self.phdr_start + self.first_load["p_vaddr"]
                    segment["p_paddr"]   = self.phdr_start + self.first_load["p_vaddr"]

            if self.phdr_segment is not None:
                self.ncontent = self.ncontent.ljust(self.phdr_start, b"\x00")

            # change pointer to program headers to point at the end of the elf
            current_hdr = self.structs.Elf_Ehdr.parse(self.ncontent)
            old_phoff = current_hdr["e_phoff"]
            current_hdr["e_phoff"] = len(self.ncontent)
            self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Ehdr.build(current_hdr), 0)

            for segment in segments:
                if segment["p_type"] == "PT_PHDR":
                    segment = self.phdr_segment
                self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Phdr.build(segment))
            self.original_header_end = len(self.ncontent)

            # we overwrite the first original program header,
            # we do not need it anymore since we have moved original program headers at the bottom of the file
            self.ncontent = utils.bytes_overwrite(self.ncontent, self.patched_tag, old_phoff)

            # adding space for the additional headers
            # I add two of them, no matter what, if the data one will be used only in case of the fallback solution
            # Additionally added program headers have been already copied by the for loop above
            self.ncontent = self.ncontent.ljust(len(self.ncontent)+self.additional_headers_size, b"\x00")

    def dump_segments(self):
        with open(self.filename, "rb") as f:
            elf = ELFFile(f)
            self.structs = elf.structs
            segments = []
            for i in range(elf.num_segments()):
                seg = elf.get_segment(i)
                segments.append(seg.header)
        return segments

    def set_added_segment_headers(self):
        if self.replace_note_segment:
            return
        l.debug("added_data_file_start: %#x", self.added_data_file_start)
        added_segments = 0

        if self.phdr_segment is not None:
            # add a LOAD segment for the PHDR segment
            phdr_segment_header = Container(**{ "p_type":   1,                                      "p_offset": self.phdr_segment["p_offset"],
                                                "p_vaddr":  self.phdr_segment["p_vaddr"],           "p_paddr":  self.phdr_segment["p_paddr"],
                                                "p_filesz": self.phdr_segment["p_filesz"],          "p_memsz":  self.phdr_segment["p_memsz"],
                                                "p_flags":  0x4,                                    "p_align":  0x1000})
            self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Phdr.build(phdr_segment_header),
                                                    self.original_header_end + (2 * self.structs.Elf_Phdr.sizeof()))
            added_segments += 1
            self.patch_info["new_segments"].append({  "p_type":   1,                                      "p_offset": self.phdr_segment["p_offset"],
                                                        "p_vaddr":  self.phdr_segment["p_vaddr"],           "p_paddr":  self.phdr_segment["p_paddr"],
                                                        "p_filesz": self.phdr_segment["p_filesz"],          "p_memsz":  self.phdr_segment["p_memsz"],
                                                        "p_flags":  0x4,                                    "p_align":  0x1000})

        # add a LOAD segment for the DATA segment
        data_segment_header = Container(**{ "p_type":   1,                                      "p_offset": self.added_data_file_start,
                                            "p_vaddr":  self.name_map["ADDED_DATA_START"],      "p_paddr":  self.name_map["ADDED_DATA_START"],
                                            "p_filesz": len(self.added_data),                   "p_memsz":  len(self.added_data),
                                            "p_flags":  0x6,                                    "p_align":  0x1000})
        self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Phdr.build(data_segment_header),
                                                self.original_header_end + self.structs.Elf_Phdr.sizeof())
        added_segments += 1
        self.patch_info["new_segments"].append({  "p_type":   1,                                      "p_offset": self.added_data_file_start,
                                                    "p_vaddr":  self.name_map["ADDED_DATA_START"],      "p_paddr":  self.name_map["ADDED_DATA_START"],
                                                    "p_filesz": len(self.added_data),                   "p_memsz":  len(self.added_data),
                                                    "p_flags":  0x6,                                    "p_align":  0x1000})

        # add a LOAD segment for the CODE segment
        code_segment_header = Container(**{ "p_type":   1,                                      "p_offset": self.added_code_file_start,
                                            "p_vaddr":  self.name_map["ADDED_CODE_START"],      "p_paddr":  self.name_map["ADDED_CODE_START"],
                                            "p_filesz": len(self.added_code),                   "p_memsz":  len(self.added_code),
                                            "p_flags":  0x5,                                    "p_align":  0x1000})
        self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Phdr.build(code_segment_header),
                                            self.original_header_end)
        added_segments += 1
        self.patch_info["new_segments"].append({  "p_type":   1,                                      "p_offset": self.added_code_file_start,
                                                    "p_vaddr":  self.name_map["ADDED_CODE_START"],      "p_paddr":  self.name_map["ADDED_CODE_START"],
                                                    "p_filesz": len(self.added_code),                   "p_memsz":  len(self.added_code),
                                                    "p_flags":  0x5,                                    "p_align":  0x1000})

        current_hdr = self.structs.Elf_Ehdr.parse(self.ncontent)
        current_hdr["e_phnum"] += added_segments
        self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Ehdr.build(current_hdr), 0)

    def set_oep(self, new_oep):
        # set original entry point
        current_hdr = self.structs.Elf_Ehdr.parse(self.ncontent)
        current_hdr["e_entry"] = new_oep
        self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Ehdr.build(current_hdr), 0)

    def get_oep(self):
        # get original entry point
        current_hdr = self.structs.Elf_Ehdr.parse(self.ncontent)
        return current_hdr["e_entry"]

    # 3 inserting strategies
    # Jump out and jump back
    # move a single function out
    # extending all the functions, so all need to move

    def get_block_containing_inst(self, inst_addr):
        index = bisect.bisect_right(self.ordered_nodes, inst_addr) - 1
        node = self.cfg.model.get_any_node(self.ordered_nodes[index], is_syscall=False)
        if inst_addr in node.instruction_addrs:
            return node.addr
        else:
            raise MissingBlockException("Couldn't find a block containing address %#x" % inst_addr)

    def get_current_code_position(self):
        if self.try_reuse_unused_space:
            return self.name_map["ADDED_CODE_START"] + len(self.added_code)
        return self.name_map["ADDED_CODE_START"] + (len(self.ncontent) - self.added_code_file_start)

    def save_state(self,applied_patches):
        self.saved_states[tuple(applied_patches)] = (self.ncontent,set(self.touched_bytes),self.name_map.copy())

    def restore_state(self,applied_patches,removed_patches):
        # find longest sequence of patches for which we have a save state
        if len(removed_patches) > 0:
            cut = min([len(applied_patches)]+[applied_patches.index(p) for p in removed_patches if p in applied_patches])
            applied_patches = applied_patches[:cut]
        current_longest = self.saved_states[tuple(applied_patches)]
        self.ncontent, self.touched_bytes, self.name_map = current_longest
        #print "retrieving",applied_patches

        # cut dictionary to the current state
        todict = OrderedDict()
        for i, (k, v) in enumerate(self.saved_states.items()):
            if i > list(self.saved_states.keys()).index(tuple(applied_patches)):
                break
            todict[k]=v
        self.saved_states = todict

        return applied_patches

    def apply_patches(self, patches):
        raise NotImplementedError()

    @staticmethod
    def handle_remove_patch(patches,patch):
        # note the patches contains also "future" patches
        l.info("Handling removal of patch: %s", str(patch))
        cleaned_patches = [p for p in patches if p != patch]
        removed_patches = [patch]
        while True:
            removed = False
            for p in cleaned_patches:
                for d in p.dependencies:
                    if d not in cleaned_patches:
                        l.info("Removing depending patch: %s depends from %s", str(p), str(d))
                        removed = True
                        if p in cleaned_patches:
                            cleaned_patches.remove(p)
                        if p not in removed_patches:
                            removed_patches.append(p)
            if not removed:
                break
        return cleaned_patches,removed_patches

    def check_if_movable(self, instruction, is_thumb=False):
        raise NotImplementedError()

    def maddress_to_baddress(self, addr):
        if addr >= self.max_convertible_address:
            msg = "%08x higher than max_convertible_address (%08x)" % (addr,self.max_convertible_address)
            raise InvalidVAddrException(msg)
        baddr = self.project.loader.main_object.addr_to_offset(addr)
        if baddr is None:
            raise InvalidVAddrException(hex(addr))
        return baddr

    def get_memory_translation_list(self, address, size):
        # returns a list of address ranges that map to a given virtual address and size
        start = address
        end = address+size-1  # we will take the byte at end
        start_p = address & 0xfffffff000
        end_p = end & 0xfffffff000
        mlist = []

        if start_p == end_p:
            mlist.append((self.maddress_to_baddress(start), self.maddress_to_baddress(end)+1))
        else:
            first_page_baddress = self.maddress_to_baddress(start)
            mlist.append((first_page_baddress, (first_page_baddress & 0xfffffff000)+0x1000))
            nstart = (start & 0xfffffff000) + 0x1000
            while nstart != end_p:
                mlist.append((self.maddress_to_baddress(nstart), self.maddress_to_baddress(nstart)+0x1000))
                nstart += 0x1000
            mlist.append((self.maddress_to_baddress(nstart), self.maddress_to_baddress(end)+1))
        return mlist

    def patch_bin(self, address, new_content):
        # since the content could theoretically be split into different segments we will handle it here
        ndata_pos = 0

        for start, end in self.get_memory_translation_list(address, len(new_content)):
            ndata = new_content[ndata_pos:ndata_pos+(end-start)]
            self.ncontent = utils.bytes_overwrite(self.ncontent, ndata, start)
            ndata_pos += len(ndata)

    def read_mem_from_file(self, address, size):
        mem = b""
        for start, end in self.get_memory_translation_list(address, size):
            mem += self.ncontent[start : end]
        return mem

    def get_movable_instructions(self, block):
        raise NotImplementedError()

    def find_detour_pos(self, block, detour_size, patch_addr):
        # iterates through the instructions to find where the detour can be stored
        movable_instructions = self.get_movable_instructions(block)

        detour_attempts = range(-1*detour_size, 0+1)

        movable_bb_start = movable_instructions[0].address
        movable_bb_size = self.project.factory.block(block.addr, num_inst=len(movable_instructions)).size
        l.debug("movable_bb_size: %d", movable_bb_size)
        l.debug("movable bb instructions:\n%s", "\n".join([utils.instruction_to_str(i) for i in movable_instructions]))

        # find a spot for the detour
        detour_pos = None
        for pos in detour_attempts:
            detour_start = patch_addr + pos
            detour_end = detour_start + detour_size - 1
            if detour_start >= movable_bb_start and detour_end < (movable_bb_start + movable_bb_size):
                detour_pos = detour_start
                break
        if detour_pos is None:
            raise DetourException("No space in bb", hex(block.addr), hex(block.size),
                                  hex(movable_bb_start), hex(movable_bb_size))
        l.debug("detour fits at %s", hex(detour_pos))

        return detour_pos

    def compile_moved_injected_code(self, classified_instructions, patch_code, offset=0, is_thumb=False):
        raise NotImplementedError()

    def insert_detour(self, patch):
        raise NotImplementedError()

    def export_patch_info(self, filename):
        if filename is None:
            filename = self.filename + ".patchinfo.json"

        with open(filename, "w") as f:
            f.write(json.dumps(self.patch_info, indent=4))

    def get_final_content(self):
        return self.ncontent

    def save(self, filename=None):
        if filename is None:
            filename = self.filename + "_patched"

        final_content = self.get_final_content()
        with open(filename, "wb") as f:
            f.write(final_content)

        os.chmod(filename, 0o755)

    def disassemble(self, code, offset=0x0, is_thumb=False):
        if isinstance(code, str):
            code = bytes(map(ord, code))
        cs = self.project.arch.capstone_thumb if is_thumb else self.project.arch.capstone
        return list(cs.disasm(code, offset))

    def compile_c(self, code, optimization='-Oz', compiler_flags=""):
        # TODO symbol support in c code
        with utils.tempdir() as td:
            c_fname = os.path.join(td, "code.c")
            object_fname = os.path.join(td, "code.o")
            bin_fname = os.path.join(td, "code.bin")

            fp = open(c_fname, 'w')
            fp.write(code)
            fp.close()
            print(self.project.arch.triplet)
            res = utils.exec_cmd("clang -nostdlib -mno-sse -target %s -ffreestanding %s -o %s -c %s %s" \
                            % (self.project.arch.triplet, optimization, object_fname, c_fname, compiler_flags), shell=True)
            if res[2] != 0:
                print("CLang error:")
                print(res[0])
                print(res[1])
                fcontent = None
                with open(c_fname, 'r') as fp:
                    fcontent = fp.read()
                print("\n".join(["%02d\t%s"%(i+1,j) for i,j in enumerate(fcontent.split("\n"))]))
                raise CLangException
            res = utils.exec_cmd("objcopy -B i386 -O binary -j .text %s %s" % (object_fname, bin_fname), shell=True)
            if res[2] != 0:
                print("objcopy error:")
                print(res[0])
                print(res[1])
                raise ObjcopyException
            compiled = None
            with open(bin_fname, "rb") as fp:
                compiled = fp.read()
        return compiled

    @staticmethod
    def capstone_to_asm(instruction):
        return instruction.mnemonic + " " + instruction.op_str.replace('{','{{').replace('}','}}')

    def compile_asm(self, code, base=None, name_map=None, is_thumb=False):
        #print "=" * 10
        #print code
        #if base != None: print hex(base)
        #if name_map != None: print {k: hex(v) for k,v in name_map.iteritems()}
        try:
            if name_map is not None:
                name_map = {k:hex(v) for (k,v) in name_map.items()}
                code = code.format(**name_map)  # compile_asm
            else:
                code = re.subn(r'{.*?}', "0x41414141", code)[0]  # solve symbols
        except KeyError as e:
            raise UndefinedSymbolException(str(e)) from e

        try:
            ks = self.project.arch.keystone_thumb if is_thumb else self.project.arch.keystone
            encoding, _ = ks.asm(code, base)
        except self.project.arch.keystone.KsError as e:
            print("ERROR: %s" %e) #TODO raise some error

        return bytes(encoding)

    def _generate_cfg(self):
        """
        Generate a control flow graph, make sure necessary steps are performed, and return a CFG.

        :return: The CFG object
        :rtype: angr.analyses.CFG
        """

        # TODO
        # 1) ida-like cfg
        # 2) with some strategies we don't need the cfg, we should be able to apply those strategies even if the cfg fails
        l.info("Start generating CFG.")
        cfg = self.project.analyses.CFGFast(normalize=True, data_references=True, force_complete_scan=False)
        l.info("Finish generating CFG.")

        return cfg
