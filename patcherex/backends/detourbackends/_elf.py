import bisect
import logging
import os
import re
from collections import OrderedDict, defaultdict

import capstone
import keystone
from elftools.construct.lib import Container
from elftools.elf.elffile import ELFFile

from patcherex.backend import Backend
from patcherex.backends.detourbackends._utils import *
from patcherex.patches import *
from patcherex.utils import CLangException, ObjcopyException, UndefinedSymbolException

l = logging.getLogger("patcherex.backends.DetourBackend")

class DetourBackendElf(Backend):
    # how do we want to design this to track relocations in the blocks...
    def __init__(self, filename, base_address=None):
        super(DetourBackendElf, self).__init__(filename, project_options={"main_opts": {"base_addr": base_address}})

        self.modded_segments = self.dump_segments() # dump_segments also set self.structs

        self.cfg = self._generate_cfg()
        self.ordered_nodes = self._get_ordered_nodes(self.cfg)

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

    def is_patched(self):
        return self.ncontent.startswith(self.patched_tag, self.structs.Elf_Ehdr.sizeof())

    def setup_headers(self, segments):
        #if self.is_patched():
        #    return

        # copying original program headers (potentially modified by patches)
        # in the new place (at the  end of the file)
        load_segments_rounded = []
        for segment in segments:
            if segment["p_type"] == "PT_LOAD":
                if self.first_load is None:
                    self.first_load = segment
                load_segments_rounded.append((
                        # start of the segment, round down to multiple of 0x1000
                        (segment["p_vaddr"] - self.first_load["p_vaddr"]) - ((segment["p_vaddr"] - self.first_load["p_vaddr"]) % 0x1000),
                        # end of the segment, round up to multiple of 0x1000
                        int((segment["p_vaddr"] + segment["p_memsz"] - self.first_load["p_vaddr"] + 0x1000 - 1) / 0x1000 * 0x1000) ))

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
                    potential_base = ((max(prev_seg[1], len(self.ncontent)) + 0xF) & ~0xF) # round up to 0x10
                    if next_seg[0] - potential_base > phdr_size: # if there is space between segments, put phdr here
                        self.phdr_start = potential_base
                        break
                else:
                    self.phdr_start = load_segments_rounded[-1][1] # otherwise put it after the last load segment

                segment["p_offset"]  = self.phdr_start
                segment["p_vaddr"]   = self.phdr_start + self.first_load["p_vaddr"]
                segment["p_paddr"]   = self.phdr_start + self.first_load["p_vaddr"]

        self.ncontent = self.ncontent.ljust(self.phdr_start, b"\x00")

        # change pointer to program headers to point at the end of the elf
        current_hdr = self.structs.Elf_Ehdr.parse(self.ncontent)
        old_phoff = current_hdr["e_phoff"]
        current_hdr["e_phoff"] = len(self.ncontent)
        self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Ehdr.build(current_hdr), 0)

        print("putting them at %#x" % self.phdr_start)
        print("current len: %#x" % len(self.ncontent))
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
        l.debug("added_data_file_start: %#x", self.added_data_file_start)
        added_segments = 0

        # add a LOAD segment for the PHDR segment
        phdr_segment_header = Container(**{ "p_type":   1,                                      "p_offset": self.phdr_segment["p_offset"],
                                            "p_vaddr":  self.phdr_segment["p_vaddr"],           "p_paddr":  self.phdr_segment["p_paddr"],
                                            "p_filesz": self.phdr_segment["p_filesz"],          "p_memsz":  self.phdr_segment["p_memsz"],
                                            "p_flags":  0x4,                                    "p_align":  0x1000})
        self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Phdr.build(phdr_segment_header),
                                                self.original_header_end + (2 * self.structs.Elf_Phdr.sizeof()))
        added_segments += 1

        # add a LOAD segment for the DATA segment
        data_segment_header = Container(**{ "p_type":   1,                                      "p_offset": self.added_data_file_start,
                                            "p_vaddr":  self.name_map["ADDED_DATA_START"],      "p_paddr":  self.name_map["ADDED_DATA_START"],
                                            "p_filesz": len(self.added_data),                   "p_memsz":  len(self.added_data),
                                            "p_flags":  0x6,                                    "p_align":  0x1000})
        self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Phdr.build(data_segment_header),
                                                self.original_header_end + self.structs.Elf_Phdr.sizeof())
        added_segments += 1

        # add a LOAD segment for the CODE segment
        code_segment_header = Container(**{ "p_type":   1,                                      "p_offset": self.added_code_file_start,
                                            "p_vaddr":  self.name_map["ADDED_CODE_START"],      "p_paddr":  self.name_map["ADDED_CODE_START"],
                                            "p_filesz": len(self.added_code),                   "p_memsz":  len(self.added_code),
                                            "p_flags":  0x5,                                    "p_align":  0x1000})
        self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Phdr.build(code_segment_header),
                                            self.original_header_end)
        added_segments += 1

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
                        l.info("Removing depending patch: "+str(p)+" depends from "+str(d))
                        removed = True
                        if p in cleaned_patches:
                            cleaned_patches.remove(p)
                        if p not in removed_patches:
                            removed_patches.append(p)
            if not removed:
                break
        return cleaned_patches,removed_patches

    def check_if_movable(self, instruction):
        raise NotImplementedError()

    def maddress_to_baddress(self, addr):
        if addr >= self.max_convertible_address:
            msg = "%08x higher than max_convertible_address (%08x)" % (addr,self.max_convertible_address)
            raise InvalidVAddrException(msg)
        baddr = self.project.loader.main_object.addr_to_offset(addr)
        if baddr is None:
            raise InvalidVAddrException(hex(addr))
        else:
            return baddr

    def get_memory_translation_list(self, address, size):
        # returns a list of address ranges that map to a given virtual address and size
        start = address
        end = address+size-1  # we will take the byte at end
        start_p = address & 0xfffffff000
        end_p = end & 0xfffffff000
        mlist = list()

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
        else:
            l.debug("detour fits at %s", hex(detour_pos))

        return detour_pos

    def compile_moved_injected_code(self, classified_instructions, patch_code, offset=0):
        raise NotImplementedError()

    def insert_detour(self, patch):
        raise NotImplementedError()

    def get_final_content(self):
        return self.ncontent

    def save(self, filename=None):
        if filename is None:
            filename = self.filename + "_patched"

        final_content = self.get_final_content()
        with open(filename, "wb") as f:
            f.write(final_content)

        os.chmod(filename, 0o755)

    def _generate_cfg(self):
        """
        Generate a control flow graph, make sure necessary steps are performed, and return a CFG.

        :return: The CFG object
        :rtype: angr.analyses.CFG
        """

        # TODO
        # 1) ida-like cfg
        # 2) with some strategies we don't need the cfg, we should be able to apply those strategies even if the cfg fails
        l.info("CFG start...")
        cfg = self.project.analyses.CFGFast(normalize=True, data_references=True, force_complete_scan=False)
        l.info("... CFG end")

        return cfg
