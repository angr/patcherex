
import os
import magic
import bisect
import logging
from collections import OrderedDict
from collections import defaultdict
from elftools.elf.elffile import ELFFile
from elftools.construct.lib import Container

from patcherex.patches import *

from ..backend import Backend
from .misc import ASM_ENTRY_POINT_PUSH_ENV, ASM_ENTRY_POINT_RESTORE_ENV

l = logging.getLogger("patcherex.backends.DetourBackend")


"""
symbols will look like {}
"""

# http://stackoverflow.com/questions/4999233/how-to-raise-error-if-duplicates-keys-in-dictionary
class RejectingDict(dict):
    def __setitem__(self, k, v):
        if k in self:
            raise ValueError("Key is already present: " + repr(k))
        else:
            return super(RejectingDict, self).__setitem__(k, v)

    def force_insert(self, k, v):
        return super(RejectingDict, self).__setitem__(k, v)


class PatchingException(Exception):
    pass

class MissingBlockException(PatchingException):
    pass

class DetourException(PatchingException):
    pass

class DoubleDetourException(PatchingException):
    pass

class InvalidVAddrException(PatchingException):
    pass

class IncompatiblePatchesException(PatchingException):
    pass

class DuplicateLabelsException(PatchingException):
    pass


class DetourBackend(Backend):
    # how do we want to design this to track relocations in the blocks...
    def __init__(self, filename, data_fallback=None, base_address=None, try_pdf_removal=True):
        if 'ELF' in magic.from_file(filename):
            super(DetourBackend, self).__init__(filename, project_options={"main_opts": {"custom_base_addr": base_address}})

            self.modded_segments = self.dump_segments()

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

            # we reused existing data segment if it is the last one in the file, otherwise we use the fallback solution
            if data_fallback == None:
                last_segment = self.modded_segments[-1]
                # TODO if not global rw data in the original program, this segment is not here
                # for now I assume it will be always here in reasonable programs
                if self.pflags_to_perms(last_segment["p_flags"]) == "RW":
                    #check that this is actually the last one in the file and no one is overlapping
                    # p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align
                    max_file_start = max([s[1] for s in self.modded_segments[:-1]])
                    max_file_end = max([s[1]+s[4] for s in self.modded_segments[:-1]])
                    if max_file_start < last_segment["p_offset"] and \
                       max_file_end <= last_segment["p_offset"] + last_segment["p_filesz"]:
                        l.info("Using standard method for RW memory. " \
                                "Existing RW segment: %08x -> %08x, Previous segment: %08x -> %08x" % \
                                (last_segment["p_offset"],
                                 last_segment["p_offset"] + last_segment["p_filesz"],
                                 max_file_start,
                                 max_file_end))
                        self.data_fallback = False
                    else:
                        l.info("Using fallback method for RW memory.")
                        self.data_fallback = True
                else:
                    l.info("Using fallback method for RW memory.")
                    self.data_fallback = True
            else:
                l.info("RW method forced to fallback? %s" % str(data_fallback))
                self.data_fallback = data_fallback

            if self.data_fallback:
                # this is the start in memory
                self.name_map["ADDED_DATA_START"] = (len(self.ncontent) % 0x1000) + self.added_data_segment
            else:
                last_segment = self.modded_segments[-1]
                # at the end of the file there is stuff which is supposely not loaded in memory
                # but it is present in the file (e.g., segment headers)
                # we need to account for that
                self.real_size_last_segment = len(self.ncontent) - last_segment["p_offset"]
                # this is the start in memory of RWData
                self.name_map["ADDED_DATA_START"] = last_segment["p_vaddr"] + last_segment["p_memsz"]
        else:
            super(DetourBackend, self).__init__(filename,try_pdf_removal)

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
            self.single_segment_header_size = 32
            # we may need up to 3 additional segments (1 for pdf removal 2 for patching)
            self.additional_headers_size = 3*self.single_segment_header_size

            self.added_code = b""
            self.added_data = b""
            self.added_code_file_start = None
            self.added_data_file_start = None
            self.added_patches = []
            self.added_rwdata_len = 0
            self.added_rwinitdata_len = 0
            self.to_init_data = b""
            self.max_convertible_address = 0xffffffff

            self.saved_states = OrderedDict()
            # not all the touched bytes are bad, they are only a serious problem in case of InsertCodePatch
            self.touched_bytes = set()
            self.modded_segments = self.dump_segments_cgc()

            if self.try_pdf_removal == True:
                l.info("Trying to remove the pdf from the binary")
                should_remove_pdf, pdf_start, pdf_length, check_instruction_addr, check_instruction_size  = self.find_pdf()
                if should_remove_pdf:
                    l.info("Removing the pdf from the binary")
                    self.remove_pdf(pdf_start, pdf_length, check_instruction_addr, check_instruction_size)
                    self.pdf_removed = True
                else:
                    l.warning("I cannot remove the pdf from this binary")
            else:
                l.info("Forced not to remove the pdf from the binary")

            # we reused existing data segment if it is the last one in the file, otherwise we use the fallback solution
            if data_fallback == None:
                last_segment = self.modded_segments[-1]
                # TODO if not global rw data in the original program, this segment is not here
                # for now I assume it will be always here in reasonable programs
                if self.pflags_to_perms(last_segment[-2]) == "RW":
                    #check that this is actually the last one in the file and no one is overlapping
                    # p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align
                    max_file_start = max([s[1] for s in self.modded_segments[:-1]])
                    max_file_end = max([s[1]+s[4] for s in self.modded_segments[:-1]])
                    if max_file_start < last_segment[1] and max_file_end <= last_segment[1]+last_segment[4]:
                        l.info("Using standard method for RW memory. " \
                                "Existing RW segment: %08x -> %08x, Previous segment: %08x -> %08x" % \
                                (last_segment[1],last_segment[1]+last_segment[4],max_file_start,max_file_end))
                        self.data_fallback = False
                    else:
                        l.info("Using fallback method for RW memory.")
                        self.data_fallback = True
                else:
                    l.info("Using fallback method for RW memory.")
                    self.data_fallback = True
            else:
                l.info("RW method forced to fallback? %s" % str(data_fallback))
                self.data_fallback = data_fallback

            if self.data_fallback:
                # this is the start in memory
                self.name_map["ADDED_DATA_START"] = (len(self.ncontent) % 0x1000) + self.added_data_segment
            else:
                last_segment = self.modded_segments[-1]
                self.real_size_last_segment = len(self.ncontent) - last_segment[1]
                self.name_map["ADDED_DATA_START"] = last_segment[2] + last_segment[5]


    def find_pdf(self):
        # 1) check if the pdf string is there and get the length
        pdf_string = b" byte CGC Extended Application follows. Each team participating in CGC must " \
                b"have submitted this completed agreement including the Team Information, the Liabi" \
                b"lity Waiver, the Site Visit Information Sheet and the Event Participation agreement.\n"
        pdf_string_pos = self.ocontent.find(pdf_string)
        if pdf_string_pos == -1:
            l.warning("pdf string not found")
            return False, None, None, None, None

        # 2) check for the pdf start
        pdf_beginning_str = [0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x33, 0x0a, 0x25, 0xc4, 0xe5, 0xf2,
                0xe5, 0xeb, 0xa7, 0xf3, 0xa0, 0xd0, 0xc4, 0xc6, 0x0a, 0x34, 0x20, 0x30, 0x20, 0x6f, 0x62,
                0x6a, 0x0a, 0x3c, 0x3c, 0x20, 0x2f, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x20, 0x35, 0x20,
                0x30, 0x20, 0x52, 0x20, 0x2f, 0x46, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x20, 0x2f, 0x46, 0x6c,
                0x61, 0x74, 0x65, 0x44, 0x65, 0x63, 0x6f, 0x64, 0x65, 0x20, 0x3e, 0x3e, 0x0a, 0x73, 0x74,
                0x72, 0x65, 0x61, 0x6d, 0x0a]
        pdf_beginning_str = bytes(pdf_beginning_str)
        pdf_beginning_pos = pdf_string_pos + len(pdf_string)
        if not self.ocontent[pdf_beginning_pos:pdf_beginning_pos+len(pdf_beginning_str)] == pdf_beginning_str:
            l.warning("pdf beginning not found")
            return False, None, None, None, None

        # 3) check for the pdf end (based on size)
        pdf_length_pos = self.ocontent[:pdf_string_pos-1].rfind(b" ")
        if pdf_length_pos == -1:
            l.warning("pdf length str not found")
            return False, None, None, None, None
        pdf_length_str = self.ocontent[pdf_length_pos:pdf_string_pos]
        try:
            pdf_length = int(pdf_length_str)
        except ValueError:
            l.warning("pdf length str not int")
            return False, None, None, None, None
        pdf_end = pdf_beginning_pos+pdf_length
        pdf_ending_str = b"\n%%EOF\n"
        if not self.ocontent[pdf_end-len(pdf_ending_str):pdf_end] == pdf_ending_str:
            l.warning("pdf ending not found")
            return False, None, None, None, None

        # 4) check for segment structure
        segments = self.modded_segments
        last_segment = segments[-1]
        if not self.pflags_to_perms(last_segment[-2]) == "RW":
            l.warning("last segment is not RW")
            return False, None, None, None, None
        max_file_start = max([s[1] for s in segments[:-1]])
        max_file_end = max([s[1]+s[4] for s in segments[:-1]])
        if not (max_file_start < last_segment[1] and max_file_end <= last_segment[1]+last_segment[4]):
            l.warning("overlapping segments")
            return False, None, None, None, None
        last_segment_file_start = last_segment[1]
        last_segment_file_end = last_segment[1]+last_segment[4]
        if not (last_segment_file_start < pdf_beginning_pos < last_segment_file_end):
            l.warning("pdf data start outside last segment")
            return False, None, None, None, None
        if not (last_segment_file_start < pdf_end <= last_segment_file_end):
            l.warning("pdf data end outside last segment")
            return False, None, None, None, None

        # this is not necessary true if yu have not empty .data
        #last_segment_expected_start = "The DECREE packages used in the creation of this challenge binary were:"
        #expected_str_end = last_segment_file_start+len(last_segment_expected_start)
        #if not self.ocontent[last_segment_file_start:expected_str_end] == last_segment_expected_start:
        #    l.warning("last segment not starting correctly")
        #    return False, None, None, None, None

        # 5) check for _start structure
        instructions = utils.disassemble(self.read_mem_from_file(self.get_oep(), 30), self.get_oep())
        i1, i2 = instructions[:2]
        if not (i1.mnemonic == u'call' and i1.mnemonic == u'call'):
            l.warning("unexpected instructions at entry points")
            return False, None, None, None, None
        try:
            checker_function_start = int(i1.op_str,16)
        except ValueError:
            l.warning("invald call address at entry point")
            return False, None, None, None, None

        # 6) check for pdf checker function structure
        # TODO we may want to avoid to be that precise, to handle slight modifications in libcgc
        # however, it would be significantly harder to detect how to remove the crc check
        expected_instructions = ["push","push","push","call","add","push","push","push","push","push",
                "push","add","pushfd","pop","and","push","popfd","push","pop","ret"]
        instructions = utils.disassemble(self.read_mem_from_file(checker_function_start, 0x30), checker_function_start)
        if not expected_instructions == [instruction.mnemonic for instruction in instructions]:
            l.warning("unexpected instructions in checker function")
            return False, None, None, None, None

        # 7) check for pdf acceses from cfg
        if False: # TODO, see issue: https://git.seclab.cs.ucsb.edu/cgc/patcherex/issues
            l.warning("unexpected acceses to the pdf")
            return False, None, None, None, None

        return True, pdf_beginning_pos, pdf_length, instructions[3].address, len(instructions[3].bytes)

    def remove_pdf(self, pdf_start, pdf_length, check_instruction_addr, check_instruction_size):
        l.info("pdf is between %08x and %08x" % (pdf_start,  pdf_start + pdf_length))
        last_segment = self.modded_segments[-1]
        cut_end = (pdf_start+pdf_length) & 0xfffff000
        cut_start = (pdf_start & 0xfffff000) + 0x1000
        cut_size = cut_end-cut_start
        cut_start_mem = cut_start - last_segment[1] + last_segment[2]
        cut_end_mem = cut_end - last_segment[1] + last_segment[2]
        l.info("cutting the pdf from: %08x to %08x" % (cut_start,cut_end))
        self.ncontent = self.ocontent[:cut_start]+self.ocontent[cut_end:]

        # remove pointer to section headers, so that it loads fine in gdb, ida, ...
        # later we can set this ti 0xffffffff for adversarial patching
        # e_shoff = 0xffffffff, e_shnum = 0x0000,  e_shstrndx = 0x0000
        self.ncontent = utils.bytes_overwrite(self.ncontent, struct.pack("<I", 0), 0x20)
        self.ncontent = utils.bytes_overwrite(self.ncontent, struct.pack("<H", 0), 0x30)
        self.ncontent = utils.bytes_overwrite(self.ncontent, struct.pack("<H", 0), 0x32)

        self.ncontent = utils.bytes_overwrite(self.ncontent, b"\x90" * check_instruction_size,
                                              self.maddress_to_baddress(check_instruction_addr))
        self.max_convertible_address = cut_start_mem

        header_size = 16 + 2*2 + 4*5 + 2*6
        buf = self.ocontent[0:header_size]
        (cgcef_type, cgcef_machine, cgcef_version, cgcef_entry, cgcef_phoff,
            cgcef_shoff, cgcef_flags, cgcef_ehsize, cgcef_phentsize, cgcef_phnum,
            cgcef_shentsize, cgcef_shnum, cgcef_shstrndx) = struct.unpack("<xxxxxxxxxxxxxxxxHHLLLLLHHHHHH", buf)
        phent_size = 8 * 4
        assert cgcef_phnum != 0
        assert cgcef_phentsize == phent_size

        segments = self.modded_segments
        last_segment = segments[-1]
        (p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align) = last_segment
        pre_cut_segment_size = cut_start_mem - p_vaddr
        # print map(hex,[cut_start,cut_end,cut_start_mem,pre_cut_segment_size, cut_start_mem, p_vaddr])
        pre_cut_segment = (p_type, p_offset, p_vaddr, p_paddr, pre_cut_segment_size, pre_cut_segment_size,
                p_flags, p_align)
        post_cut_segment = (p_type, p_offset + pre_cut_segment_size,
                p_vaddr + pre_cut_segment_size + cut_size, p_vaddr + pre_cut_segment_size + cut_size,
                p_filesz - cut_size - pre_cut_segment_size, p_memsz - cut_size - pre_cut_segment_size,
                p_flags, p_align)

        l.info("last segment changed from \n%s to \n%s\n%s",
                map(hex, last_segment), map(hex, pre_cut_segment), map(hex, post_cut_segment)
               )
        self.modded_segments = segments[:-1] + [pre_cut_segment,post_cut_segment]

    def is_patched(self):
        start = self.structs.Elf_Ehdr.sizeof()
        return self.ncontent[start:start + len(self.patched_tag)] == self.patched_tag

    def setup_headers(self, segments):
        #if self.is_patched():
        #    return

        # copying original program headers (potentially modified by patches and/or pdf removal)
        # in the new place (at the  end of the file)
        if 'ELF' not in magic.from_file(self.filename):
            # align size of the entire ELF
            self.ncontent = utils.pad_bytes(self.ncontent, 0x10)
            # change pointer to program headers to point at the end of the elf
            self.ncontent = utils.bytes_overwrite(self.ncontent, struct.pack("<I", len(self.ncontent)), 0x1C)

            # copying original program headers (potentially modified by patches and/or pdf removal)
            # in the new place (at the  end of the file)
            for segment in segments:
                self.ncontent = utils.bytes_overwrite(self.ncontent, struct.pack("<IIIIIIII", *segment))
            self.original_header_end = len(self.ncontent)

            # we overwrite the first original program header,
            # we do not need it anymore since we have moved original program headers at the bottom of the file
            self.ncontent = utils.bytes_overwrite(self.ncontent, self.patched_tag, 0x34)

            # adding space for the additional headers
            # I add two of them, no matter what, if the data one will be used only in case of the fallback solution
            # Additionally added program headers have been already copied by the for loop above
            self.ncontent = self.ncontent.ljust(len(self.ncontent)+self.additional_headers_size, b"\x00")

        else:
            # for ELF binaries
            self.first_load = None
            for segment in segments:
                if segment["p_type"] == "PT_LOAD" and self.first_load is None:
                    self.first_load = segment
                    break

            for segment in segments:
                if segment["p_type"] == "PT_PHDR":
                    if self.phdr_segment is not None:
                        raise ValueError("Multiple PHDR segments!")
                    self.phdr_segment = segment

                    segment["p_filesz"] += self.additional_headers_size
                    segment["p_memsz"]  += self.additional_headers_size

                    phdr_size = max(segment["p_filesz"], segment["p_memsz"])

                    blah = sorted(((s.vaddr - self.project.loader.main_object.mapped_base, s.vaddr + s.memsize - self.project.loader.main_object.mapped_base) for s in self.project.loader.main_object.segments), key=lambda x: x[0])
                    while True:
                        stuff = []
                        i = 0
                        while i < len(blah) - 1:
                            thing1 = blah[i]
                            thing2 = blah[i + 1]
                            if thing1[1] > thing2[0]:
                                stuff.append((thing1[0], thing2[1]))
                                i += 2
                            else:
                                stuff.append(thing1)
                                i += 1
                        if i == len(blah) - 1:
                            stuff.append(blah[i])
                        if stuff == blah:
                            break
                        blah = stuff

                    for prev_seg, next_seg in zip(blah[:-1], blah[1:]):
                        potential_base = ((max(prev_seg[1], len(self.ncontent)) + 0xF) & ~0xF)
                        if next_seg[0] - potential_base > phdr_size:
                            self.phdr_start = potential_base
                            break
                    else:
                        self.phdr_start = blah[-1][1]

                    segment["p_offset"]  = self.phdr_start
                    segment["p_vaddr"]   = self.phdr_start + self.first_load["p_vaddr"]
                    segment["p_paddr"]   = self.phdr_start + self.first_load["p_vaddr"]

            self.ncontent = self.ncontent.ljust(self.phdr_start, b"\x00")

            # change pointer to program headers to point at the end of the elf
            current_hdr = self.structs.Elf_Ehdr.parse(self.ncontent)
            old_phoff = current_hdr["e_phoff"]
            current_hdr["e_phoff"] = len(self.ncontent)
            self.ncontent = utils.bytes_overwrite(self.ncontent,
                                                self.structs.Elf_Ehdr.build(current_hdr),
                                                0)

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

    def dump_segments_cgc(self, tprint=False):
        # from: https://github.com/CyberGrandChallenge/readcgcef/blob/master/readcgcef-minimal.py
        header_size = 16 + 2 * 2 + 4 * 5 + 2 * 6
        buf = self.ncontent[0:header_size]
        (cgcef_type, cgcef_machine, cgcef_version, cgcef_entry, cgcef_phoff,
         cgcef_shoff, cgcef_flags, cgcef_ehsize, cgcef_phentsize, cgcef_phnum,
         cgcef_shentsize, cgcef_shnum, cgcef_shstrndx) = struct.unpack("<xxxxxxxxxxxxxxxxHHLLLLLHHHHHH", buf)
        phent_size = 8 * 4
        assert cgcef_phnum != 0
        assert cgcef_phentsize == phent_size

        pt_types = {0: "NULL", 1: "LOAD", 6: "PHDR", 0x60000000 + 0x474e551: "GNU_STACK", 0x6ccccccc: "CGCPOV2"}
        segments = []
        for i in range(0, cgcef_phnum):
            hdr = self.ncontent[cgcef_phoff + phent_size * i:cgcef_phoff + phent_size * i + phent_size]
            (p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align) = struct.unpack("<IIIIIIII", hdr)

            assert p_type in pt_types
            ptype_str = pt_types[p_type]

            segments.append((p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align))

            if tprint:
                print("---")
                print("Loc:" + hex(cgcef_phoff + phent_size * i))
                print("Type: %s" % ptype_str)
                print("Permissions: %s" % self.pflags_to_perms(p_flags))
                print("Memory: 0x%x + 0x%x" % (p_vaddr, p_memsz))
                print("File: 0x%x + 0x%x" % (p_offset, p_filesz))
                print(map(hex, (p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align)))

        self.segments = segments
        return segments

    def dump_segments(self, tprint=False):
        with open(self.filename, "rb") as f:
            elf = ELFFile(f)
            self.structs = elf.structs
            segments = []
            for i in range(elf.num_segments()):
                seg = elf.get_segment(i)
                segments.append(seg.header)
                """
                attrs = (seg["p_type"],   seg["p_offset"], seg["p_vaddr"], seg["p_paddr"],
                         seg["p_filesz"], seg["p_memsz"],  seg["p_flags"], seg["p_align"])
                segments.append(attrs)
                """
        return segments

    def set_added_segment_headers(self, nsegments):
        if 'ELF' not in magic.from_file(self.filename):
            assert self.ncontent[0x34:0x34+len(self.patched_tag)] == self.patched_tag
            if self.data_fallback:
                l.debug("added_data_file_start: %#x", self.added_data_file_start)
            added_segments = 0
            original_nsegments = nsegments

            # if the size of a segment is zero, the kernel does not allocate any memory
            # so, we don't care about empty segments
            if self.data_fallback:
                mem_data_location = self.name_map["ADDED_DATA_START"]
                data_segment_header = (1, self.added_data_file_start, mem_data_location, mem_data_location,
                                       len(self.added_data), len(self.added_data), 0x6, 0x1000)  # RW
                self.ncontent = utils.bytes_overwrite(self.ncontent, struct.pack("<IIIIIIII", *data_segment_header),
                                                      self.original_header_end + 32)
                added_segments += 1
            else:
                pass
                # in this case the header has been already patched before

            mem_code_location = self.added_code_segment + (self.added_code_file_start % 0x1000)
            code_segment_header = (1, self.added_code_file_start, mem_code_location, mem_code_location,
                                   len(self.added_code), len(self.added_code), 0x5, 0x1000)  # RX
            self.ncontent = utils.bytes_overwrite(self.ncontent, struct.pack("<IIIIIIII", *code_segment_header),
                                                  self.original_header_end)
            added_segments += 1

            # print original_nsegments,added_segments
            self.ncontent = utils.bytes_overwrite(self.ncontent, struct.pack("<H", original_nsegments + added_segments), 0x2c)
        else:
            if self.data_fallback:
                l.debug("added_data_file_start: %#x", self.added_data_file_start)
            added_segments = 0
            original_nsegments = nsegments

            # add a LOAD segment for the PHDR segment
            phdr_offset = self.phdr_segment["p_offset"]
            phdr_vaddr = self.phdr_segment["p_vaddr"]
            phdr_paddr = self.phdr_segment["p_paddr"]
            phdr_fsize = self.phdr_segment["p_filesz"]
            phdr_msize = self.phdr_segment["p_memsz"]
            phdr_segment_header = Container(**{"p_type":   1,          "p_offset": phdr_offset,
                                               "p_vaddr":  phdr_vaddr, "p_paddr":  phdr_paddr,
                                               "p_filesz": phdr_fsize, "p_memsz":  phdr_msize,
                                               "p_flags":  0x4,        "p_align":  0x1000})
            self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Phdr.build(phdr_segment_header),
                                                  self.original_header_end + (2 * self.structs.Elf_Phdr.sizeof()))
            added_segments += 1


            # if the size of a segment is zero, the kernel does not allocate any memory
            # so, we don't care about empty segments
            if self.data_fallback:
                mem_data_location = self.name_map["ADDED_DATA_START"]
                data_segment_header = Container(**{"p_type":   1,                    "p_offset": self.added_data_file_start,
                                                   "p_vaddr":  mem_data_location,    "p_paddr":  mem_data_location,
                                                   "p_filesz": len(self.added_data), "p_memsz":  len(self.added_data),
                                                   "p_flags":  0x6,                  "p_align":  0x1000})
                self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Phdr.build(data_segment_header),
                                                      self.original_header_end + self.structs.Elf_Phdr.sizeof())
                added_segments += 1
            else:
                pass
                # in this case the header has been already patched before

            self.mem_code_location = self.added_code_segment + (self.added_code_file_start % 0x1000)
            code_segment_header = Container(**{"p_type":   1,                      "p_offset": self.added_code_file_start,
                                               "p_vaddr":  self.mem_code_location, "p_paddr":  self.mem_code_location,
                                               "p_filesz": len(self.added_code),   "p_memsz":  len(self.added_code),
                                               "p_flags":  0x5,                    "p_align":  0x1000})
            self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Phdr.build(code_segment_header),
                                                self.original_header_end)
            added_segments += 1

            # print original_nsegments,added_segments
            current_hdr = self.structs.Elf_Ehdr.parse(self.ncontent)
            current_hdr["e_phnum"] += added_segments
            self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Ehdr.build(current_hdr), 0)

    @staticmethod
    def pflags_to_perms(p_flags):
        pf_x = (1 << 0)
        pf_w = (1 << 1)
        pf_r = (1 << 2)

        perms = ""
        if p_flags & pf_r:
            perms += "R"
        if p_flags & pf_w:
            perms += "W"
        if p_flags & pf_x:
            perms += "X"
        return perms

    def set_oep(self, new_oep):
        # get original entry point
        current_hdr = self.structs.Elf_Ehdr.parse(self.ncontent)
        current_hdr["e_entry"] = new_oep
        self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Ehdr.build(current_hdr), 0)

    def get_oep(self):
        # set original entry point
        current_hdr = self.structs.Elf_Ehdr.parse(self.ncontent)
        return current_hdr["e_entry"]

    # 3 inserting strategies
    # Jump out and jump back
    # move a single function out
    # extending all the functions, so all need to move

    def get_block_containing_inst(self, inst_addr):
        index = bisect.bisect_right(self.ordered_nodes, inst_addr) - 1
        node = self.cfg.get_any_node(self.ordered_nodes[index], is_syscall=False)
        if inst_addr in node.instruction_addrs:
            return node.addr
        else:
            raise MissingBlockException("Couldn't find a block containing address %#x" % inst_addr)

    def get_current_code_position(self):
        return self.name_map["ADDED_CODE_START"] + (len(self.ncontent) - self.added_code_file_start)

    def save_state(self,applied_patches):
        #print "inserting", tuple(applied_patches)
        self.saved_states[tuple(applied_patches)] = (self.ncontent,set(self.touched_bytes))

    def restore_state(self,applied_patches,removed_patches):
        # find longest sequence of patches for which we have a save state
        if len(removed_patches) > 0:
            cut = min([len(applied_patches)]+[applied_patches.index(p) for p in removed_patches if p in applied_patches])
            applied_patches = applied_patches[:cut]
        current_longest = self.saved_states[tuple(applied_patches)]
        self.ncontent, self.touched_bytes = current_longest
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
        # deal with stackable patches
        # add stackable patches to the one with highest priority
        insert_code_patches = [p for p in patches if isinstance(p, InsertCodePatch)]
        insert_code_patches_dict = defaultdict(list)
        for p in insert_code_patches:
            insert_code_patches_dict[p.addr].append(p)
        insert_code_patches_dict_sorted = defaultdict(list)
        for k,v in insert_code_patches_dict.items():
            insert_code_patches_dict_sorted[k] = sorted(v,key=lambda x:-1*x.priority)

        insert_code_patches_stackable = [p for p in patches if isinstance(p, InsertCodePatch) and p.stackable]
        for sp in insert_code_patches_stackable:
            assert len(sp.dependencies) == 0
            if sp.addr in insert_code_patches_dict_sorted:
                highest_priority_at_addr = insert_code_patches_dict_sorted[sp.addr][0]
                if highest_priority_at_addr != sp:
                    highest_priority_at_addr.asm_code += "\n"+sp.asm_code+"\n"
                    patches.remove(sp)

        #deal with AddLabel patches
        lpatches = [p for p in patches if (isinstance(p, AddLabelPatch))]
        for p in lpatches:
            self.name_map[p.name] = p.addr

        # check for duplicate labels, it is not very necessary for this backend
        # but it is better to behave in the same way of the reassembler backend
        relevant_patches = [p for p in patches if (isinstance(p, AddCodePatch) or
                isinstance(p, InsertCodePatch) or isinstance(p, AddEntryPointPatch))]
        all_code = ""
        for p in relevant_patches:
            if isinstance(p, InsertCodePatch):
                code = p.code
            else:
                code = p.asm_code
            all_code += "\n" + code + "\n"
        labels = utils.string_to_labels(all_code)
        duplicates = set([x for x in labels if labels.count(x) > 1])
        if len(duplicates) > 1:
            raise DuplicateLabelsException("found duplicate assembly labels: %s" % (str(duplicates)))

        # for now any added code will be executed by jumping out and back ie CGRex
        # apply all add code patches
        self.added_code_file_start = len(self.ncontent)
        self.name_map.force_insert("ADDED_CODE_START",(len(self.ncontent) % 0x1000) + self.added_code_segment)

        # 0) RawPatch:
        for patch in patches:
            if isinstance(patch, RawFilePatch):
                self.ncontent = utils.bytes_overwrite(self.ncontent, patch.data, patch.file_addr)
                self.added_patches.append(patch)
                l.info("Added patch: " + str(patch))
        for patch in patches:
            if isinstance(patch, RawMemPatch):
                self.patch_bin(patch.addr,patch.data)
                self.added_patches.append(patch)
                l.info("Added patch: " + str(patch))

        for patch in patches:
            if isinstance(patch, RemoveInstructionPatch):
                if patch.ins_size is None:
                    ins = self.read_mem_from_file(patch.ins_addr, 16)
                    size = list(self.project.arch.capstone.disasm(ins, 0))[0].size
                else:
                    size = patch.ins_size
                self.patch_bin(patch.ins_addr, "\x90" * size)
                self.added_patches.append(patch)
                l.info("Added patch: " + str(patch))

        if self.data_fallback:
            # 1)
            self.added_data_file_start = len(self.ncontent)
            curr_data_position = self.name_map["ADDED_DATA_START"]
            for patch in patches:
                if isinstance(patch, AddRWDataPatch) or isinstance(patch, AddRODataPatch) or \
                        isinstance(patch, AddRWInitDataPatch):
                    if hasattr(patch, "data"):
                        final_patch_data = patch.data
                    else:
                        final_patch_data = b"\x00" * patch.len
                    self.added_data += final_patch_data
                    if patch.name is not None:
                        self.name_map[patch.name] = curr_data_position
                    curr_data_position += len(final_patch_data)
                    self.ncontent = utils.bytes_overwrite(self.ncontent, final_patch_data)
                    self.added_patches.append(patch)
                    l.info("Added patch: " + str(patch))
            self.ncontent = utils.pad_bytes(self.ncontent, 0x10)  # some minimal alignment may be good

            self.added_code_file_start = len(self.ncontent)
            self.name_map.force_insert("ADDED_CODE_START", (len(self.ncontent) % 0x1000) + self.added_code_segment)
        else:
            # 1.1) AddRWDataPatch
            for patch in patches:
                if isinstance(patch, AddRWDataPatch):
                    if patch.name is not None:
                        self.name_map[patch.name] = self.name_map["ADDED_DATA_START"] + self.added_rwdata_len
                    self.added_rwdata_len += patch.len
                    self.added_patches.append(patch)
                    l.info("Added patch: " + str(patch))

            # 1.2) AddRWInitDataPatch
            for patch in patches:
                if isinstance(patch, AddRWInitDataPatch):
                    self.to_init_data += patch.data
                    if patch.name is not None:
                        self.name_map[patch.name] = self.name_map["ADDED_DATA_START"] + self.added_rwdata_len + \
                                self.added_rwinitdata_len
                    self.added_rwinitdata_len += len(patch.data)
                    self.added_patches.append(patch)
                    l.info("Added patch: " + str(patch))
            if self.to_init_data != b"":
                code = '''
                jmp _skip_data
                _to_init_data:
                    db %s
                _skip_data:
                    mov esi, _to_init_data
                    mov edi, %s
                    mov ecx, %d
                    cld
                    rep movsb
                ''' % (",".join([hex(x) for x in self.to_init_data]), \
                        hex(self.name_map["ADDED_DATA_START"] + self.added_rwdata_len), \
                        self.added_rwinitdata_len)
                patches.append(AddEntryPointPatch(code,priority=1000,name="INIT_DATA"))

            # 1.3) AddRODataPatch
            for patch in patches:
                if isinstance(patch, AddRODataPatch):
                    self.to_init_data += patch.data
                    if patch.name is not None:
                        self.name_map[patch.name] = self.get_current_code_position()
                    self.added_code += patch.data
                    self.ncontent = utils.bytes_overwrite(self.ncontent, patch.data)
                    self.added_patches.append(patch)
                    l.info("Added patch: " + str(patch))

        if 'ELF' in magic.from_file(self.filename):
            # add PIE thunk
            self.name_map["pie_thunk"] = self.get_current_code_position()
            if self.structs.elfclass == 64:
                pie_thunk = """
                _patcherex_begin_patch:
                call $+5
                here:
                pop rax
                sub rax, (here - _patcherex_begin_patch + {pie_thunk})
                ret
                """
            else:
                pie_thunk = """
                _patcherex_begin_patch:
                call $+5
                here:
                pop eax
                sub eax, (here - _patcherex_begin_patch + {pie_thunk})
                ret
                """
            new_code = utils.compile_asm(pie_thunk,
                                         self.get_current_code_position(),
                                         self.name_map,
                                         bits=self.structs.elfclass)
            self.added_code += new_code
            self.ncontent = utils.bytes_overwrite(self.ncontent, new_code)

        # 2) AddCodePatch
        # resolving symbols
        current_symbol_pos = self.get_current_code_position()
        for patch in patches:
            if isinstance(patch, AddCodePatch):
                if patch.is_c:
                    code_len = len(utils.compile_c(patch.asm_code,
                                                   optimization=patch.optimization,
                                                   compiler_flags=patch.compiler_flags))
                else:
                    code_len = len(utils.compile_asm_fake_symbol(patch.asm_code,
                                                                 current_symbol_pos,
                                                                 bits=self.structs.elfclass))
                if patch.name is not None:
                    self.name_map[patch.name] = current_symbol_pos
                current_symbol_pos += code_len
        # now compile for real
        for patch in patches:
            if isinstance(patch, AddCodePatch):
                if patch.is_c:
                    new_code = utils.compile_c(patch.asm_code,
                                               optimization=patch.optimization,
                                               compiler_flags=patch.compiler_flags)
                else:
                    new_code = utils.compile_asm(patch.asm_code,
                                                 self.get_current_code_position(),
                                                 self.name_map,
                                                 bits=self.structs.elfclass)
                self.added_code += new_code
                self.ncontent = utils.bytes_overwrite(self.ncontent, new_code)
                self.added_patches.append(patch)
                l.info("Added patch: " + str(patch))

        # 3) AddEntryPointPatch
        # basically like AddCodePatch but we detour by changing oep
        # and we jump at the end of all of them
        # resolving symbols
        if any([isinstance(p, AddEntryPointPatch) for p in patches]):
            pre_entrypoint_code_position = self.get_current_code_position()
            current_symbol_pos = self.get_current_code_position()
            entrypoint_patches = [p for p in patches if isinstance(p,AddEntryPointPatch)]
            between_restore_entrypoint_patches = sorted([p for p in entrypoint_patches if not p.after_restore], \
                key=lambda x:-1*x.priority)
            after_restore_entrypoint_patches = sorted([p for p in entrypoint_patches if p.after_restore], \
                key=lambda x:-1*x.priority)

            current_symbol_pos += len(utils.compile_asm_fake_symbol("pusha\n",
                                                                    current_symbol_pos,
                                                                    bits=self.structs.elfclass))
            for patch in between_restore_entrypoint_patches:
                code_len = len(utils.compile_asm_fake_symbol(patch.asm_code,
                                                             current_symbol_pos,
                                                             bits=self.structs.elfclass))
                if patch.name is not None:
                    self.name_map[patch.name] = current_symbol_pos
                current_symbol_pos += code_len
            # now compile for real
            new_code = utils.compile_asm(ASM_ENTRY_POINT_PUSH_ENV,
                                         self.get_current_code_position(),
                                         bits=self.structs.elfclass)
            self.added_code += new_code
            self.ncontent = utils.bytes_overwrite(self.ncontent, new_code)
            for patch in between_restore_entrypoint_patches:
                new_code = utils.compile_asm(patch.asm_code,
                                             self.get_current_code_position(),
                                             self.name_map,
                                             bits=self.structs.elfclass)
                self.added_code += new_code
                self.added_patches.append(patch)
                l.info("Added patch: " + str(patch))
                self.ncontent = utils.bytes_overwrite(self.ncontent, new_code)

            restore_code = ASM_ENTRY_POINT_RESTORE_ENV
            current_symbol_pos += len(utils.compile_asm_fake_symbol(restore_code,
                                                                    current_symbol_pos,
                                                                    bits=self.structs.elfclass))
            for patch in after_restore_entrypoint_patches:
                code_len = len(utils.compile_asm_fake_symbol(patch.asm_code,
                                                             current_symbol_pos,
                                                             bits=self.structs.elfclass))
                if patch.name is not None:
                    self.name_map[patch.name] = current_symbol_pos
                current_symbol_pos += code_len
            # now compile for real
            new_code = utils.compile_asm(restore_code,
                                         self.get_current_code_position(),
                                         bits=self.structs.elfclass)
            self.added_code += new_code
            self.ncontent = utils.bytes_overwrite(self.ncontent, new_code)
            for patch in after_restore_entrypoint_patches:
                new_code = utils.compile_asm(patch.asm_code,
                                             self.get_current_code_position(),
                                             self.name_map,
                                             bits=self.structs.elfclass)
                self.added_code += new_code
                self.ncontent = utils.bytes_overwrite(self.ncontent, new_code)
                self.added_patches.append(patch)
                l.info("Added patch: " + str(patch))

            oep = self.get_oep()
            self.set_oep(pre_entrypoint_code_position)
            new_code = utils.compile_jmp(self.get_current_code_position(),oep)
            self.added_code += new_code
            self.ncontent += new_code

        # 4) InlinePatch
        # we assume the patch never patches the added code
        for patch in patches:
            if isinstance(patch, InlinePatch):
                if 'ELF' in magic.from_file(self.filename):
                    new_code = utils.compile_asm(patch.new_asm,
                                                patch.instruction_addr,
                                                self.name_map,
                                                bits=self.structs.elfclass)
                else:
                    new_code = utils.compile_asm(patch.new_asm,
                                                patch.instruction_addr,
                                                self.name_map) 
                assert len(new_code) == self.project.factory.block(patch.instruction_addr, num_inst=1).size
                file_offset = self.project.loader.main_object.addr_to_offset(patch.instruction_addr)
                self.ncontent = utils.bytes_overwrite(self.ncontent, new_code, file_offset)
                self.added_patches.append(patch)
                l.info("Added patch: " + str(patch))

        # 5) InsertCodePatch
        # these patches specify an address in some basic block, In general we will move the basic block
        # and fix relative offsets
        # With this backend heer we can fail applying a patch, in case, resolve dependencies
        insert_code_patches = [p for p in patches if isinstance(p, InsertCodePatch)]
        insert_code_patches = sorted([p for p in insert_code_patches],key=lambda x:-1*x.priority)
        applied_patches = []
        while True:
            name_list = [str(p) if (p is None or p.name is None) else p.name for p in applied_patches]
            l.info("applied_patches is: |" + "-".join(name_list)+"|")
            assert all([a == b for a, b in zip(applied_patches, insert_code_patches)])
            for patch in insert_code_patches[len(applied_patches):]:
                self.save_state(applied_patches)
                try:
                    l.info("Trying to add patch: " + str(patch))
                    if patch.name is not None:
                        self.name_map[patch.name] = self.get_current_code_position()
                    new_code = self.insert_detour(patch)
                    self.added_code += new_code
                    self.ncontent = utils.bytes_overwrite(self.ncontent, new_code)
                    applied_patches.append(patch)
                    self.added_patches.append(patch)
                    l.info("Added patch: " + str(patch))
                except (DetourException, MissingBlockException, DoubleDetourException) as e:
                    l.warning(e)
                    insert_code_patches, removed = self.handle_remove_patch(insert_code_patches,patch)
                    #print map(str,removed)
                    applied_patches = self.restore_state(applied_patches, removed)
                    l.warning("One patch failed, rolling back InsertCodePatch patches. Failed patch: "+str(patch))
                    break
                    # TODO: right now rollback goes back to 0 patches, we may want to go back less
                    # the solution is to save touched_bytes and ncontent indexed by applied patfch
                    # and go back to the biggest compatible list of patches
            else:
                break #at this point we applied everything in current insert_code_patches
                # TODO symbol name, for now no name_map for InsertCode patches

        header_patches = [InsertCodePatch,InlinePatch,AddEntryPointPatch,AddCodePatch, \
                AddRWDataPatch,AddRODataPatch,AddRWInitDataPatch]
        if any([isinstance(p,ins) for ins in header_patches for p in self.added_patches]) or \
                any([isinstance(p,SegmentHeaderPatch) for p in patches]):
            # either implicitly (because of a patch adding code or data) or explicitly, we need to change segment headers

            # 6) SegmentHeaderPatch
            segment_header_patches = [p for p in patches if isinstance(p,SegmentHeaderPatch)]
            if len(segment_header_patches) > 1:
                msg = "more than one patch tries to change segment headers: " + "|".join([str(p) for p in segment_header_patches])
                raise IncompatiblePatchesException(msg)
            elif len(segment_header_patches) == 1:
                segment_patch = segment_header_patches[0]
                segments = segment_patch.segment_headers
                l.info("Added patch: " + str(segment_patch))
            else:
                segments = self.modded_segments

            for patch in [p for p in patches if isinstance(p,AddSegmentHeaderPatch)]:
                # add after the first
                segments = [segments[0]] + [patch.new_segment] + segments[1:]

            if not self.data_fallback:
                last_segment = segments[-1]
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = last_segment
                last_segment =  p_type, p_offset, p_vaddr, p_paddr, \
                       p_filesz, p_memsz + self.added_rwdata_len + self.added_rwinitdata_len, p_flags, p_align
                segments[-1] = last_segment
            self.setup_headers(segments)
            self.set_added_segment_headers(len(segments))
            l.debug("final symbol table: "+ repr([(k,hex(v)) for k,v in self.name_map.items()]))
        else:
            l.info("no patches, the binary will not be touched")

    def handle_remove_patch(self,patches,patch):
        # note the patches contains also "future" patches
        l.info("Handling removal of patch: "+str(patch))
        cleaned_patches = [p for p in patches if p != patch]
        removed_patches = [patch]
        while True:
            removed = False
            #print "---"
            for p in cleaned_patches:
                #print p.name
                for d in p.dependencies:
                    #print "\t",d.name, map(lambda x:x.name,cleaned_patches)
                    if d not in cleaned_patches:
                        l.info("Removing depending patch: "+str(p)+" depends from "+str(d))
                        removed = True
                        if p in cleaned_patches:
                            cleaned_patches.remove(p)
                        if p not in removed_patches:
                            removed_patches.append(p)
            if removed == False:
                break
        return cleaned_patches,removed_patches

    def check_if_movable(self, instruction):
        # the idea here is an instruction is movable if and only if
        # it has the same string representation when moved at different offsets is "movable"
        if 'ELF' not in magic.from_file(self.filename):
            def bytes_to_comparable_str(ibytes, offset):
                return " ".join(utils.instruction_to_str(utils.disassemble(ibytes, offset)[0]).split()[2:])

            instruction_bytes = str(instruction.bytes)
            pos1 = bytes_to_comparable_str(instruction_bytes, 0x0)
            pos2 = bytes_to_comparable_str(instruction_bytes, 0x07f00000)
            pos3 = bytes_to_comparable_str(instruction_bytes, 0xfe000000)
            if pos1 == pos2 and pos2 == pos3:
                return True
            else:
                return False
        else:
            def bytes_to_comparable_str(ibytes, offset, bits):
                return " ".join(utils.instruction_to_str(utils.disassemble(ibytes, offset,
                                                                           bits=bits)[0]).split()[2:])

            instruction_bytes = str(instruction.bytes)
            pos1 = bytes_to_comparable_str(instruction_bytes, 0x0, self.structs.elfclass)
            pos2 = bytes_to_comparable_str(instruction_bytes, 0x07f00000, self.structs.elfclass)
            pos3 = bytes_to_comparable_str(instruction_bytes, 0xfe000000, self.structs.elfclass)
            # print pos1, pos2, pos3
            if pos1 == pos2 and pos2 == pos3:
                return True
            else:
                return False

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
        # print hex(start), hex(end)
        start_p = address & 0xfffffff000
        end_p = end & 0xfffffff000
        if start_p == end_p:
            return [(self.maddress_to_baddress(start), self.maddress_to_baddress(end)+1)]
        else:
            first_page_baddress = self.maddress_to_baddress(start)
            mlist = list()
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
            # print "-",hex(start),hex(end)
            ndata = new_content[ndata_pos:ndata_pos+(end-start)]
            self.ncontent = utils.bytes_overwrite(self.ncontent, ndata, start)
            ndata_pos += len(ndata)

    def read_mem_from_file(self, address, size):
        mem = b""
        for start, end in self.get_memory_translation_list(address, size):
            # print "-",hex(start),hex(end)
            mem += self.ncontent[start : end]
        return mem

    def get_movable_instructions(self, block):
        # TODO there are two improvements here:
        # 1) being able to move the jmp and call at the end of a bb
        # 2) detect cases like call-pop and dependent instructions (which should not be moved)
        # get movable_instructions in the bb
        original_bbcode = block.bytes
        if 'ELF' not in magic.from_file(self.filename):
            instructions = utils.disassemble(original_bbcode, block.addr)
        else:
            instructions = utils.disassemble(original_bbcode, block.addr, bits=self.structs.elfclass)

        if self.check_if_movable(instructions[-1]):
            movable_instructions = instructions
        else:
            movable_instructions = instructions[:-1]

        return movable_instructions

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
        # create injected_code (pre, injected, culprit, post, jmp_back)
        injected_code = "_patcherex_begin_patch:\n"
        injected_code += "\n".join([utils.capstone_to_nasm(i)
                                    for i in classified_instructions
                                    if i.overwritten == 'pre'])
        injected_code += "\n"
        injected_code += "; --- custom code start\n" + patch_code + "\n" + "; --- custom code end\n" + "\n"
        injected_code += "\n".join([utils.capstone_to_nasm(i)
                                    for i in classified_instructions
                                    if i.overwritten == 'culprit'])
        injected_code += "\n"
        injected_code += "\n".join([utils.capstone_to_nasm(i)
                                    for i in classified_instructions
                                    if i.overwritten == 'post'])
        injected_code += "\n"
        jmp_back_target = None
        for i in reversed(classified_instructions):  # jmp back to the one after the last byte of the last non-out
            if i.overwritten != "out":
                jmp_back_target = i.address+len(i.bytes)
                break
        assert jmp_back_target is not None
        injected_code += "jmp %s" % hex(int(jmp_back_target) - offset) + "\n"
        # removing blank lines
        injected_code = "\n".join([line for line in injected_code.split("\n") if line != ""])
        l.debug("injected code:\n%s", injected_code)

        if 'ELF' not in magic.from_file(self.filename):
            compiled_code = utils.compile_asm(injected_code, base=self.get_current_code_position(), name_map=self.name_map)
        else:
            compiled_code = utils.compile_asm(injected_code,
                                              base=self.get_current_code_position(),
                                              name_map=self.name_map,
                                              bits=self.structs.elfclass)
        return compiled_code

    def insert_detour(self, patch):
        # TODO allow special case to patch syscall wrapper epilogue
        # (not that important since we do not want to patch epilogue in syscall wrapper)
        if 'ELF' not in magic.from_file(self.filename):
            block_addr = self.get_block_containing_inst(patch.addr)
            block = self.project.factory.block(block_addr)

            l.debug("inserting detour for patch: %s" % (map(hex, (block_addr, block.size, patch.addr))))

            detour_size = 5
            one_byte_nop = b'\x90'

            movable_instructions = self.get_movable_instructions(block)
            if len(movable_instructions) == 0:
                raise DetourException("No movable instructions found")
            detour_pos = self.find_detour_pos(block, detour_size, patch.addr)
            detour_overwritten_bytes = range(detour_pos, detour_pos+detour_size)

            for i in movable_instructions:
                if len(set(detour_overwritten_bytes).intersection(set(range(i.address, i.address+len(i.bytes))))) > 0:
                    if i.address < patch.addr:
                        i.overwritten = "pre"
                    elif i.address == patch.addr:
                        i.overwritten = "culprit"
                    else:
                        i.overwritten = "post"
                else:
                    i.overwritten = "out"
            l.debug("\n".join([utils.instruction_to_str(i) for i in movable_instructions]))
            assert any([i.overwritten != "out" for i in movable_instructions])
            # replace overwritten instructions with nops
            for i in movable_instructions:
                if i.overwritten != "out":
                    for b in range(i.address, i.address+len(i.bytes)):
                        if b in self.touched_bytes:
                            raise DoubleDetourException("byte has been already touched: %08x" % b)
                        else:
                            self.touched_bytes.add(b)
                    self.patch_bin(i.address, one_byte_nop*len(i.bytes))

            # insert the jump detour

            detour_jmp_code = utils.compile_jmp(detour_pos, self.get_current_code_position())
            self.patch_bin(detour_pos, detour_jmp_code)
            patched_bbcode = self.read_mem_from_file(block_addr, block.size)
            patched_bbinstructions = utils.disassemble(patched_bbcode, block_addr)
            l.debug("patched bb instructions:\n %s",
                    "\n".join([utils.instruction_to_str(i) for i in patched_bbinstructions]))
            new_code = self.compile_moved_injected_code(movable_instructions, patch.code)
            return new_code
        else:
            block_addr = self.get_block_containing_inst(patch.addr)
            mem = self.read_mem_from_file(block_addr, self.project.factory.block(block_addr).size)
            block = self.project.factory.block(block_addr, byte_string=mem)

            l.debug("inserting detour for patch: %s" % (map(hex, (block_addr, block.size, patch.addr))))

            detour_size = 5
            one_byte_nop = b'\x90'

            # get movable instructions
            movable_instructions = self.get_movable_instructions(block)
            if len(movable_instructions) == 0:
                raise DetourException("No movable instructions found")

            # figure out where to insert the detour
            detour_pos = self.find_detour_pos(block, detour_size, patch.addr)

            # classify overwritten instructions
            detour_overwritten_bytes = range(detour_pos, detour_pos+detour_size)

            for i in movable_instructions:
                if len(set(detour_overwritten_bytes).intersection(set(range(i.address, i.address+len(i.bytes))))) > 0:
                    if i.address < patch.addr:
                        i.overwritten = "pre"
                    elif i.address == patch.addr:
                        i.overwritten = "culprit"
                    else:
                        i.overwritten = "post"
                else:
                    i.overwritten = "out"
            l.debug("\n".join([utils.instruction_to_str(i) for i in movable_instructions]))
            assert any([i.overwritten != "out" for i in movable_instructions])

            # replace overwritten instructions with nops
            for i in movable_instructions:
                if i.overwritten != "out":
                    for b in range(i.address, i.address+len(i.bytes)):
                        if b in self.touched_bytes:
                            raise DoubleDetourException("byte has been already touched: %08x" % b)
                        else:
                            self.touched_bytes.add(b)
                    self.patch_bin(i.address, one_byte_nop*len(i.bytes))

            # insert the jump detour
            offset = self.project.loader.main_object.mapped_base if self.project.loader.main_object.pic else 0
            detour_jmp_code = utils.compile_jmp(detour_pos, self.get_current_code_position() + offset)
            self.patch_bin(detour_pos, detour_jmp_code)
            patched_bbcode = self.read_mem_from_file(block_addr, block.size)
            patched_bbinstructions = utils.disassemble(patched_bbcode, block_addr, bits=self.structs.elfclass)
            l.debug("patched bb instructions:\n %s",
                    "\n".join([utils.instruction_to_str(i) for i in patched_bbinstructions]))

            new_code = self.compile_moved_injected_code(movable_instructions, patch.code, offset=offset)

            return new_code

    def get_final_content(self):
        # print self.modded_segments
        return self.ncontent

    def save(self, filename=None):
        if filename is None:
            filename = self.filename + "_patched"

        final_content = self.get_final_content()
        with open(filename, "wb") as f:
            f.write(final_content)

        os.chmod(filename, 0o755)


def init_backend(program_name, options):
    return DetourBackend(program_name, **options)
