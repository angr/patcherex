import angr

import os
import utils
import struct

"""
symbols will look like {}
"""


class Patch(object):
    def __init__(self, name):
        self.name = name


class InlinePatch(Patch):
    def __init__(self, instruction_addr, new_asm, name=None):
        super(InlinePatch, self).__init__(name)
        self.instruction_addr = instruction_addr
        self.new_asm = new_asm


class AddDataPatch(Patch):
    def __init__(self, data, name=None):
        super(AddDataPatch, self).__init__(name)
        self.data = data


class AddCodePatch(Patch):
    def __init__(self, asm_code, name=None):
        super(AddCodePatch, self).__init__(name)
        self.asm_code = asm_code


class InsertCodePatch(Patch):
    def __init__(self, addr, code, name=None):
        super(InsertCodePatch, self).__init__(name)
        self.addr = addr
        self.code = code

# todo entry point patch, might need to be implemented differently
# todo remove padding
# todo check that patches do not pile up
# todo check for symbol name collisions


class Patcherex(object):
    # how do we want to design this to track relocations in the blocks...
    def __init__(self, filename):
        # file info
        self.filename = filename
        self.project = angr.Project(filename)
        with open(filename, "rb") as f:
            self.ocontent = f.read()

        # header stuff
        self.ncontent = None
        self.segments = None
        self.original_header_end = None

        # tag to track if already patched
        self.patched_tag = "SHELLPHISH\x00"  # should not be longer than 0x20

        # where to put the segments
        self.added_code_segment = 0x09000000
        self.added_data_segment = 0x09100000

        # set up headers, initializes ncontent
        self.setup_headers()

        # patches data
        self.patches = []
        self.name_map = dict()

        self.added_code = ""
        self.added_data = ""
        self.curr_code_position = self.added_code_segment
        self.curr_data_position = self.added_data_segment
        self.curr_file_position = utils.round_up_to_page(len(self.ncontent) + 2*32)
        self.added_code_file_start = None
        self.added_data_file_start = None

        # Todo ida-like cfg
        self.cfg = self.project.analyses.CFG()

    def add_data(self, data, name=None):
        self.patches.append(AddDataPatch(data, name))

    def add_code(self, code, name=None):
        self.patches.append(AddCodePatch(code, name))

    def insert_into_block(self, addr, code_to_insert, name=None):
        self.patches.append(InsertCodePatch(addr, code_to_insert, name))

    def replace_instruction_bytes(self, instruction_addr, new_bytes, name=None):
        pass

    def replace_instruction_asm(self, instruction_addr, new_asm, name=None):
        self.patches.append(InlinePatch(instruction_addr, new_asm, name))

    def is_patched(self):
        return self.ncontent[0x34:0x34 + len(self.patched_tag)] == self.patched_tag

    def setup_headers(self):
        self.ncontent = self.ocontent
        if self.is_patched():
            return

        segments = self.dump_segments()

        # align size of the entire ELF
        self.ncontent = utils.pad_str(self.ncontent, 0x10)
        # change pointer to program headers to point at the end of the elf
        self.ncontent = utils.str_overwrite(self.ncontent, struct.pack("<I", len(self.ncontent)), 0x1C)

        # copying original program headers in the new place (at the end of the file)
        for segment in segments:
            self.ncontent = utils.str_overwrite(self.ncontent, struct.pack("<IIIIIIII", *segment))
        self.original_header_end = len(self.ncontent)

        # we overwrite the first original program header,
        # we do not need it anymore since we have moved original program headers at the bottom of the file
        self.ncontent = utils.str_overwrite(self.ncontent, self.patched_tag, 0x34)

    def dump_segments(self, tprint=False):
        # from: https://github.com/CyberGrandChallenge/readcgcef/blob/master/readcgcef-minimal.py
        header_size = 16 + 2*2 + 4*5 + 2*6
        buf = self.ncontent[0:header_size]
        (cgcef_type, cgcef_machine, cgcef_version, cgcef_entry, cgcef_phoff,
            cgcef_shoff, cgcef_flags, cgcef_ehsize, cgcef_phentsize, cgcef_phnum,
            cgcef_shentsize, cgcef_shnum, cgcef_shstrndx) = struct.unpack("<xxxxxxxxxxxxxxxxHHLLLLLHHHHHH", buf)
        phent_size = 8 * 4
        assert cgcef_phnum != 0
        assert cgcef_phentsize == phent_size

        pt_types = {0: "NULL", 1: "LOAD", 6: "PHDR", 0x60000000+0x474e551: "GNU_STACK", 0x6ccccccc: "CGCPOV2"}
        segments = []
        for i in xrange(0, cgcef_phnum):
            hdr = self.ncontent[cgcef_phoff + phent_size * i:cgcef_phoff + phent_size * i + phent_size]
            (p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align) = struct.unpack("<IIIIIIII", hdr)
            if tprint:
                print (p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align)

            assert p_type in pt_types
            ptype_str = pt_types[p_type]

            segments.append((p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align))

            if tprint:
                print "---"
                print "Type: %s" % ptype_str
                print "Permissions: %s" % self.pflags_to_perms(p_flags)
                print "Memory: 0x%x + 0x%x" % (p_vaddr, p_memsz)
                print "File: 0x%x + 0x%x" % (p_offset, p_filesz)

        self.segments = segments
        return segments

    def set_added_segment_headers(self):
        assert self.ncontent[0x34:0x34+len(self.patched_tag)] == self.patched_tag
        #TODO if no added data or code, do not even add segments
        print hex(self.added_data_file_start)

        data_segment_header = (1, self.added_data_file_start, self.added_data_segment, self.added_data_segment,
                                len(self.added_data), len(self.added_data), 0x6, 0x0)  # RW
        code_segment_header = (1, self.added_code_file_start, self.added_code_segment, self.added_code_segment,
                                len(self.added_code), len(self.added_code), 0x5, 0x0)  # RX

        self.ncontent = utils.str_overwrite(self.ncontent, struct.pack("<IIIIIIII", *code_segment_header), self.original_header_end)
        self.ncontent = utils.str_overwrite(self.ncontent, struct.pack("<IIIIIIII", *data_segment_header), self.original_header_end + 32)
        original_nsegments = struct.unpack("<H", self.ncontent[0x2c:0x2c+2])[0]
        self.ncontent = utils.str_overwrite(self.ncontent, struct.pack("<H", original_nsegments + 2), 0x2c)

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
        self.ncontent = utils.str_overwrite(self.ncontent,struct.pack("<I", new_oep), 0x18)


    def get_oep(self):
        return struct.unpack("<I",self.ncontent[0x18:0x18+4])[0]


    # 3 inserting strategies
    # Jump out and jump back
    # move a single function out
    # extending all the functions, so all need to move


    def compile_patches(self):
        # for now any added code will be executed by jumping out and back ie CGRex
        # apply all add code patches
        self.name_map = dict()
        self.added_data = ""
        self.added_code = ""
        self.curr_code_position = self.added_code_segment
        self.curr_data_position = self.added_data_segment
        self.curr_file_position = utils.round_up_to_page(len(self.ncontent) + 2*32)  # TODO no padding
        self.added_data_file_start = self.curr_file_position

        # extend the file to the current file position
        self.ncontent = self.ncontent.ljust(self.curr_file_position, "\x00")

        # 1) AddDataPatch
        for patch in self.patches:
            if isinstance(patch, AddDataPatch):
                self.added_data += patch.data
                if patch.name is not None:
                    self.name_map[patch.name] = self.curr_data_position
                self.curr_data_position += len(patch.data)
                self.curr_file_position += len(patch.data)
                self.ncontent = utils.str_overwrite(self.ncontent, patch.data)

        # pad (todo remove)
        self.ncontent = utils.pad_str(self.ncontent, 0x1000)
        self.curr_file_position = len(self.ncontent)

        self.added_code_file_start = self.curr_file_position
        # 2) AddCodePatch
        # resolving symbols
        current_symbol_pos = self.curr_code_position
        for patch in self.patches:
            if isinstance(patch, AddCodePatch):
                code_len = len(utils.compile_asm_fake_symbol(patch.asm_code, current_symbol_pos))
                if patch.name is not None:
                    self.name_map[patch.name] = current_symbol_pos
                current_symbol_pos += code_len
        # now compile for real
        for patch in self.patches:
            if isinstance(patch, AddCodePatch):
                new_code = utils.compile_asm(patch.asm_code, self.curr_code_position, self.name_map)
                self.added_code += new_code
                self.curr_code_position += len(new_code)
                self.curr_file_position += len(new_code)
                self.ncontent = utils.str_overwrite(self.ncontent, new_code)

        # 3) InlinePatch
        # we assume the patch never patches the added code
        for patch in self.patches:
            if isinstance(patch, InlinePatch):
                new_code = utils.compile_asm(patch.new_asm, patch.instruction_addr, self.name_map)
                assert len(new_code) == self.project.factory.block(patch.instruction_addr, num_inst=1).size
                file_offset = self.project.loader.main_bin.addr_to_offset(patch.instruction_addr)
                self.ncontent = utils.str_overwrite(self.ncontent, new_code, file_offset)

        self.set_added_segment_headers()

    def save(self, filename=None):
        if filename is None:
            filename = self.filename + "_patched"

        with open(filename, "wb") as f:
            f.write(self.ncontent)

        os.chmod(filename, 0755)
