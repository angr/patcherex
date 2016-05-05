import angr
import os
import struct
import bisect
import logging

import patcherex
from patcherex import utils
from patcherex.patches import *

l = logging.getLogger("patcherex.backends.BaseBackend")


"""
symbols will look like {}
"""


class PatchingException(Exception):
    pass

class MissingBlockException(PatchingException):
    pass

class DetourException(PatchingException):
    pass

class InvalidVAddrException(PatchingException):
    pass

class IncompatiblePatchesException(PatchingException):
    pass



# todo check that patches do not pile up
# todo check for symbol name collisions
# todo allow simple pile ups, maybe we want to iterate through functions/basic_blocks not through patches
# todo asserts maybe should be exceptions
# todo add checks to verify that functions are called in proper order


class BaseBackend(object):
    # how do we want to design this to track relocations in the blocks...
    def __init__(self, filename):
        # file info
        self.filename = filename
        self.project = angr.Project(filename)
        with open(filename, "rb") as f:
            self.ocontent = f.read()

        # header stuff
        self.ncontent = self.ocontent
        self.segments = None
        self.original_header_end = None

        # tag to track if already patched
        self.patched_tag = "SHELLPHISH\x00"  # should not be longer than 0x20

        self.name_map = dict()

        # where to put the segments
        self.added_code_segment = 0x09000000
        self.added_data_segment = 0x09100000
        self.additional_headers_size = 2*32

        # set up headers, initializes ncontent
        self.name_map["ADDED_DATA_START"] = (len(self.ncontent) % 0x1000) + self.added_data_segment
        # we can set ADDED_CODE_START only after we added all the data (unless we decide to pad the data)

        self.added_code = ""
        self.added_data = ""

        self.added_code_file_start = None
        self.added_data_file_start = None

        # TODO
        # 1) ida-like cfg
        # 2) with some strategies we don't need the cfg, we should be able to apply those strategies even if the cfg fails 
        l.info("CFG start...")
        self.cfg = self.project.analyses.CFG()
        l.info("... CFG end")
        l.info("normalize start...")
        self.cfg.normalize()
        l.info("... normalize end")

        # TODO this should be in the cfg
        self.ordered_nodes = self.get_ordered_nodes()

    def get_ordered_nodes(self):
        prev_addr = None
        ordered_nodes = []
        for n in sorted(self.cfg.nodes(), key=lambda x: x.addr):
            if n.addr == prev_addr:
                continue
            prev_addr = n.addr
            ordered_nodes.append(n.addr)
        return ordered_nodes

    def is_patched(self):
        return self.ncontent[0x34:0x34 + len(self.patched_tag)] == self.patched_tag

    def setup_headers(self,segments):
        if self.is_patched():
            return

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

        # adding space for the additional headers
        self.ncontent = self.ncontent.ljust(len(self.ncontent)+self.additional_headers_size, "\x00")

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
        l.debug("added_data_file_start: %#x", self.added_data_file_start)

        # if the size of a segment is zero, the kernel does not allocate any memory
        # so, we don't care about empty segments
        mem_data_location = self.added_data_segment + (self.added_data_file_start % 0x1000)
        data_segment_header = (1, self.added_data_file_start, mem_data_location, mem_data_location,
                               len(self.added_data), len(self.added_data), 0x6, 0x1000)  # RW
        mem_code_location = self.added_code_segment + (self.added_code_file_start % 0x1000)
        code_segment_header = (1, self.added_code_file_start, mem_code_location, mem_code_location,
                               len(self.added_code), len(self.added_code), 0x5, 0x1000)  # RX

        self.ncontent = utils.str_overwrite(self.ncontent, struct.pack("<IIIIIIII", *code_segment_header),
                                            self.original_header_end)
        self.ncontent = utils.str_overwrite(self.ncontent, struct.pack("<IIIIIIII", *data_segment_header),
                                            self.original_header_end + 32)
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
        # get original entry point
        self.ncontent = utils.str_overwrite(self.ncontent, struct.pack("<I", new_oep), 0x18)

    def get_oep(self):
        # set original entry point
        return struct.unpack("<I", self.ncontent[0x18:0x18+4])[0]

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

    def apply_patches(self,patches):
        # for now any added code will be executed by jumping out and back ie CGRex
        # apply all add code patches
        added_patches = []
        self.added_data = ""
        self.added_code = ""
        curr_data_position = self.name_map["ADDED_DATA_START"]
        self.added_data_file_start = len(self.ncontent)


        # 0) RawPatch:
        for patch in patches:
            if isinstance(patch, RawFilePatch):
                self.ncontent = utils.str_overwrite(self.ncontent,patch.data,patch.file_addr)
                added_patches.append(patch)
                l.info("Added patch: " + str(patch))
        for patch in patches:
            if isinstance(patch, RawMemPatch):
                self.patch_bin(patch.addr,patch.data)
                added_patches.append(patch)
                l.info("Added patch: " + str(patch))

        # 1) AddDataPatch
        for patch in patches:
            if isinstance(patch, AddDataPatch):
                self.added_data += patch.data
                if patch.name is not None:
                    self.name_map[patch.name] = curr_data_position
                curr_data_position += len(patch.data)
                self.ncontent = utils.str_overwrite(self.ncontent, patch.data)
                added_patches.append(patch)
                l.info("Added patch: " + str(patch))
        self.ncontent = utils.pad_str(self.ncontent, 0x10)  # some minimal alignment may be good

        # 2) AddCodePatch
        # resolving symbols
        self.added_code_file_start = len(self.ncontent)
        self.name_map["ADDED_CODE_START"] = (len(self.ncontent) % 0x1000) + self.added_code_segment
        current_symbol_pos = self.get_current_code_position()
        for patch in patches:
            if isinstance(patch, AddCodePatch):
                code_len = len(utils.compile_asm_fake_symbol(patch.asm_code, current_symbol_pos))
                if patch.name is not None:
                    self.name_map[patch.name] = current_symbol_pos
                current_symbol_pos += code_len
        # now compile for real
        for patch in patches:
            if isinstance(patch, AddCodePatch):
                new_code = utils.compile_asm(patch.asm_code, self.get_current_code_position(), self.name_map)
                self.added_code += new_code
                self.ncontent = utils.str_overwrite(self.ncontent, new_code)
                added_patches.append(patch)
                l.info("Added patch: " + str(patch))

        # 3) AddEntryPointPatch
        # basically like AddCodePatch but we detour by changing oep
        # and we jump at the end of all of them
        # resolving symbols 
        if any([isinstance(p, AddEntryPointPatch) for p in patches]):
            pre_entrypoint_code_position = self.get_current_code_position()
            current_symbol_pos = self.get_current_code_position()
            current_symbol_pos += len(utils.compile_asm_fake_symbol("pusha\npushf\n", current_symbol_pos))
            for patch in sorted([p for p in patches if isinstance(p,AddEntryPointPatch)],key=lambda x:x.priority):
                if isinstance(patch, AddEntryPointPatch):
                    code_len = len(utils.compile_asm_fake_symbol(patch.asm_code, current_symbol_pos))
                    if patch.name is not None:
                        self.name_map[patch.name] = current_symbol_pos
                    current_symbol_pos += code_len
            # now compile for real
            new_code = utils.compile_asm("pusha\npushf\n", self.get_current_code_position())
            self.added_code += new_code
            self.ncontent = utils.str_overwrite(self.ncontent, new_code)
            for patch in sorted([p for p in patches if isinstance(p,AddEntryPointPatch)],key=lambda x:x.priority):
                if isinstance(patch, AddEntryPointPatch):
                    new_code = utils.compile_asm(patch.asm_code, self.get_current_code_position(), self.name_map)
                    self.added_code += new_code
                    self.ncontent = utils.str_overwrite(self.ncontent, new_code)
            new_code = utils.compile_asm("popf\npopa\n", self.get_current_code_position())
            self.added_code += new_code
            self.ncontent = utils.str_overwrite(self.ncontent, new_code)
            oep = self.get_oep()
            self.set_oep(pre_entrypoint_code_position)
            new_code = utils.compile_jmp(self.get_current_code_position(),oep)
            self.added_code += new_code
            self.ncontent += new_code
            added_patches.append(patch)
            l.info("Added patch: " + str(patch))

        # 4) InlinePatch
        # we assume the patch never patches the added code
        for patch in patches:
            if isinstance(patch, InlinePatch):
                new_code = utils.compile_asm(patch.new_asm, patch.instruction_addr, self.name_map)
                assert len(new_code) == self.project.factory.block(patch.instruction_addr, num_inst=1).size
                file_offset = self.project.loader.main_bin.addr_to_offset(patch.instruction_addr)
                self.ncontent = utils.str_overwrite(self.ncontent, new_code, file_offset)
                added_patches.append(patch)
                l.info("Added patch: " + str(patch))

        # 5) InsertCodePatch
        # these patches specify an address in some basic block, In general we will move the basic block
        # and fix relative offsets
        # With this backend heer we can fail applying a patch, in case, resolve dependencies
        while True:
            ncontent_copy = self.ncontent
            insert_code_patches = [p for p in patches if isinstance(p, InsertCodePatch)]
            for patch in insert_code_patches:
                    try:
                        new_code = self.insert_detour(patch)
                        self.added_code += new_code
                        self.ncontent = utils.str_overwrite(self.ncontent, new_code)
                        added_patches.append(patch)
                        l.info("Added patch: " + str(patch))
                    except (DetourException, MissingBlockException) as e:
                        l.warning(e)
                        patches = self.handle_remove_patch(patches,patch)
                        self.ncontent = ncontent_copy
                        l.warning("One patch failed, rolling back InsertCodePatch patches. Failed patch: "+str(patch))
                        break
            else:
                break
                # TODO symbol name

        header_patches = [InsertCodePatch,InlinePatch,AddEntryPointPatch,AddCodePatch,AddDataPatch]
        if any([isinstance(p,ins) for ins in header_patches for p in added_patches]) or \
                any([isinstance(p,SegmentHeaderPatch) for p in patches]):
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
                segments = self.dump_segments()
            self.setup_headers(segments)
            self.set_added_segment_headers()

        l.debug("final symbol table: "+ repr([(k,hex(v)) for k,v in self.name_map.iteritems()]))

    def handle_remove_patch(self,patches,patch):
        l.info("Handling removal of patch: "+str(patch))
        cleaned_patches = [p for p in patches if p != patch]
        while True:
            removed = False
            for p in cleaned_patches:
                for d in p.dependencies:
                    if d not in cleaned_patches:
                        l.info("Removing depending patch: "+str(p)+" depends from "+str(d))
                        removed = True
                        cleaned_patches.remove(p)
            if removed == False:
                break
        return cleaned_patches

    @staticmethod
    def check_if_movable(instruction):
        # the idea here is an instruction is movable if and only if
        # it has the same string representation when moved at different offsets is "movable"
        def bytes_to_comparable_str(ibytes, offset):
            return " ".join(utils.instruction_to_str(utils.decompile(ibytes, offset)[0]).split()[2:])

        instruction_bytes = str(instruction.bytes)
        pos1 = bytes_to_comparable_str(instruction_bytes, 0x0)
        pos2 = bytes_to_comparable_str(instruction_bytes, 0x07f00000)
        pos3 = bytes_to_comparable_str(instruction_bytes, 0xfe000000)
        # print pos1, pos2, pos3
        if pos1 == pos2 and pos2 == pos3:
            return True
        else:
            return False

    def maddress_to_baddress(self, addr):
        baddr = self.project.loader.main_bin.addr_to_offset(addr)
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
            self.ncontent = utils.str_overwrite(self.ncontent, ndata, start)
            ndata_pos += len(ndata)

    def read_mem_from_file(self, address, size):
        mem = ""
        for start, end in self.get_memory_translation_list(address, size):
            # print "-",hex(start),hex(end)
            mem += self.ncontent[start:end]
        return mem

    def get_movable_instructions(self, block):
        # TODO there are two improvements here:
        # 1) being able to move the jmp and call at the end of a bb
        # 2) detect cases like call-pop and dependent instructions (which should not be moved)
        # get movable_instructions in the bb
        original_bbcode = block.bytes
        instructions = utils.decompile(original_bbcode, block.addr)

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

    def compile_moved_injected_code(self, classified_instructions, patch_code):
        # create injected_code (pre, injected, culprit, post, jmp_back)
        injected_code = ""
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
                jmp_back_target = i.address+len(str(i.bytes))
                break
        assert jmp_back_target is not None
        injected_code += "jmp %s" % hex(int(jmp_back_target)) + "\n"
        # removing blank lines
        injected_code = "\n".join([line for line in injected_code.split("\n") if line != ""])
        l.debug("injected code:\n%s", injected_code)

        compiled_code = utils.compile_asm(injected_code, base=self.get_current_code_position(), name_map=self.name_map)
        return compiled_code

    def insert_detour(self, patch):
        block_addr = self.get_block_containing_inst(patch.addr)
        block = self.project.factory.block(block_addr)

        l.debug("inserting detour for patch: %s" % (map(hex, (block_addr, block.size, patch.addr))))

        detour_size = 5
        one_byte_nop = '\x90'

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
                self.patch_bin(i.address, one_byte_nop*len(i.bytes))

        # insert the jump detour
        detour_jmp_code = utils.compile_jmp(detour_pos, self.get_current_code_position())
        self.patch_bin(detour_pos, detour_jmp_code)
        patched_bbcode = self.read_mem_from_file(block_addr, block.size)
        patched_bbinstructions = utils.decompile(patched_bbcode, block_addr)
        l.debug("patched bb instructions:\n %s",
                "\n".join([utils.instruction_to_str(i) for i in patched_bbinstructions]))

        new_code = self.compile_moved_injected_code(movable_instructions, patch.code)

        return new_code

    def get_final_content(self):
        return self.ncontent

    def save(self, filename=None):
        if filename is None:
            filename = self.filename + "_patched"

        final_content = self.get_final_content()
        with open(filename, "wb") as f:
            f.write(final_content)

        os.chmod(filename, 0755)
