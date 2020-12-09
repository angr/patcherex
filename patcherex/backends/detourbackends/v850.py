import bisect
import logging
import os
import re
import struct
from typing import List
from collections import defaultdict

import cle
from patcherex import utils
from patcherex.backends.detourbackends._elf import DetourBackendElf, l
from patcherex.backends.detourbackends._utils import (
    DetourException, DoubleDetourException, DuplicateLabelsException,
    IncompatiblePatchesException, MissingBlockException)
from patcherex.patches import (AddCodePatch, AddEntryPointPatch, AddLabelPatch,
                               AddRODataPatch, AddRWDataPatch,
                               AddRWInitDataPatch, AddSegmentHeaderPatch,
                               InlinePatch, InsertCodePatch, RawFilePatch,
                               RawMemPatch, RemoveInstructionPatch,
                               ReplaceFunctionPatch, SegmentHeaderPatch,
                               CodePatch)
from patcherex.utils import (CLangException, ObjcopyException,
                             UndefinedSymbolException, bytes_overwrite)
from elftools.elf.elffile import ELFFile
import copy


l = logging.getLogger("patcherex.backends.DetourBackend")

class DetourBackendV850:
    """
    self.ncontents: rewriting target binary
    self.ocontents: original target binary; not used, for naming convention
    self.filename: the original filename of target binary
    self.base_address: where the binary will be loaded
    self.elf_file: pyelf instance of self.ncontents
    self.has_new_section: True if the new section is already added to ncontents
    self.p_vaddr_text: the virtual address where .text section should be loaded 
    self.p_offset_text: the offset of ncontents where .text section is located
    self.sh_offset_trampolin: the offset of ncontents where the new section is located
    self.sh_addr_trampolin: the virtual address where the new section should be located
    self.trampolin_code_position: the offset of sh_offset_trampolin where trampolin code should be located
    self.f: file pointer of the original binary; closed at destructor for pyelf
    self.added_section_header: header of new section
    self.sh_trampolin_index: index of new section
    self.phdr_text: segment header of the segment which includes .text and new section
    self.ph_trampolin_index: index of segment including trampolin section
    """
    def __init__(self, filename: str, base_address: int, **argv):
        self.f = open(filename, 'rb')
        
        self.ncontents = self.f.read()
        self.ocontents = self.f.read()
        self.elf_file = ELFFile(self.f)

        self.filename = filename
        self.base_address = base_address
        self.has_new_section = False
        self.p_vaddr_text = None
        self.p_offset_text = None
        self.sh_offset_trampolin = None
        self.sh_addr_trampolin = None
        self.trampolin_code_position = None
        self.added_section_header = None
        self.phdr_text = None
    
    def __del__(self):
        self.f.close()

    def apply_patches(self, patches: List[CodePatch]) -> None:
        for patch in patches:
            # Currently, only support detour patch
            if isinstance(patch, InsertCodePatch) is not True:
                raise NotImplementedError()

            self.__apply_insert_code_patch(patch)

    def save(self, filename: str=None) -> None:
        if filename is None:
            filename = self.filename + ".patcherex.elf"
        with open(filename, 'wb') as f:
            f.write(self.ncontents)

            
    def __generate_section(self, trampolin_code_length: int = 200) -> None:
        """
        generate section for trampolin code
        new section offset: filesz of file header
        new section size: trampolin_code_length
        """
        if self.has_new_section is True:
            return

        header = self.elf_file.header

        # finding .text and .rodata section
        s_rodata = None
        for i in range(self.elf_file.num_sections()):
            temp = self.elf_file.get_section(i)
            if temp.name == '.text':
                s_text = temp
            elif temp.name == '.data':
                s_rodata = temp
        p_data = None

        # ph_idx_text: the index of program header which contains .text section
        # ph_idx_data: the index of program header which contains .data section
        ph_idx_text, ph_idx_data = 0, 0
        for i in range(header['e_phnum']):
            temp = self.elf_file.get_segment(i)
            if(temp.section_in_segment(s_text)): 
                self.phdr_text = temp.header
                ph_idx_text = i
            elif(temp.section_in_segment(s_rodata)):
                p_data = temp
                ph_idx_data = i

        self.added_section_header = copy.deepcopy(s_text.header)
        self.added_section_header['sh_offset'] = self.phdr_text['p_offset'] + self.phdr_text['p_filesz']
        self.added_section_header['sh_addr'] = self.phdr_text['p_vaddr'] + self.phdr_text['p_memsz']
        self.added_section_header['sh_size'] = trampolin_code_length

        self.ncontents = bytes_overwrite(self.ncontents, self.elf_file.structs.Elf_Shdr.build(self.added_section_header), header['e_shoff'] + header['e_shnum'] * self.elf_file.header['e_shentsize'])
        
        self.phdr_text['p_filesz'] += self.added_section_header['sh_size']
        self.phdr_text['p_memsz'] += self.added_section_header['sh_size']
        self.ncontents = bytes_overwrite(self.ncontents, self.elf_file.structs.Elf_Phdr.build(self.phdr_text), header['e_phoff'] + header['e_phentsize'] * ph_idx_text)

        self.has_new_section = True
        self.p_vaddr_text = self.phdr_text['p_vaddr']
        self.p_offset_text = self.phdr_text['p_offset']
        self.sh_offset_trampolin = self.added_section_header['sh_offset']
        self.sh_addr_trampolin = self.added_section_header['sh_addr']
        self.trampolin_code_position = 0
        self.sh_trampolin_index = header['e_shnum']
        self.ph_trampolin_index = ph_idx_text

        header['e_shnum'] += 1
        self.ncontents = bytes_overwrite(self.ncontents, self.elf_file.structs.Elf_Ehdr.build(header), 0)

    def __update_section(self) -> None:
        """
        update already generated section header
        """
        org_size = self.added_section_header['sh_size']

        self.phdr_text['p_filesz'] = self.phdr_text['p_filesz'] + self.trampolin_code_position - org_size
        self.phdr_text['p_memsz'] = self.phdr_text['p_memsz'] + self.trampolin_code_position - org_size
        self.added_section_header['sh_size'] = self.trampolin_code_position

        #print(ph_update.header.values)
        self.ncontents = bytes_overwrite(self.ncontents, self.elf_file.structs.Elf_Shdr.build(self.added_section_header), self.elf_file.header['e_shoff'] + self.elf_file.header['e_shentsize'] * self.sh_trampolin_index)
        self.ncontents = bytes_overwrite(self.ncontents, self.elf_file.structs.Elf_Phdr.build(self.phdr_text), self.elf_file.header['e_phoff'] + self.elf_file.header['e_phentsize'] * self.ph_trampolin_index)


    def __apply_insert_code_patch(self, patch: InsertCodePatch) -> None:
        """
        1. Generate new section for trampolin code
        2. Generate trampolin code from patch(user input)
        3. Write ncontents
        """
        # hardcodded
        self.__generate_section()

        code = V850Utils.assemble(patch.code)
        jumplength = 4

        """
        V850 instructions are 2-byte length or 4-byte length but jump instruction is 4-byte length
        following if-else is handling the byte-length issue
        """
        # target_offset: offset of ncontents where detour patch will be applied
        target_offset = patch.addr - self.p_vaddr_text + self.p_offset_text

        # Check broken instruction
        assert V850Utils.is_2byte(self.ncontents[target_offset - 1]), "Invalid Address: Broken Instruction"

        original_instruction_tail = b""
        # 4byte
        if V850Utils.is_4byte(self.ncontents[target_offset+1]):
            original_instruction_head = self.ncontents[target_offset:target_offset+4]
        # 2byte
        else:
            if V850Utils.is_4byte(self.ncontents[target_offset + 3]):
                original_instruction_head = self.ncontents[target_offset:target_offset+2]
                original_instruction_tail = self.ncontents[target_offset+2:target_offset+6]
                jumplength = 6
            else:
                original_instruction_head = self.ncontents[target_offset:target_offset+2]
                original_instruction_tail = self.ncontents[target_offset+2:target_offset+4]
        
        # self.trampolin_code_position: virtual address where trampolie code shoule be located
        if jumplength == 6:
            self.ncontents = V850Utils.insert_bytes(self.ncontents, target_offset, V850Utils.jump(self.sh_addr_trampolin + self.trampolin_code_position - patch.addr) + b'\x00\x00')
        else:
            self.ncontents = V850Utils.insert_bytes(self.ncontents, target_offset, V850Utils.jump(self.sh_addr_trampolin + self.trampolin_code_position - patch.addr))

        code = original_instruction_head + code + original_instruction_tail
        backward_jump_size = self.sh_addr_trampolin + self.trampolin_code_position + len(code) - patch.addr - 4
        code = code + V850Utils.jump_back(backward_jump_size)

        # self.sh_offset_trampolin + self.trampolin_code_position: offset of ncontents where patched code should be located
        self.ncontents = bytes_overwrite(self.ncontents, code, self.sh_offset_trampolin + self.trampolin_code_position)
        self.trampolin_code_position += len(code)

        self.__update_section()

# static class
class V850Utils:
    CC = "v850-elf-gcc"
    CC_O = " -c"
    OBJCOPY = "v850-elf-objcopy"
    OBJCOPY_O = " -O binary"

    @staticmethod
    def assemble(code: str) -> bytearray:
        """
        Takes assembly code, returns assembled binary.
        """
        res = b""
        with open("tmp.s", "w") as f:
            f.write(str(code))
        os.system(V850Utils.CC + V850Utils.CC_O + " tmp.s")
        os.system(V850Utils.OBJCOPY + V850Utils.OBJCOPY_O + " tmp.o" + " tmp.bin")
        with open("tmp.bin", "rb") as f:
            res = f.read()
        return res
        
    @staticmethod
    def jump(length: int) -> bytearray:
        """
        Takes pre-calculated PC-relative length, returns a forward jump instruction
        E.g., jump forward, 0x123456-length: \x92\x07\x56\x34

        JR disp22:
        15                            0   31                           16
        0 0 0 0 0 1 1 1 1 0 d d d d d d | d d d d d d d d d d d d d d d 0
        """
        print("jump length: ", hex(length))
        print("0x100078 + length = ", hex(0x100078 + length))
        jmp = 0x7800000
        jmp = jmp + length
        jmp_l = jmp >> 16
        jmp_h = jmp & 0xFFFF
        return jmp_l.to_bytes(2, byteorder="little") + jmp_h.to_bytes(2, byteorder="little")

    @staticmethod
    def jump_back(length: int) -> bytearray:
        """
        Takes pre-calculated PC-relative length, returns a backward jump instruction
        E.g., jump backward, 0x123456-length: \xAD\x07\xCB\xA9
        (2's compliment of 0x123456 is 0x2DCBA9)

        JR disp22:
        15                            0   31                           16
        0 0 0 0 0 1 1 1 1 0 d d d d d d | d d d d d d d d d d d d d d d 0
        """
        print("back jump length: ", length)
        jmp = 0x7800000
        length = (length ^ 0x3FFFFF) + 1
        jmp = jmp + length
        jmp_l = jmp >> 16
        jmp_h = jmp & 0xFFFF
        return jmp_l.to_bytes(2, byteorder="little") + jmp_h.to_bytes(2, byteorder="little")

    @staticmethod
    def insert_bytes(target: bytearray, offset: int, code: bytearray) -> bytearray:
        """
        Inserts 'code' into 'target' at 'offeset', returns it
        """
        b = bytearray(target)
        c = b[:offset] + code + b[offset + len(code):]
        return c