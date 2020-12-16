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
    self.pa_base: The physical address of the first segment; It assumes that the first segment includes .text section
    self.pa_new_segment: The physical address of newly created segment
    self.new_phdr: Newly created program header describing new segment
    self.new_shdr: Newly created section header describing new section
    self.new_shdr_offset: The offset of self.ncontents pointing self.new_shdr
    self.new_phdr_offset: The offset of self.ncontents pointing self.new_phdr
    """
    def __init__(self, filename: str, base_address: int, **argv):
        self.f = open(filename, 'rb')
        
        self.ncontents = self.f.read()
        self.ocontents = self.f.read()
        self.elf_file = ELFFile(self.f)

        self.filename = filename
        self.base_address = base_address
        self.has_new_section = False
        self.pa_base = self.elf_file.get_segment(0).header['p_paddr']
        self.pa_new_segment = self.__find_segment_pa()
        self.new_phdr = None
        self.new_shdr = None
        self.new_shdr_offset = None
        self.new_phdr_offset = None

        l.warn("V850 backend does not work properly when you try to detour jump instructions")
        l.warn("V850 backend have not been tested on real board, or simulator")
    
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
            
    def __find_segment_pa(self):
        """
        This function assume that all segments will be loaded on the same base of physical address
        """

        pa = self.pa_base

        for i in range(self.elf_file.header['e_phnum']):
            phdr = self.elf_file.get_segment(i).header
            pa += phdr['p_filesz']

        return pa

    def __generate_trampolin_area(self, trampolin_code_length: int = 200) -> None:
        """
        generate section, section header, segment, segment header,
        modify elf header for trampolin code
        =============================
        |                           |
        |        original ELF       |
        |                           |
        =============================    <- original EOF; new offset of section header table (ELF header modified)
        |                           |
        |           copied          |
        |   section header table    |
        |                           |
        -----------------------------
        |                           |
        |   new section header      |
        |                           |
        -----------------------------   <- new offset of program header table (ELF header modified)
        |                           |
        |           copied          |
        |   program header table    |
        |                           |
        -----------------------------
        |                           |
        |   new program header      |
        |                           |
        -----------------------------   <- pointed by new program header
        |                           |
        |        new segment        |
        |                           |
        |           ----------------|   <- described by new section header
        |           |  new section  |
        =============================
        """
        if self.has_new_section is True:
            return

        header = copy.deepcopy(self.elf_file.header)

        shdt_offset = len(self.ncontents)
        self.new_shdr_offset = shdt_offset + header['e_shentsize'] * header['e_shnum']

        s_text = None
        for i in range(self.elf_file.num_sections()):
            temp = self.elf_file.get_section(i)
            if temp.name == '.text':
                self.new_shdr = copy.deepcopy(temp.header)
                s_text = temp
            self.ncontents = bytes_overwrite(self.ncontents, self.elf_file.structs.Elf_Shdr.build(temp.header))

        self.new_shdr['sh_size'] = trampolin_code_length
        self.new_shdr['sh_offset'] = self.new_shdr_offset + header['e_shentsize'] + header['e_phentsize'] * (header['e_phnum'] + 1)

        self.ncontents = bytes_overwrite(self.ncontents, self.elf_file.structs.Elf_Shdr.build(self.new_shdr))

        phdt_offset = len(self.ncontents)
        self.new_phdr_offset = len(self.ncontents) + header['e_phentsize'] * header['e_phnum']

        p_text = None
        for i in range(self.elf_file.num_segments()):
            temp = self.elf_file.get_segment(i)
            if temp.section_in_segment(s_text):
                self.new_phdr = temp.header
                self.p_vaddr_text = temp.header['p_vaddr']
                self.p_offset_text = temp.header['p_offset']
                p_text = temp
            self.ncontents = bytes_overwrite(self.ncontents, self.elf_file.structs.Elf_Phdr.build(temp.header))

        self.new_phdr['p_paddr'] = self.pa_new_segment
        self.new_phdr['p_vaddr'] = self.new_shdr['sh_addr']
        self.new_phdr['p_memsz'] = trampolin_code_length
        self.new_phdr['p_filesz'] = trampolin_code_length
        self.new_phdr['p_offset'] = self.new_shdr['sh_offset']
        self.ncontents = bytes_overwrite(self.ncontents, self.elf_file.structs.Elf_Phdr.build(self.new_phdr))

        self.new_shdr['sh_addr'] = p_text.header['p_vaddr']
        self.new_shdr['sh_addr'] += (self.pa_new_segment - self.pa_base)
        self.ncontents = bytes_overwrite(self.ncontents, self.elf_file.structs.Elf_Shdr.build(self.new_shdr), self.new_shdr_offset)


        header['e_shoff'] = shdt_offset
        header['e_phoff'] = phdt_offset
        header['e_phnum'] += 1
        header['e_shnum'] += 1

        self.trampolin_code_position = 0
        self.ncontents = bytes_overwrite(self.ncontents, self.elf_file.structs.Elf_Ehdr.build(header), 0)

        
        self.sh_offset_trampolin = self.new_shdr['sh_offset']
        self.sh_addr_trampolin = self.new_shdr['sh_addr']

        self.has_new_section = True

    def __update_section(self) -> None:
        """
        update already generated section header
        """
        org_size = self.new_shdr['sh_size']

        self.new_phdr['p_filesz'] = self.new_phdr['p_filesz'] + self.trampolin_code_position - org_size
        self.new_phdr['p_memsz'] = self.new_phdr['p_memsz'] + self.trampolin_code_position - org_size
        self.new_shdr['sh_size'] = self.trampolin_code_position

        #print(ph_update.header.values)
        self.ncontents = bytes_overwrite(self.ncontents, self.elf_file.structs.Elf_Shdr.build(self.new_shdr), self.new_shdr_offset)
        self.ncontents = bytes_overwrite(self.ncontents, self.elf_file.structs.Elf_Phdr.build(self.new_phdr), self.new_phdr_offset)


    def __apply_insert_code_patch(self, patch: InsertCodePatch) -> None:
        """
        1. Generate new section for trampolin code
        2. Generate trampolin code from patch(user input)
        3. Write ncontents
        """
        # hardcodded
        self.__generate_trampolin_area()

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

        #TODO: Handle edge case: when head or tail instruction is PC-relative(e.g., JR, JARL, Bcond)
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
    def is_2byte(opcode: bytes) -> bool:
        """
        Takes second byte of opcode, returns true if it is 2-bytes length opcode
        """
        mask = 0x07
        result = mask & opcode
        return result < 6
    
    @staticmethod
    def is_4byte(opcode: bytes) -> bool:
        """
        Takes second byte of opcode, returns true if it is 4-bytes length opcode
        """
        return not V850Utils.is_2byte(opcode)

    @staticmethod
    def insert_bytes(target: bytearray, offset: int, code: bytearray) -> bytearray:
        """
        Inserts 'code' into 'target' at 'offeset', returns it
        """
        b = bytearray(target)
        c = b[:offset] + code + b[offset + len(code):]
        return c