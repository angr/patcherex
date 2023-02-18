import bisect
import logging
import os
import re
import angr
import archinfo
from collections import defaultdict
import tempfile

import cle
from elftools.elf.elffile import ELFFile
from patcherex import utils
from patcherex.backends.detourbackends._elf import DetourBackendElf, l
from patcherex.backends.detourbackends.ppc import DetourBackendPpc
from patcherex.backends.detourbackends._utils import (AttrDict,
    DetourException, DoubleDetourException, DuplicateLabelsException,
    IncompatiblePatchesException, MissingBlockException)
from patcherex.patches import (AddCodePatch, AddEntryPointPatch, AddLabelPatch,
                               AddRODataPatch, AddRWDataPatch,
                               AddRWInitDataPatch, AddSegmentHeaderPatch,
                               InlinePatch, InsertCodePatch, InsertFunctionPatch,
                               RawFilePatch, RawMemPatch, RemoveInstructionPatch,
                               ReplaceFunctionPatch, SegmentHeaderPatch)
from patcherex.utils import CLangException, ObjcopyException

l = logging.getLogger("patcherex.backends.DetourBackend")

class DetourBackendPpcVle(DetourBackendPpc):
    def __init__(self, filename, base_address=None, try_reuse_unused_space=False, replace_note_segment=False, try_without_cfg=False, use_pickle=False):
        self.filename = filename
        arch = archinfo.ArchPcode("PowerPC:BE:32:e200")
        self.project = angr.Project(filename, arch=arch, auto_load_libs=False, engine=angr.engines.UberEnginePcode)
        self._identifer = None
        with open(filename, "rb") as f:
            self.ocontent = f.read()

        if try_reuse_unused_space:
            raise NotImplementedError()
        super().__init__(filename, base_address=base_address, replace_note_segment=replace_note_segment, try_without_cfg=try_without_cfg, use_pickle=use_pickle, skip_super_init=True)
        self.added_code_segment = 0xf00000
        self.added_data_segment = 0xe00000
        self.name_map.update(ADDED_DATA_START = (len(self.ncontent) % 0x1000) + self.added_data_segment)

    def compile_asm(self, code, base=None, name_map=None, is_thumb=False):
        try:
            if name_map is not None:
                code = code.format(**name_map)  # compile_asm
            else:
                code = re.subn(r'{.*?}', "0x41414141", code)[0]  # solve symbols
        except KeyError as e:
            raise UndefinedSymbolException(str(e)) from e

        # use `as` to assemble the code
        with utils.tempdir() as td:
            with open(os.path.join(td, "code.s"), "w") as f:
                f.write(code)
                print(code)
            res = utils.exec_cmd("/home/han/misc/powerpc-eabivle-4_9/bin/powerpc-eabivle-as -mvle -o %s.o %s" % (os.path.join(td, "code"), os.path.join(td, "code.s")), shell=True)
            if res[2] != 0:
                raise Exception(f"powerpc-eabivle-as:\n{str(res[0] + res[1], 'utf-8')}")
            res = utils.exec_cmd("/home/han/misc/powerpc-eabivle-4_9/bin/powerpc-eabivle-objcopy -O binary -j .text %s.o %s.bin" % (os.path.join(td, "code"), os.path.join(td, "code")), shell=True)
            if res[2] != 0:
                raise Exception(f"powerpc-eabivle-objcopy:\n{str(res[0] + res[1], 'utf-8')}")
            with open(os.path.join(td, "code.bin"), "rb") as f:
                return f.read()

    def disassemble(self, code, offset=0x0, is_thumb=False):
        if isinstance(code, str):
            code = bytes(map(ord, code))
        with utils.tempdir() as td:
            with open(os.path.join(td, "code.bin"), "wb") as f:
                f.write(code)

            res = utils.exec_cmd("/home/han/misc/powerpc-eabivle-4_9/bin/powerpc-eabivle-objdump -D -b binary -m powerpc:vle -EB %s.bin | tail +8" % (os.path.join(td, "code")), shell=True)
            if res[2] != 0:
                raise Exception(f"powerpc-eabivle-objdump:\n{str(res[0] + res[1], 'utf-8')}")
            str_result = res[0].decode("utf-8")

        result = []
        for line in str_result.splitlines():
            m = re.match(r"\s+(?P<address>[0-9a-f]+):\s+(?P<bytes>([0-9a-f]{2}\s)+)\s+(?P<mnemonic>.+?)\s+(?P<op_str>.+?)$", line)
            if m:
                instr = AttrDict(m.groupdict())
                instr['address'] = int(instr['address'], 16) + offset
                instr['bytes'] = bytes.fromhex(instr['bytes'])
                instr['mnemonic'] = re.sub(r'\s+','', instr['mnemonic'])
                instr['op_str'] = re.sub(r'\s+','', instr['op_str'].split(";")[0]).replace(",", ", ")
                result.append(instr)
        return result

    def compile_jmp(self, origin, target):
        jmp_str = '''
            e_b {target}
        '''.format(**{'target': hex(int(target))})
        return self.compile_asm(jmp_str, base=origin)

    @staticmethod
    def compile_function(code, compiler_flags="", bits=32, little_endian=False, entry=0x0, symbols=None, data_only=False, prefix=""):
        with utils.tempdir() as td:
            c_fname = os.path.join(td, "code.c")
            object_fname = os.path.join(td, "code.o")
            object2_fname = os.path.join(td, "code.2.o")
            linker_script_fname = os.path.join(td, "code.lds")
            data_fname = os.path.join(td, "data")
            rodata_sec_index = rodata_sym_index_old = rodata_sym_index_new = -1

            # C -> Object File
            with open(c_fname, 'w') as fp:
                fp.write(code)
            res = utils.exec_cmd("/home/han/misc/powerpc-eabivle-4_9/bin/powerpc-eabivle-gcc -o %s -c %s %s" % (object_fname, c_fname, compiler_flags), shell=True)
            if res[2] != 0:
                raise Exception("GCC error: " + str(res[0] + res[1], 'utf-8'))

            # Setup Linker Script
            linker_script = "SECTIONS { .text : { *(.text) "
            if symbols:
                for i in symbols:
                    if i == ".rodata":
                        linker_script += i + " = " + hex(symbols[i] - ((entry - 0x10700000) & ~0xFFFF)) + ";"
                    else:
                        linker_script += i + " = " + hex(symbols[i] - entry) + ";"
            linker_script += "} .rodata : { *(.rodata*) } }"
            with open(linker_script_fname, 'w') as fp:
                fp.write(linker_script)

            # Object File --LinkerScript--> Object File
            res = utils.exec_cmd("/home/han/misc/powerpc-eabivle-4_9/bin/powerpc-eabivle-ld -relocatable %s -T %s -o %s" % (object_fname, linker_script_fname, object2_fname), shell=True)
            if res[2] != 0:
                raise Exception("Linking Error: " + str(res[0] + res[1], 'utf-8'))

            # Load Object File
            ld = cle.Loader(object2_fname, main_opts={"base_addr": 0x0}, perform_relocations=False)

            # Figure Out .text Section Size
            for section in ld.all_objects[0].sections:
                    if section.name == ".text":
                        text_section_size = section.filesize
                        break

            # Modify Symbols in Object File to Trick Loader
            with open(object2_fname, "rb+") as f:
                elf = ELFFile(f)

                # Find the Index of .rodata Section
                for i in range(elf.num_sections()):
                    if elf.get_section(i).name == ".rodata":
                        rodata_sec_index = i
                        break

                # Find the Index of the src and dest Symbol
                symtab_section = elf.get_section_by_name(".symtab")
                for i in range(symtab_section.num_symbols()):
                    if symtab_section.get_symbol(i)['st_shndx'] == rodata_sec_index and symtab_section.get_symbol(i)['st_info']['type'] == 'STT_SECTION':
                        rodata_sym_index_old = i
                    if symtab_section.get_symbol(i).name == ".rodata":
                        rodata_sym_index_new = i

                # Rewrite the Symbol
                if rodata_sym_index_new != -1 and rodata_sec_index != -1 and rodata_sym_index_old != -1:
                    for i in range(elf.num_sections()):
                        if elf.get_section(i).header['sh_name'] == symtab_section.header['sh_name']:
                            f.seek(0)
                            content = f.read()
                            f.seek(symtab_section['sh_offset'] + rodata_sym_index_new * symtab_section['sh_entsize'])
                            rodata_sym_new = f.read(symtab_section['sh_entsize'])
                            content = utils.bytes_overwrite(content, rodata_sym_new, symtab_section['sh_offset'] + rodata_sym_index_old * symtab_section['sh_entsize'])
                            f.seek(0)
                            f.write(content)
                            f.truncate()
                            break

                # Replace all R_PPC_PLTREL24 to R_PPC_REL24
                rela_section = elf.get_section_by_name(".rela.text")
                if rela_section is not None:
                    for i in range(rela_section.num_relocations()):
                        if rela_section.get_relocation(i)['r_info_type'] == 18:
                            reloc = rela_section.get_relocation(i).entry
                            reloc['r_info'] -= 8

                            for j in range(elf.num_sections()):
                                if elf.get_section(j).header['sh_name'] == rela_section.header['sh_name']:
                                    f.seek(0)
                                    content = f.read()
                                    content = utils.bytes_overwrite(content, elf.structs.Elf_Rela.build(reloc), rela_section['sh_offset'] + i * rela_section['sh_entsize'])
                                    f.seek(0)
                                    f.write(content)
                                    f.truncate()
                                    break

            # Load the Modified Object File and Return compiled Data or Code
            ld = cle.Loader(object2_fname, main_opts={"base_addr": 0x0, "entry_point": 0x0})
            if data_only:
                patches = []
                for section in ld.all_objects[0].sections:
                    if section.name == ".rodata":
                        res = utils.exec_cmd("/home/han/misc/powerpc-eabivle-4_9/bin/powerpc-eabivle-objcopy -O binary -j %s %s %s" % (section.name, object2_fname, data_fname), shell=True)
                        if res[2] != 0:
                            raise ObjcopyException("Objcopy Error: " + str(res[0] + res[1], 'utf-8'))
                        with open(data_fname, "rb") as fp:
                            patches.append(AddRODataPatch(fp.read(), name=prefix + section.name))
                        break
                return patches
            else:
                compiled = ld.memory.load(ld.all_objects[0].entry, text_section_size)
                return compiled