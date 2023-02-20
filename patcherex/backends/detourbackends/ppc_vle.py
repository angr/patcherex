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

    vle_binutils_path = os.path.realpath(os.path.join(os.path.dirname(__file__), '..', '..', 'binary_dependencies', 'powerpc-eabivle', 'bin'))

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
        self.added_code_segment = 0x840000
        self.added_data_segment = 0x850000
        self.name_map.update(ADDED_DATA_START = (len(self.ncontent) % 0x1000) + self.added_data_segment)


    def dump_sections(self):
        with open(self.filename, "rb") as f:
            elf = ELFFile(f)
            sections = []
            for i in range(elf.num_sections()):
                sec = elf.get_section(i)
                sections.append(sec)
        return sections

    def apply_patches(self, patches):
        super().apply_patches(patches)
        # reuse .debug_info and .debug_abbrev sections for new code and data
        current_Ehdr = self.structs.Elf_Ehdr.parse(self.ncontent)
        self.sections = self.dump_sections()
        for section in enumerate(self.sections):
            if section[1].name == ".debug_info":
                current_Shdr = section[1].header
                current_Shdr['sh_addr'] = self.name_map["ADDED_CODE_START"]
                current_Shdr['sh_offset'] = self.added_code_file_start
                current_Shdr['sh_size'] = len(self.added_code)
                current_Shdr['sh_flags'] |= 0x2
                self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Shdr.build(current_Shdr), current_Ehdr['e_shoff'] + current_Ehdr['e_shentsize'] * section[0])
            if section[1].name == ".debug_abbrev":
                current_Shdr = section[1].header
                current_Shdr['sh_addr'] = self.name_map["ADDED_DATA_START"]
                current_Shdr['sh_flags'] |= 0x2
                current_Shdr['sh_offset'] = self.added_data_file_start
                current_Shdr['sh_size'] = len(self.added_data)
                self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Shdr.build(current_Shdr), current_Ehdr['e_shoff'] + current_Ehdr['e_shentsize'] * section[0])


    def setup_headers(self, segments):
        pass

    def set_added_segment_headers(self):
        pass

    def compile_moved_injected_code_for_insertfunctionpatch(self, classified_instructions, patch, offset=0, is_thumb=False):
        # Prepare pre_code with dummy function address
        pre_code = "\n".join([self.capstone_to_asm(i)
                                    for i in classified_instructions
                                    if i.overwritten == 'pre'])
        pre_code += "\n"
        # store all general purpose registers on the stack
        pre_code += "e_stwu r1, -0x80(r1)\n"
        pre_code += "e_stmw r3, 0x8(r1)\n"

        pre_code += patch.prefunc + "\n"
        pre_code = "\n".join([line for line in pre_code.split("\n") if line != ""])

        # compile pre_code
        pre_code_compiled = self.compile_asm(pre_code,
                                              base=self.get_current_code_position(),
                                              name_map=self.name_map)

        # compile function_call to get the size of it
        fake_function_call = f"e_bl {hex(self.get_current_code_position() + 0x40)}\n"
        fake_function_call_compiled = self.compile_asm(fake_function_call,
                                              base=self.get_current_code_position() + len(pre_code_compiled),
                                              name_map=self.name_map)

        # prepare post code
        post_code = "e_lmw r3, 0x8(r1)\n"
        post_code += "e_addi r1, r1, 0x80\n"
        post_code += "\n".join([self.capstone_to_asm(i)
                                    for i in classified_instructions
                                    if i.overwritten == 'culprit'])
        post_code += "\n"
        post_code += "\n".join([self.capstone_to_asm(i)
                                    for i in classified_instructions
                                    if i.overwritten == 'post'])
        post_code += "\n"
        if "RESTORE_CONTEXT" in patch.postfunc:
            post_code = patch.postfunc.replace("RESTORE_CONTEXT", post_code)
        else:
            post_code = patch.postfunc + "\n" + post_code
        jmp_back_target = None
        for i in reversed(classified_instructions):  # jmp back to the one after the last byte of the last non-out
            if i.overwritten != "out":
                jmp_back_target = i.address+len(i.bytes)
                break
        assert jmp_back_target is not None
        post_code += "e_b %s" % hex(int(jmp_back_target) - offset) + "\n"
        post_code = "\n".join([line for line in post_code.split("\n") if line != ""])

        # compile post_code
        post_code_compiled = self.compile_asm(post_code,
                                              base=self.get_current_code_position() + len(pre_code_compiled) + len(fake_function_call_compiled),
                                              name_map=self.name_map)
        jmp_table_addr = self.get_current_code_position() + len(pre_code_compiled) + len(fake_function_call_compiled)
        jmp_table_instrs = self.disassemble(post_code_compiled, jmp_table_addr)
        exit_edges = []
        for idx in range(len(jmp_table_instrs)):
            instr = jmp_table_instrs[idx]
            if instr.mnemonic.startswith("e_lmw"):
                break
            if instr.mnemonic.startswith("cmp"):
                if idx < len(jmp_table_instrs) - 1 and jmp_table_instrs[idx + 1].mnemonic.startswith("e_b"):
                    next_instr = jmp_table_instrs[idx + 1]
                    last_instr = jmp_table_instrs[idx - 1]
                    ret_val = int(last_instr.op_str.split(",")[1].strip())
                    if ret_val < 0:
                        exit_edges.append([hex(next_instr.address), next_instr.op_str])
        self.patch_info["exit_edges"]["patched"][hex(self.project.kb.functions.floor_func(patch.addr).addr)] = exit_edges

        if (self.get_current_code_position() + len(pre_code_compiled) + len(fake_function_call_compiled) + len(post_code_compiled)) % 4 != 0:
            post_code_compiled += b"\x00"*(4 - (self.get_current_code_position() + len(pre_code_compiled) + len(fake_function_call_compiled) + len(post_code_compiled)) % 4)

        # recompile function call with the correct function address
        function_call = f"e_bl {hex(self.get_current_code_position() + len(pre_code_compiled) + len(fake_function_call_compiled) + len(post_code_compiled))}\n"
        function_call_compiled = self.compile_asm(function_call,
                                              base=self.get_current_code_position() + len(pre_code_compiled),
                                              name_map=self.name_map)

        # compile the function itslef
        patch_info_addr = self.get_current_code_position() + len(pre_code_compiled) + len(function_call_compiled) + len(post_code_compiled)
        self.patch_info["cfgfast_options"]["patched"]["function_starts"].append(hex(patch_info_addr))
        self.patch_info["patcherex_added_functions"].append(hex(patch_info_addr))
        func_code_compiled = self.compile_function(patch.func, compiler_flags="-fPIE" if self.project.loader.main_object.pic else "", entry=self.get_current_code_position() + len(pre_code_compiled) + len(function_call_compiled) + len(post_code_compiled), symbols=patch.symbols)
        if len(func_code_compiled) % 4 != 0:
            func_code_compiled += b"\x00"*(4 - len(func_code_compiled) % 4)

        return pre_code_compiled + function_call_compiled + post_code_compiled + func_code_compiled

    def compile_asm(self, code, base=None, name_map=None, is_thumb=False, dummy=False):
        try:
            if name_map is not None:
                code = code.format(**name_map)  # compile_asm
            else:
                code = re.subn(r'{.*?}', "0x41414141", code)[0]  # solve symbols
        except KeyError as e:
            raise UndefinedSymbolException(str(e)) from e

        code = re.subn(r'r(\d+)', r'\1', code)[0]

        if base is not None and not dummy:
            # produce a list of {instr_offset: instr} pairs
            branch_instrs = {}
            instr_count = 0
            for line in code.splitlines():
                line = line.strip()
                if line.startswith(".") or line.startswith("#") or line == "" or line.endswith(":"):
                    continue
                # if line matches "e_b 0x*" or "e_bl 0x*", add it to the branch_instrs dict
                if re.match(r"(e_b|e_bl) 0x[0-9a-fA-F]+", line):
                    branch_instrs[instr_count] = line
                instr_count += 1

            disasms = self.disassemble(self.compile_asm(code, base=base, name_map=name_map, dummy=True), offset=base)

            for i in range(len(disasms)):
                if i in branch_instrs:
                    branch_instrs[i] = branch_instrs[i].split(" ")[0] + " " + hex(int(branch_instrs[i].split(" ")[1], 16) - disasms[i]['address'])

            instr_count = 0
            for line_count, line in enumerate(code.splitlines()):
                if line.startswith(".") or line.startswith("#") or line == "" or line.endswith(":"):
                    continue
                if instr_count in branch_instrs:
                    code = code.splitlines()
                    code[line_count] = branch_instrs[instr_count]
                    code = "\n".join(code)
                instr_count += 1

        # set base address
        if base is not None:
            code = f".org {hex(base)}\n" + code

        # use `as` to assemble the code
        with utils.tempdir() as td:
            with open(os.path.join(td, "code.s"), "w") as f:
                f.write(code)
            res = utils.exec_cmd(f"{os.path.join(DetourBackendPpcVle.vle_binutils_path, 'powerpc-eabivle-as')} -mvle -o {os.path.join(td, 'code')}.o {os.path.join(td, 'code')}.s", shell=True)
            if res[2] != 0:
                raise Exception(f"powerpc-eabivle-as:\n{str(res[0] + res[1], 'utf-8')}")
            res = utils.exec_cmd(f"{os.path.join(DetourBackendPpcVle.vle_binutils_path, 'powerpc-eabivle-objcopy')} -O binary -j .text {os.path.join(td, 'code')}.o {os.path.join(td, 'code')}.bin", shell=True)
            if res[2] != 0:
                raise Exception(f"powerpc-eabivle-objcopy:\n{str(res[0] + res[1], 'utf-8')}")
            with open(os.path.join(td, "code.bin"), "rb") as f:
                if base is not None:
                    f.seek(base)
                result = f.read()
                disasms = self.disassemble(result, base if base is not None else 0x0)
                return result

    def check_if_movable(self, instruction, is_thumb=False):
        def bytes_to_comparable_str(ibytes, offset):
            return " ".join(utils.instruction_to_str(self.disassemble(ibytes, offset)[0]).split()[2:])

        instruction_bytes = instruction.bytes
        pos1 = bytes_to_comparable_str(instruction_bytes, 0x0)
        pos2 = bytes_to_comparable_str(instruction_bytes, 0x840000)
        pos3 = bytes_to_comparable_str(instruction_bytes, 0x1040000)
        return pos1 == pos2 and pos2 == pos3

    def disassemble(self, code, offset=0x0, is_thumb=False):
        if isinstance(code, str):
            code = bytes(map(ord, code))
        with utils.tempdir() as td:
            with open(os.path.join(td, "code.bin"), "wb") as f:
                f.write(code)

            res = utils.exec_cmd(f"{os.path.join(DetourBackendPpcVle.vle_binutils_path, 'powerpc-eabivle-objdump')} -D -b binary --adjust-vma={hex(offset)} -m powerpc:vle -EB {os.path.join(td, 'code')}.bin | tail +8", shell=True)
            if res[2] != 0:
                raise Exception(f"powerpc-eabivle-objdump:\n{str(res[0] + res[1], 'utf-8')}")
            str_result = res[0].decode("utf-8")

        result = []
        for line in str_result.splitlines():
            m = re.match(r"\s+(?P<address>[0-9a-f]+):\s+(?P<bytes>([0-9a-f]{2}\s)+)\s+(?P<mnemonic>.+?)\s+(?P<op_str>.+?)$", line)
            if m:
                instr = AttrDict(m.groupdict())
                instr['address'] = int(instr['address'], 16)
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
                
            res = utils.exec_cmd(f"{os.path.join(DetourBackendPpcVle.vle_binutils_path, 'powerpc-eabivle-gcc')} -o {object_fname} -c {c_fname} {compiler_flags}", shell=True)
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
            res = utils.exec_cmd(f"{os.path.join(DetourBackendPpcVle.vle_binutils_path, 'powerpc-eabivle-ld')} -relocatable {object_fname} -T {linker_script_fname} -o {object2_fname}", shell=True)
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
                        res = utils.exec_cmd(f"{os.path.join(DetourBackendPpcVle.vle_binutils_path, 'powerpc-eabivle-objcopy')} -O binary -j {section.name} {object2_fname} {data_fname}", shell=True)
                        if res[2] != 0:
                            raise ObjcopyException("Objcopy Error: " + str(res[0] + res[1], 'utf-8'))
                        with open(data_fname, "rb") as fp:
                            patches.append(AddRODataPatch(fp.read(), name=prefix + section.name))
                        break
                return patches
            else:
                compiled = ld.memory.load(ld.all_objects[0].entry, text_section_size)
                return compiled

    @staticmethod
    def generate_asm_jump_on_return_val(mapping):
        asm = ""
        for ret_val, jmp_addr in mapping.items():
            asm += f"e_li r4, {ret_val}\n"
            asm += f"cmp 0, r3, r4\n"
            asm += f"e_beq _label_{str(ret_val).replace('-', '_')}\n"
        asm += f"RESTORE_CONTEXT\n"
        asm += f"e_b _end\n"
        for ret_val, jmp_addr in mapping.items():
            asm += f"_label_{str(ret_val).replace('-', '_')}:\n"
            asm += f"RESTORE_CONTEXT\n"
            asm += f"e_b {hex(jmp_addr)}\n"
        asm += f"_end:\n"
        return asm
    
    @staticmethod
    def generate_asm_for_arguments(arg_list):
        if len(arg_list) == 0:
            return ""
        if len(arg_list) > 4:
            raise Exception("Currently Patcherex Only Supports Up to 4 Arguments")
        asm = ""
        const_pool = ""
        for arg in arg_list:
            _const_pool = re.search(r"e_b _end\n(.*)_end:", arg, re.DOTALL)
            if _const_pool:
                const_pool += f"{_const_pool.group(1)}\n"


        for i in range(1, len(arg_list)):
            if "e_b _end" in arg_list[i]:
                asm += f"{arg_list[i][:arg_list[i].index('e_b _end')]}\n"
            else:
                asm += f"{arg_list[i]}\n"
            asm += f"se_mr r{i+3}, r3\n"

        if "e_b _end" in arg_list[0]:
            asm += f"{arg_list[0][:arg_list[0].index('e_b _end')]}\n"
        else:
            asm += f"{arg_list[0]}\n"

        if const_pool:
            const_pool_list = const_pool.splitlines()
            const_pool = "\n".join(sorted(set(const_pool_list), key=const_pool_list.index))
            asm += "b _end\n"
            asm += const_pool
            asm += "_end:\n"
        return asm
