import logging
import os
from collections import defaultdict

import cle
from elftools.elf.elffile import ELFFile
from patcherex import utils
from patcherex.backends.detourbackends._utils import (DetourException,
                                                      DoubleDetourException,
                                                      DuplicateLabelsException,
                                                      MissingBlockException)
from patcherex.backends.detourbackends.arm import DetourBackendArm, l
from patcherex.patches import (AddCodePatch, AddEntryPointPatch, AddLabelPatch,
                               AddRODataPatch, AddRWDataPatch,
                               AddRWInitDataPatch, AddSegmentHeaderPatch,
                               InlinePatch, InsertCodePatch, RawFilePatch,
                               RawMemPatch, RemoveInstructionPatch,
                               ReplaceFunctionPatch, SegmentHeaderPatch)
from patcherex.utils import CLangException

l = logging.getLogger("patcherex.backends.DetourBackend")

class DetourBackendArmStm32(DetourBackendArm):
    # =========== WIP =============
    # Not yet tested, designed for Nucleo-32 board
    def __init__(self, filename, base_address=None, try_reuse_unused_space=False, replace_note_segment=False, try_without_cfg=False):
        if try_reuse_unused_space:
            raise NotImplementedError()
        if try_without_cfg:
            raise NotImplementedError()
        super().__init__(filename, base_address=base_address, replace_note_segment=replace_note_segment, try_without_cfg=try_without_cfg)
        self.name_map.force_insert("ADDED_DATA_START", self.modded_segments[1]['p_paddr'] + self.modded_segments[1]['p_filesz'])
        self.added_data_file_start = self.modded_segments[1]['p_offset'] + self.modded_segments[1]['p_filesz']
        self.sections = self.dump_sections()

    def dump_sections(self):
        with open(self.filename, "rb") as f:
            elf = ELFFile(f)
            sections = []
            for i in range(elf.num_sections()):
                sec = elf.get_section(i)
                sections.append(sec)
        return sections

    @staticmethod
    def insert_bytes(original_content, new_content, pos):
        return original_content[:pos] + new_content + original_content[pos:]

    def get_current_code_position(self):
        return self.name_map["ADDED_CODE_START"] + len(self.added_code)

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
        for patch in patches:
            if isinstance(patch, AddLabelPatch):
                self.name_map[patch.name] = patch.addr

        # check for duplicate labels, it is not very necessary for this backend
        # but it is better to behave in the same way of the reassembler backend
        relevant_patches = [p for p in patches if (isinstance(p, (AddCodePatch, InsertCodePatch)))]
        all_code = ""
        for p in relevant_patches:
            if isinstance(p, InsertCodePatch):
                code = p.code
            else:
                code = p.asm_code
            all_code += "\n" + code + "\n"
        labels = utils.string_to_labels(all_code)
        duplicates = set(x for x in labels if labels.count(x) > 1)
        if len(duplicates) > 1:
            raise DuplicateLabelsException("found duplicate assembly labels: %s" % (str(duplicates)))

        for patch in patches:
            if isinstance(patch, (AddEntryPointPatch, AddSegmentHeaderPatch, SegmentHeaderPatch)):
                raise NotImplementedError()

        # 0) RawPatch:
        for patch in patches:
            if isinstance(patch, RawFilePatch):
                self.ncontent = utils.bytes_overwrite(self.ncontent, patch.data, patch.file_addr)
                self.added_patches.append(patch)
                l.info("Added patch: %s", str(patch))
        for patch in patches:
            if isinstance(patch, RawMemPatch):
                self.patch_bin(patch.addr,patch.data)
                self.added_patches.append(patch)
                l.info("Added patch: %s", str(patch))

        for patch in patches:
            if isinstance(patch, RemoveInstructionPatch):
                if patch.ins_size is None:
                    ins = self.read_mem_from_file(patch.ins_addr, 4)
                    size = self.disassemble(ins, 0, is_thumb=self.check_if_thumb(patch.ins_addr))[0].size
                else:
                    size = patch.ins_size
                self.patch_bin(patch.ins_addr, b"\x00\xbf" * int((size + 2 - 1) / 2) if self.check_if_thumb(patch.ins_addr) else b"\x00\xF0\x20\xE3" * int((size + 4 - 1) / 4))
                self.added_patches.append(patch)
                l.info("Added patch: %s", str(patch))

        # 1) Add{RO/RW/RWInit}DataPatch
        curr_data_position = self.name_map["ADDED_DATA_START"]
        for patch in patches:
            if isinstance(patch, (AddRWDataPatch, AddRODataPatch, AddRWInitDataPatch)):
                if hasattr(patch, "data"):
                    final_patch_data = patch.data
                else:
                    final_patch_data = b"\x00" * patch.len
                self.added_data += final_patch_data
                if patch.name is not None:
                    self.name_map[patch.name] = curr_data_position
                curr_data_position += len(final_patch_data)
                self.added_patches.append(patch)
                l.info("Added patch: %s", str(patch))

        if ((len(self.added_data) + self.added_data_file_start) % 2 == 1):
            self.added_data += b"\x00"
        self.ncontent = self.insert_bytes(self.ncontent, self.added_data, self.added_data_file_start)

        self.added_code_file_start = self.added_data_file_start + len(self.added_data)
        self.name_map.force_insert("ADDED_CODE_START", self.name_map['ADDED_DATA_START'] + len(self.added_data))

        # 2) AddCodePatch
        # resolving symbols
        current_symbol_pos = self.get_current_code_position()
        for patch in patches:
            if isinstance(patch, AddCodePatch):
                if patch.is_c:
                    code_len = len(self.compile_c(patch.asm_code,
                                                   optimization=patch.optimization,
                                                   compiler_flags=patch.compiler_flags,
                                                   is_thumb=patch.is_thumb))
                else:
                    code_len = len(self.compile_asm(patch.asm_code,
                                                                 current_symbol_pos,
                                                                 is_thumb=patch.is_thumb))
                if patch.name is not None:
                    self.name_map[patch.name] = current_symbol_pos
                current_symbol_pos += code_len
        # now compile for real
        for patch in patches:
            if isinstance(patch, AddCodePatch):
                if patch.is_c:
                    new_code = self.compile_c(patch.asm_code,
                                               optimization=patch.optimization,
                                               compiler_flags=patch.compiler_flags,
                                               is_thumb=patch.is_thumb)
                else:
                    new_code = self.compile_asm(patch.asm_code,
                                                 self.get_current_code_position(),
                                                 self.name_map,
                                                 is_thumb=patch.is_thumb)
                self.added_code += new_code
                self.added_patches.append(patch)
                l.info("Added patch: %s", str(patch))

        # 4) InlinePatch
        # we assume the patch never patches the added code
        for patch in patches:
            if isinstance(patch, InlinePatch):
                new_code = self.compile_asm(patch.new_asm,
                                                patch.instruction_addr,
                                                self.name_map,
                                                is_thumb=self.check_if_thumb(patch.instruction_addr))
                # Limiting the inline patch to a single block is not necessary
                # assert len(new_code) <= self.project.factory.block(patch.instruction_addr, num_inst=patch.num_instr, max_size=).size
                file_offset = self.project.loader.main_object.addr_to_offset(patch.instruction_addr)
                self.ncontent = utils.bytes_overwrite(self.ncontent, new_code, file_offset)
                self.added_patches.append(patch)
                l.info("Added patch: %s", str(patch))

        # 5) InsertCodePatch
        # these patches specify an address in some basic block, In general we will move the basic block
        # and fix relative offsets
        # With this backend heer we can fail applying a patch, in case, resolve dependencies
        insert_code_patches = [p for p in patches if isinstance(p, InsertCodePatch)]
        insert_code_patches = sorted(insert_code_patches, key=lambda x:-1*x.priority)
        applied_patches = []
        while True:
            name_list = [str(p) if (p is None or p.name is None) else p.name for p in applied_patches]
            l.info("applied_patches is: |%s|", "-".join(name_list))
            assert all(a == b for a, b in zip(applied_patches, insert_code_patches))
            for patch in insert_code_patches[len(applied_patches):]:
                self.save_state(applied_patches)
                try:
                    l.info("Trying to add patch: %s", str(patch))
                    if patch.name is not None:
                        self.name_map[patch.name] = self.get_current_code_position()
                    new_code = self.insert_detour(patch)
                    self.added_code += new_code
                    applied_patches.append(patch)
                    self.added_patches.append(patch)
                    l.info("Added patch: %s", str(patch))
                except (DetourException, MissingBlockException, DoubleDetourException) as e:
                    l.warning(e)
                    insert_code_patches, removed = self.handle_remove_patch(insert_code_patches,patch)
                    #print map(str,removed)
                    applied_patches = self.restore_state(applied_patches, removed)
                    l.warning("One patch failed, rolling back InsertCodePatch patches. Failed patch: %s", str(patch))
                    break
                    # TODO: right now rollback goes back to 0 patches, we may want to go back less
                    # the solution is to save touched_bytes and ncontent indexed by applied patfch
                    # and go back to the biggest compatible list of patches
            else:
                break #at this point we applied everything in current insert_code_patches
                # TODO symbol name, for now no name_map for InsertCode patches

        # 5.5) ReplaceFunctionPatch
        for patch in patches:
            if isinstance(patch, ReplaceFunctionPatch):
                l.warning("ReplaceFunctionPatch: ARM/Thumb interworking is not yet supported.")
                is_thumb = self.check_if_thumb(patch.addr)
                patch.addr = patch.addr - (patch.addr % 2)
                new_code = self.compile_function(patch.asm_code, compiler_flags="-fPIE" if self.project.loader.main_object.pic else "", is_thumb=is_thumb, entry=patch.addr, symbols=patch.symbols)
                file_offset = self.project.loader.main_object.addr_to_offset(patch.addr)
                self.ncontent = utils.bytes_overwrite(self.ncontent, (b"\x00\xBF" * (patch.size // 2)) if is_thumb else (b"\x00\xF0\x20\xE3" * (patch.size // 4)), file_offset)
                if(patch.size >= len(new_code)):
                    file_offset = self.project.loader.main_object.addr_to_offset(patch.addr)
                    self.ncontent = utils.bytes_overwrite(self.ncontent, new_code, file_offset)
                else:
                    detour_pos = self.get_current_code_position()
                    offset = self.project.loader.main_object.mapped_base if self.project.loader.main_object.pic else 0
                    new_code = self.compile_function(patch.asm_code, compiler_flags="-fPIE" if self.project.loader.main_object.pic else "", is_thumb=is_thumb, entry=detour_pos + offset, symbols=patch.symbols)
                    self.added_code += new_code
                    # compile jmp
                    jmp_code = self.compile_jmp(patch.addr, detour_pos + offset, is_thumb=is_thumb)
                    self.patch_bin(patch.addr, jmp_code)
                self.added_patches.append(patch)
                l.info("Added patch: %s", str(patch))

        self.ncontent = self.insert_bytes(self.ncontent, self.added_code, self.added_code_file_start)

        # Modifiy sections and 3rd LOAD segment if needed
        if (len(self.added_data) + len(self.added_code) > 0):
            # update ELF header
            current_Ehdr = self.structs.Elf_Ehdr.parse(self.ncontent)
            current_Ehdr['e_shoff'] += len(self.added_code) + len(self.added_data)
            self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Ehdr.build(current_Ehdr), 0)
            # update section headers
            current_Shdr_index = -1
            for section in self.sections:
                current_Shdr_index += 1
                current_Shdr = section.header
                if current_Shdr['sh_offset'] >= self.added_data_file_start:
                    current_Shdr['sh_offset'] += len(self.added_code) + len(self.added_data)
                elif section.name == ".data":
                    current_Shdr['sh_size'] += len(self.added_code) + len(self.added_data)
                else:
                    pass
                self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Shdr.build(current_Shdr), current_Ehdr['e_shoff'] + current_Ehdr['e_shentsize'] * current_Shdr_index)
            # update 2nd & 3rd segment header
            current_Phdr = self.modded_segments[1]
            current_Phdr['p_filesz'] += len(self.added_code) + len(self.added_data)
            current_Phdr['p_memsz'] += len(self.added_code) + len(self.added_data)
            self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Phdr.build(current_Phdr), current_Ehdr['e_phoff'] + current_Ehdr['e_phentsize'] * 1)

            current_Phdr = self.modded_segments[2]
            current_Phdr['p_offset'] += len(self.added_code) + len(self.added_data)
            current_Phdr['p_vaddr'] += len(self.added_code) + len(self.added_data)
            current_Phdr['p_paddr'] += len(self.added_code) + len(self.added_data)
            self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Phdr.build(current_Phdr), current_Ehdr['e_phoff'] + current_Ehdr['e_phentsize'] * 2)

    def compile_jmp(self, origin, target, is_thumb=False):
        # I don't know why but "b target" simply won't work, so I use "bl target" instead
        jmp_str = '''
            push {{lr}}
            bl %s
            pop {{pc}}
        ''' % hex(target)
        print(hex(origin))
        return self.compile_asm(jmp_str, base=origin, name_map=self.name_map,is_thumb=is_thumb)

    @staticmethod
    def compile_function(code, compiler_flags="", is_thumb=False, entry=0x0, symbols=None):
        with utils.tempdir() as td:
            c_fname = os.path.join(td, "code.c")
            object_fname = os.path.join(td, "code.o")
            object2_fname = os.path.join(td, "code.2.o")
            linker_script_fname = os.path.join(td, "code.lds")

            with open(c_fname, 'w') as fp:
                fp.write(code)

            linker_script = "SECTIONS { .text : { *(.text) "
            if symbols:
                for i in symbols:
                    linker_script += i + " = " + hex(symbols[i] - entry) + ";"
            linker_script += "}}"

            with open(linker_script_fname, 'w') as fp:
                fp.write(linker_script)

            res = utils.exec_cmd("clang -target arm-none-eabi -Os -mcpu=cortex-m0 -o %s -c %s %s %s" \
                            % (object_fname, c_fname, compiler_flags, "-mthumb" if is_thumb else "-mno-thumb"), shell=True)
            if res[2] != 0:
                raise CLangException("CLang error: " + str(res[0] + res[1], 'utf-8'))

            res = utils.exec_cmd("ld.lld -relocatable %s -T %s -o %s" % (object_fname, linker_script_fname, object2_fname), shell=True)
            if res[2] != 0:
                raise Exception("Linking Error: " + str(res[0] + res[1], 'utf-8'))

            ld = cle.Loader(object2_fname, main_opts={"base_addr": 0x0})
            compiled = ld.memory.load(ld.all_objects[0].entry, 0xFFFFFFFFFFFFFFFF)
        return compiled
