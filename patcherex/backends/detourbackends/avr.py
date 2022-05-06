import bisect
import logging
import os
import re
from collections import defaultdict

import cle
from angr_platforms.avr import arch_avr, lift_avr  # pylint: disable=no-name-in-module, import-error, unused-import
from elftools.elf.elffile import ELFFile
from patcherex import utils
from patcherex.backends.detourbackends._elf import DetourBackendElf, l
from patcherex.backends.detourbackends._utils import (AttrDict,
                                                      DetourException,
                                                      DoubleDetourException,
                                                      DuplicateLabelsException,
                                                      MissingBlockException)
from patcherex.patches import (AddCodePatch, AddEntryPointPatch, AddLabelPatch,
                               AddRODataPatch, AddRWDataPatch,
                               AddRWInitDataPatch, AddSegmentHeaderPatch,
                               InlinePatch, InsertCodePatch, RawFilePatch,
                               RawMemPatch, RemoveInstructionPatch,
                               ReplaceFunctionPatch, SegmentHeaderPatch)
from patcherex.utils import (CLangException, ObjcopyException,
                             UndefinedSymbolException)

l = logging.getLogger("patcherex.backends.DetourBackend")


class DetourBackendAVR(DetourBackendElf):
    # =========== WIP =============
    # Designed for ATMega328p, not tested for other chips
    # how do we want to design this to track relocations in the blocks...
    def __init__(self, filename, base_address=None, try_reuse_unused_space=False, replace_note_segment=False, try_without_cfg=False):
        if try_reuse_unused_space:
            raise NotImplementedError()
        if replace_note_segment:
            raise NotImplementedError()
        if try_without_cfg:
            raise NotImplementedError()
        super().__init__(filename, base_address=base_address, replace_note_segment=replace_note_segment, try_without_cfg=try_without_cfg)
        # we don't care about segments, we only care sections
        self.sections = self.dump_sections()
        for section in self.sections:
            if section.name == ".text":
                self.text_section_offset = section['sh_offset']
                self.text_section_addr = section['sh_addr']
                self.text_section_size = section['sh_size']
            elif section.name == ".data":
                self.data_section_offset = section['sh_offset']
                self.data_section_size = section['sh_size']
            elif section.name == ".bss":
                self.bss_section_offset = section['sh_offset']
                self.bss_section_size = section['sh_size']
                self.bss_section_addr = section['sh_addr'] % 0x10000

        assert self.data_section_offset + self.data_section_size == self.bss_section_offset

        self.added_data_file_start = self.bss_section_offset
        self.name_map.force_insert("ADDED_DATA_START", self.bss_section_addr + self.bss_section_size)

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

    def get_block_containing_inst(self, inst_addr):
        index = bisect.bisect_right(self.ordered_nodes, inst_addr) - 1
        node = self.cfg.model.get_any_node(self.ordered_nodes[index], is_syscall=False)
        if inst_addr in node.instruction_addrs:
            return node.addr
        else:
            raise MissingBlockException("Couldn't find a block containing address %#x" % inst_addr)

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
        relevant_patches = [p for p in patches if isinstance(p, (AddCodePatch, InsertCodePatch))]
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
            if isinstance(patch, (ReplaceFunctionPatch, AddEntryPointPatch, AddSegmentHeaderPatch, SegmentHeaderPatch)):
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
                    size = 2
                else:
                    size = patch.ins_size
                self.patch_bin(patch.ins_addr, b"\x00\x00" * int((size + 2 - 1) / 2))
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
        self.name_map.force_insert("ADDED_CODE_START", self.added_code_file_start - (self.text_section_offset - self.text_section_addr))

        # __do_copy_data
        # FIXME: not working properly
        if len(self.added_data) > 0:
            data_start = self.name_map["ADDED_DATA_START"]
            data_end = curr_data_position
            data_load_start = self.name_map["ADDED_CODE_START"] - len(self.added_data)

            data_start_hi8, data_start_lo8 = data_start >> 8, data_start & 0xFF
            data_end_hi8, data_end_lo8 = data_end >> 8, data_end & 0xFF
            data_load_start_hi8, data_load_start_lo8 = data_load_start >> 8, data_load_start & 0xFF

            do_copy_data_code = '''
                ldi r17, %s
                ldi r26, %s
                ldi r27, %s
                ldi r30, %s
                ldi r31, %s
                rjmp +0x16
                lpm r0, z+
                st x+, r0
                cpi r26, %s
                cpc r27, r17
                brne 0x2
            ''' % (hex(data_end_hi8), hex(data_start_lo8), hex(data_start_hi8), hex(data_load_start_lo8), hex(data_load_start_hi8), hex(data_end_lo8))

            # TODO: should not be hardcoded to 0x8c
            # we are assuming that 0x8c is end of orginal __do_copy_data and start of __do_clear_bss
            patches.insert(0, InsertCodePatch(0x8c, code=do_copy_data_code, name="__do_copy_data", priority=1000))

        # 2) AddCodePatch
        # resolving symbols
        current_symbol_pos = self.get_current_code_position()
        for patch in patches:
            if isinstance(patch, AddCodePatch):
                if patch.is_c:
                    code_len = len(self.compile_c(patch.asm_code,
                                                   optimization=patch.optimization,
                                                   compiler_flags=patch.compiler_flags))
                else:
                    code_len = len(self.compile_asm(patch.asm_code, current_symbol_pos))
                if patch.name is not None:
                    self.name_map[patch.name] = current_symbol_pos
                current_symbol_pos += code_len
        # now compile for real
        self.added_code = b""
        for patch in patches:
            if isinstance(patch, AddCodePatch):
                if patch.is_c:
                    new_code = self.compile_c(patch.asm_code,
                                               optimization=patch.optimization,
                                               compiler_flags=patch.compiler_flags)
                else:
                    new_code = self.compile_asm(patch.asm_code, self.name_map)
                self.added_code += new_code
                self.added_patches.append(patch)
                l.info("Added patch: %s", str(patch))

        # 4) InlinePatch
        # we assume the patch never patches the added code
        for patch in patches:
            if isinstance(patch, InlinePatch):
                new_code = self.compile_asm(patch.new_asm, self.name_map)
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

        self.ncontent = self.insert_bytes(self.ncontent, self.added_code, self.added_code_file_start)

        # Modifiy sections if needed
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
                if section.name == ".text":
                    pass
                elif section.name == ".data":
                    current_Shdr['sh_size'] += len(self.added_code) + len(self.added_data)
                    current_Shdr['sh_addr'] = self.text_section_size
                else:
                    current_Shdr['sh_offset'] += len(self.added_code) + len(self.added_data)
                self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Shdr.build(
                    current_Shdr), current_Ehdr['e_shoff'] + current_Ehdr['e_shentsize'] * current_Shdr_index)

    def check_if_movable(self, instruction, is_thumb=False):
        # FIXME: assuming only rjmp, rcall, and br* are not movable
        # but there might be other instructions that cannot be moved
        mnemonic = self.disassemble(instruction.bytes)[0]['mnemonic']
        return mnemonic != "rjmp" and mnemonic != "rcall" and not mnemonic.startswith("br")

    def get_movable_instructions(self, block):
        # TODO there are two improvements here:
        # 1) being able to move the jmp and call at the end of a bb
        # 2) detect cases like call-pop and dependent instructions (which should not be moved)
        # get movable_instructions in the bb
        original_bbcode = block.bytes
        instructions = self.disassemble(original_bbcode, block.addr)

        if self.check_if_movable(instructions[-1]):
            movable_instructions = instructions
        else:
            movable_instructions = instructions[:-1]

        return movable_instructions

    def find_detour_pos(self, block, detour_size, patch_addr):
        # iterates through the instructions to find where the detour can be stored
        movable_instructions = self.get_movable_instructions(block)

        movable_bb_start = movable_instructions[0].address
        movable_bb_size = self.project.factory.block(block.addr, num_inst=len(movable_instructions)).size
        l.debug("movable_bb_size: %d", movable_bb_size)
        l.debug("movable bb instructions:\n%s", "\n".join([utils.instruction_to_str(i) for i in movable_instructions]))

        # find a spot for the detour
        detour_pos = None
        for detour_start in range(patch_addr - detour_size, movable_bb_start + movable_bb_size - detour_size, 2):
            if detour_start in [i.address for i in movable_instructions]:
                detour_pos = detour_start
                break
        if detour_pos is None:
            raise DetourException("No space in bb", hex(block.addr), hex(block.size),
                                  hex(movable_bb_start), hex(movable_bb_size))
        l.debug("detour fits at %s", hex(detour_pos))
        print(hex(detour_pos))
        return detour_pos

    def compile_moved_injected_code(self, classified_instructions, patch_code, offset=0, is_thumb=False):
        # create injected_code (pre, injected, culprit, post, jmp_back)
        injected_code = "_patcherex_begin_patch:\n"
        injected_code += "\n".join([self.capstone_to_asm(i)
                                    for i in classified_instructions
                                    if i.overwritten == 'pre'])
        injected_code += "\n"
        injected_code += patch_code + "\n"
        injected_code += "\n".join([self.capstone_to_asm(i)
                                    for i in classified_instructions
                                    if i.overwritten == 'culprit'])
        injected_code += "\n"
        injected_code += "\n".join([self.capstone_to_asm(i)
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
        compiled_code = self.compile_asm(injected_code, name_map=self.name_map)
        return compiled_code

    def insert_detour(self, patch):
        # TODO allow special case to patch syscall wrapper epilogue
        # (not that important since we do not want to patch epilogue in syscall wrapper)
        block_addr = self.get_block_containing_inst(patch.addr)
        mem = self.read_mem_from_file(block_addr, self.project.factory.block(block_addr).size)
        block = self.project.factory.block(block_addr, byte_string=mem)

        l.debug("inserting detour for patch: %s", (map(hex, (block_addr, block.size, patch.addr))))

        detour_size = 4
        avr_nop = b"\x00\x00"

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
        assert any(i.overwritten != "out" for i in movable_instructions)

        # replace overwritten instructions with nops
        for i in movable_instructions:
            if i.overwritten != "out":
                for b in range(i.address, i.address+len(i.bytes)):
                    if b in self.touched_bytes:
                        raise DoubleDetourException("byte has been already touched: %08x" % b)
                    self.touched_bytes.add(b)
                self.patch_bin(i.address, avr_nop)

        # insert the jump detour
        offset = self.project.loader.main_object.mapped_base if self.project.loader.main_object.pic else 0
        detour_jmp_code = self.compile_jmp(self.get_current_code_position() + offset)
        self.patch_bin(detour_pos, detour_jmp_code)
        patched_bbcode = self.read_mem_from_file(block_addr, block.size)
        patched_bbinstructions = self.disassemble(patched_bbcode, block_addr)
        l.debug("patched bb instructions:\n %s",
                "\n".join([utils.instruction_to_str(i) for i in patched_bbinstructions]))

        new_code = self.compile_moved_injected_code(movable_instructions, patch.code, offset=offset)

        return new_code

    @staticmethod
    def disassemble(code, offset=0x0): # pylint: disable=arguments-differ
        with utils.tempdir() as td:
            bin_fname = os.path.join(td, "code.bin")

            fp = open(bin_fname, 'wb')
            fp.write(code)
            fp.close()
            res = utils.exec_cmd("avr-objdump -D -b binary -m avr5 %s | tail +8" % (bin_fname), shell=True)
            if res[2] != 0:
                raise Exception("avr-objdump error: " + str(res[0] + res[1], 'utf-8'))
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

    def compile_jmp(self, target):
        jmp_str = '''
            jmp {target}
        '''.format(**{'target': hex(int(target))})
        return self.compile_asm(jmp_str)

    @staticmethod
    def compile_asm(code, name_map=None): # pylint: disable=arguments-differ
        if not code.endswith("\n"): # prevent avr-as warning
            code += "\n"
        try:
            if name_map is not None:
                name_map = {k:hex(v) for (k,v) in name_map.items()}
                code = code.format(**name_map)  # compile_asm
            else:
                code = re.subn(r'{.*?}', "0x41414141", code)[0]  # solve symbols # TODO
        except KeyError as e:
            raise UndefinedSymbolException(str(e)) from e

        with utils.tempdir() as td:
            asm_fname = os.path.join(td, "code.asm")
            object_fname = os.path.join(td, "code.o")
            bin_fname = os.path.join(td, "code.bin")

            fp = open(asm_fname, 'w')
            fp.write(code)
            fp.close()

            res = utils.exec_cmd("avr-as -mmcu=avr5 %s -o %s" % (asm_fname, object_fname), shell=True)
            if res[2] != 0:
                raise Exception("avr-as error: " + str(res[0] + res[1], 'utf-8'))

            res = utils.exec_cmd("objcopy -B i386 -O binary -j .text %s %s" % (object_fname, bin_fname), shell=True)
            if res[2] != 0:
                raise Exception("objcopy error: " + str(res[0] + res[1], 'utf-8'))

            fp = open(bin_fname, "rb")
            compiled = fp.read()
            fp.close()
        return compiled

    @staticmethod
    def get_c_function_wrapper_code(function_symbol):
        wcode = []
        wcode.append("call {%s}" % function_symbol)

        return "\n".join(wcode)

    @staticmethod
    def compile_c(code, optimization='-Oz', compiler_flags=""):
        # TODO symbol support in c code
        with utils.tempdir() as td:
            c_fname = os.path.join(td, "code.c")
            object_fname = os.path.join(td, "code.o")
            bin_fname = os.path.join(td, "code.bin")

            fp = open(c_fname, 'w')
            fp.write(code)
            fp.close()

            res = utils.exec_cmd("clang-10 -nostdlib -mno-sse -target avr -mmcu=atmega328p -ffreestanding %s -o %s -c %s %s" \
                            % (optimization, object_fname, c_fname, compiler_flags), shell=True)
            if res[2] != 0:
                print("CLang error:")
                print(res[0])
                print(res[1])
                fp = open(c_fname, 'r')
                fcontent = fp.read()
                fp.close()
                print("\n".join(["%02d\t%s"%(i+1,j) for i,j in enumerate(fcontent.split("\n"))]))
                raise CLangException
            res = utils.exec_cmd("objcopy -B i386 -O binary -j .text %s %s" % (object_fname, bin_fname), shell=True)
            if res[2] != 0:
                print("objcopy error:")
                print(res[0])
                print(res[1])
                raise ObjcopyException
            fp = open(bin_fname, "rb")
            compiled = fp.read()
            fp.close()
        return compiled

    @staticmethod
    def compile_function(code, compiler_flags="", entry=0x0, symbols=None):
        with utils.tempdir() as td:
            c_fname = os.path.join(td, "code.c")
            object_fname = os.path.join(td, "code.o")
            object2_fname = os.path.join(td, "code.2.o")
            linker_script_fname = os.path.join(td, "code.lds")

            # C -> Object File
            with open(c_fname, 'w') as fp:
                fp.write(code)
            # clang -target avr -mmcu=atmega328p
            res = utils.exec_cmd("avr-gcc -mmcu=atmega328p -o %s -c %s %s" % (object_fname, c_fname, compiler_flags), shell=True)
            if res[2] != 0:
                raise Exception("avr-gcc error: " + str(res[0] + res[1], 'utf-8'))

            # Setup Linker Script
            linker_script = "SECTIONS { .text : { *(.text) "
            if symbols:
                for i in symbols:
                        linker_script += i + " = " + hex(symbols[i] - entry) + ";"
            linker_script += "}}"

            with open(linker_script_fname, 'w') as fp:
                fp.write(linker_script)

            # Object File --LinkerScript--> Object File
            res = utils.exec_cmd("avr-ld -relocatable %s -T %s -o %s" %
                                 (object_fname, linker_script_fname, object2_fname), shell=True)
            if res[2] != 0:
                raise Exception("Linking Error: " + str(res[0] + res[1], 'utf-8'))

            ld = cle.Loader(object2_fname, main_opts={"base_addr": 0x0})
            compiled = ld.memory.load(ld.all_objects[0].entry, 0xFFFFFFFFFFFFFFFF)
        return compiled

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
        cfg = self.project.analyses.CFGFast()
        l.info("... CFG end")

        return cfg
