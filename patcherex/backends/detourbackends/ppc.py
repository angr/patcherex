import bisect
import logging
import os
import re
from collections import defaultdict

import cle
from elftools.elf.elffile import ELFFile
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
                               ReplaceFunctionPatch, SegmentHeaderPatch)
from patcherex.utils import CLangException, ObjcopyException

l = logging.getLogger("patcherex.backends.DetourBackend")

class DetourBackendPpc(DetourBackendElf):
    # how do we want to design this to track relocations in the blocks...
    def __init__(self, filename, base_address=None, try_reuse_unused_space=False, replace_note_segment=False, try_without_cfg=False):
        if try_reuse_unused_space:
            raise NotImplementedError()
        super().__init__(filename, base_address=base_address, replace_note_segment=replace_note_segment, try_without_cfg=try_without_cfg)
        self.added_code_segment = 0x10600000
        self.added_data_segment = 0x10700000
        self.name_map.update(ADDED_DATA_START = (len(self.ncontent) % 0x1000) + self.added_data_segment)

    def get_oep(self):
        if self.structs.elfclass == 64 and not self.structs.little_endian:
            current_hdr = self.structs.Elf_Ehdr.parse(self.ncontent)
            return int.from_bytes(self.read_mem_from_file(current_hdr["e_entry"], 8), "big")
        else:
            return super().get_oep()

    def set_oep(self, new_oep):
        if self.structs.elfclass == 64 and not self.structs.little_endian:
            current_hdr = self.structs.Elf_Ehdr.parse(self.ncontent)
            self.patch_bin(current_hdr["e_entry"], b"\x00\x00\x00\x00" + new_oep.to_bytes(4, 'big'))
        else:
            super().set_oep(new_oep)

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
        lpatches = [p for p in patches if (isinstance(p, AddLabelPatch))]
        for p in lpatches:
            self.name_map[p.name] = p.addr

        # check for duplicate labels, it is not very necessary for this backend
        # but it is better to behave in the same way of the reassembler backend
        relevant_patches = [p for p in patches if isinstance(p, (AddCodePatch, AddEntryPointPatch, InsertCodePatch))]
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

        # for now any added code will be executed by jumping out and back ie CGRex
        # apply all add code patches
        self.added_code_file_start = len(self.ncontent)
        self.name_map.force_insert("ADDED_CODE_START",(len(self.ncontent) % 0x1000) + self.added_code_segment)

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
                    size = 4
                else:
                    size = patch.ins_size
                self.patch_bin(patch.ins_addr, b"\x60\x00\x00\x00" * int((size + 4 - 1) / 4))
                self.added_patches.append(patch)
                l.info("Added patch: %s", str(patch))

        # 5.5) ReplaceFunctionPatch (preprocessing rodata)
        for patch in patches:
            if isinstance(patch, ReplaceFunctionPatch):
                patches += self.compile_function(patch.asm_code, entry=patch.addr, symbols=patch.symbols, data_only=True, prefix="_RFP" + str(patches.index(patch)))

        # 1) Add{RO/RW/RWInit}DataPatch
        self.added_data_file_start = len(self.ncontent)
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
                self.ncontent = utils.bytes_overwrite(self.ncontent, final_patch_data)
                self.added_patches.append(patch)
                l.info("Added patch: %s", str(patch))
        self.ncontent = utils.pad_bytes(self.ncontent, 0x10)  # some minimal alignment may be good

        self.added_code_file_start = len(self.ncontent)
        if self.replace_note_segment:
            self.name_map.force_insert("ADDED_CODE_START", int((curr_data_position + 0x10 - 1) / 0x10) * 0x10)
        else:
            self.name_map.force_insert("ADDED_CODE_START", (len(self.ncontent) % 0x1000) + self.added_code_segment)

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
        for patch in patches:
            if isinstance(patch, AddCodePatch):
                if patch.is_c:
                    new_code = self.compile_c(patch.asm_code,
                                               optimization=patch.optimization,
                                               compiler_flags=patch.compiler_flags)
                else:
                    new_code = self.compile_asm(patch.asm_code,
                                                 self.get_current_code_position(),
                                                 self.name_map)
                self.added_code += new_code
                self.ncontent = utils.bytes_overwrite(self.ncontent, new_code)
                self.added_patches.append(patch)
                l.info("Added patch: %s", str(patch))

        # 3) AddEntryPointPatch
        # basically like AddCodePatch but we detour by changing oep
        # and we jump at the end of all of them
        # resolving symbols
        for patch in patches:
            if isinstance(patch, AddEntryPointPatch):
                old_oep = self.get_oep()
                new_oep = self.get_current_code_position()
                # ref: glibc/sysdeps/{ARCH}/start.S
                instructions = patch.asm_code
                instructions += "\nb {}".format(hex(int(old_oep)))

                new_code = self.compile_asm(instructions,
                                             self.get_current_code_position(),
                                             self.name_map)
                self.added_code += new_code
                self.added_patches.append(patch)
                self.ncontent = utils.bytes_overwrite(self.ncontent, new_code)
                self.set_oep(new_oep)
                l.info("Added patch: %s", str(patch))


        # 4) InlinePatch
        # we assume the patch never patches the added code
        for patch in patches:
            if isinstance(patch, InlinePatch):
                new_code = self.compile_asm(patch.new_asm,
                                                patch.instruction_addr,
                                                self.name_map)
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
                    self.ncontent = utils.bytes_overwrite(self.ncontent, new_code)
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

        header_patches = [InsertCodePatch,InlinePatch,AddEntryPointPatch,AddCodePatch, \
                AddRWDataPatch,AddRODataPatch,AddRWInitDataPatch]

        # 5.5) ReplaceFunctionPatch
        for patch in patches:
            if isinstance(patch, ReplaceFunctionPatch):
                if self.structs.elfclass == 64:
                    # reloc type not supported (TOC info is in executables but not in object file, but relocs in object file will need TOC info.)
                    raise Exception("ReplaceFunctionPatch: PPC64 not yet supported")
                for k, v in self.name_map.items():
                    if k.startswith("_RFP" + str(patches.index(patch))):
                        patch.symbols[k[len("_RFP" + str(patches.index(patch))):]] = v
                new_code = self.compile_function(patch.asm_code, bits=self.structs.elfclass, little_endian=self.structs.little_endian, entry=patch.addr, symbols=patch.symbols)
                file_offset = self.project.loader.main_object.addr_to_offset(patch.addr)
                self.ncontent = utils.bytes_overwrite(self.ncontent, b"\x60\x00\x00\x00" * (patch.size // 4), file_offset)
                if(patch.size >= len(new_code)):
                    file_offset = self.project.loader.main_object.addr_to_offset(patch.addr)
                    self.ncontent = utils.bytes_overwrite(self.ncontent, new_code, file_offset)
                else:
                    header_patches.append(ReplaceFunctionPatch)
                    detour_pos = self.get_current_code_position()
                    offset = self.project.loader.main_object.mapped_base if self.project.loader.main_object.pic else 0
                    new_code = self.compile_function(patch.asm_code, bits=self.structs.elfclass, little_endian=self.structs.little_endian, entry=detour_pos + offset, symbols=patch.symbols)
                    self.added_code += new_code
                    self.ncontent = utils.bytes_overwrite(self.ncontent, new_code)
                    # compile jmp
                    jmp_code = self.compile_jmp(patch.addr, detour_pos + offset)
                    self.patch_bin(patch.addr, jmp_code)
                self.added_patches.append(patch)
                l.info("Added patch: %s", str(patch))

        if any(isinstance(p,ins) for ins in header_patches for p in self.added_patches) or \
                any(isinstance(p,SegmentHeaderPatch) for p in patches):
            # either implicitly (because of a patch adding code or data) or explicitly, we need to change segment headers

            # 6) SegmentHeaderPatch
            segment_header_patches = [p for p in patches if isinstance(p,SegmentHeaderPatch)]
            if len(segment_header_patches) > 1:
                msg = "more than one patch tries to change segment headers: %s", "|".join([str(p) for p in segment_header_patches])
                raise IncompatiblePatchesException(msg)
            if len(segment_header_patches) == 1:
                segment_patch = segment_header_patches[0]
                segments = segment_patch.segment_headers
                l.info("Added patch: %s", str(segment_patch))
            else:
                segments = self.modded_segments

            for patch in [p for p in patches if isinstance(p,AddSegmentHeaderPatch)]:
                # add after the first
                segments = [segments[0]] + [patch.new_segment] + segments[1:]

            self.setup_headers(segments)
            self.set_added_segment_headers()
            l.debug("final symbol table: %s", repr([(k,hex(v)) for k,v in self.name_map.items()]))
        else:
            l.info("no patches, the binary will not be touched")

    def check_if_movable(self, instruction, is_thumb=False):
        # the idea here is an instruction is movable if and only if
        # it has the same string representation when moved at different offsets is "movable"
        def bytes_to_comparable_str(ibytes, offset):
            return " ".join(utils.instruction_to_str(self.disassemble(ibytes, offset)[0]).split()[2:])

        instruction_bytes = instruction.bytes
        pos1 = bytes_to_comparable_str(instruction_bytes, 0x0)
        pos2 = bytes_to_comparable_str(instruction_bytes, 0x07f00000)
        pos3 = bytes_to_comparable_str(instruction_bytes, 0xfe000000)
        return pos1 == pos2 and pos2 == pos3

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
        for detour_start in range(movable_bb_start, movable_bb_start + movable_bb_size - detour_size, 4):
            if detour_start in [i.address for i in movable_instructions]:
                detour_pos = detour_start
                break
        if detour_pos is None:
            raise DetourException("No space in bb", hex(block.addr), hex(block.size),
                                  hex(movable_bb_start), hex(movable_bb_size))
        l.debug("detour fits at %s", hex(detour_pos))

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
        injected_code += "b %s" % hex(int(jmp_back_target) - offset) + "\n"
        # removing blank lines
        injected_code = "\n".join([line for line in injected_code.split("\n") if line != ""])
        l.debug("injected code:\n%s", injected_code)

        compiled_code = self.compile_asm(injected_code,
                                              base=self.get_current_code_position(),
                                              name_map=self.name_map)
        return compiled_code

    def insert_detour(self, patch):
        detour_size = 4
        ppc_nop = b"\x60\x00\x00\x00"

        if self.try_without_cfg:
            offset = self.project.loader.main_object.mapped_base if self.project.loader.main_object.pic else 0
            detour_jmp_code = self.compile_jmp(patch.addr, self.get_current_code_position() + offset)
            patched_bbcode = self.read_mem_from_file(patch.addr, detour_size)
            patched_bbinstructions = self.disassemble(patched_bbcode, patch.addr)
            l.debug("patched bb instructions:\n %s",
                    "\n".join([utils.instruction_to_str(i) for i in patched_bbinstructions]))
            self.patch_bin(patch.addr, detour_jmp_code)
            new_code = self.compile_asm(patch.code + "\n" + "\n".join([self.capstone_to_asm(s) for s in patched_bbinstructions]) + "\nb %s" % hex(patch.addr + 4 - offset), base=self.get_current_code_position(), name_map=self.name_map)
            return new_code
        # TODO allow special case to patch syscall wrapper epilogue
        # (not that important since we do not want to patch epilogue in syscall wrapper)
        block_addr = self.get_block_containing_inst(patch.addr)
        mem = self.read_mem_from_file(block_addr, self.project.factory.block(block_addr).size)
        block = self.project.factory.block(block_addr, byte_string=mem)

        l.debug("inserting detour for patch: %s", (map(hex, (block_addr, block.size, patch.addr))))

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
                self.patch_bin(i.address, ppc_nop)

        # insert the jump detour
        offset = self.project.loader.main_object.mapped_base if self.project.loader.main_object.pic else 0
        detour_jmp_code = self.compile_jmp(detour_pos, self.get_current_code_position() + offset)
        self.patch_bin(detour_pos, detour_jmp_code)
        patched_bbcode = self.read_mem_from_file(block_addr, block.size)
        patched_bbinstructions = self.disassemble(patched_bbcode, block_addr)
        l.debug("patched bb instructions:\n %s",
                "\n".join([utils.instruction_to_str(i) for i in patched_bbinstructions]))

        new_code = self.compile_moved_injected_code(movable_instructions, patch.code, offset=offset)

        return new_code

    def compile_asm(self, code, base=None, name_map=None): # pylint: disable=arguments-differ
        code = re.subn(r'\br(\d+)', r"\1", code)[0]  # remvoe "r" before register
        return super().compile_asm(code, base, name_map)

    def compile_jmp(self, origin, target):
        jmp_str = '''
            b {target}
        '''.format(**{'target': hex(int(target))})
        return self.compile_asm(jmp_str, base=origin)

    @staticmethod
    def get_c_function_wrapper_code(function_symbol):
        wcode = []
        wcode.append("bl {%s}" % function_symbol)

        return "\n".join(wcode)

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
            target = ("powerpcle-linux-gnu" if little_endian else "powerpc-linux-gnu") if bits == 32 else ("powerpc64le-linux-gnu" if little_endian else "powerpc64-linux-gnu")
            res = utils.exec_cmd("clang -target %s -o %s -c %s %s" \
                            % (target, object_fname, c_fname, compiler_flags), shell=True)
            if res[2] != 0:
                raise CLangException("CLang error: " + str(res[0] + res[1], 'utf-8'))

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
            res = utils.exec_cmd("ld.lld -relocatable %s -T %s -o %s" % (object_fname, linker_script_fname, object2_fname), shell=True)
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
                        res = utils.exec_cmd("objcopy -B i386 -O binary -j %s %s %s" % (section.name, object2_fname, data_fname), shell=True)
                        if res[2] != 0:
                            raise ObjcopyException("Objcopy Error: " + str(res[0] + res[1], 'utf-8'))
                        with open(data_fname, "rb") as fp:
                            patches.append(AddRODataPatch(fp.read(), name=prefix + section.name))
                        break
                return patches
            else:
                compiled = ld.memory.load(ld.all_objects[0].entry, text_section_size)
                return compiled
