import logging
import os
from collections import defaultdict

import cle
from patcherex import utils
from patcherex.backends.detourbackends._elf import DetourBackendElf, l
from patcherex.backends.detourbackends._utils import (
    DetourException, DoubleDetourException, DuplicateLabelsException,
    IncompatiblePatchesException, MissingBlockException)
from patcherex.patches import (AddCodePatch, AddEntryPointPatch, AddFunctionPatch,
                               AddLabelPatch, AddRODataPatch, AddRWDataPatch,
                               AddRWInitDataPatch, AddSegmentHeaderPatch, FunctionWrapperPatch,
                               InlinePatch, InsertCodePatch, RawFilePatch,
                               RawMemPatch, RemoveInstructionPatch,
                               ReplaceFunctionPatch, SegmentHeaderPatch)
from patcherex.utils import CLangException, instruction_to_str

l = logging.getLogger("patcherex.backends.DetourBackend")


class DetourBackendi386(DetourBackendElf):
    # how do we want to design this to track relocations in the blocks...
    def __init__(self, filename, base_address=None, try_reuse_unused_space=False, replace_note_segment=False, try_without_cfg=False):
        if try_reuse_unused_space:
            raise NotImplementedError()
        if try_without_cfg:
            raise NotImplementedError()
        super().__init__(filename, base_address=base_address,
                         replace_note_segment=replace_note_segment, try_without_cfg=try_without_cfg)

    def apply_patches(self, patches):
        # deal with stackable patches
        # add stackable patches to the one with highest priority
        insert_code_patches = [
            p for p in patches if isinstance(p, InsertCodePatch)]
        insert_code_patches_dict = defaultdict(list)
        for p in insert_code_patches:
            insert_code_patches_dict[p.addr].append(p)
        insert_code_patches_dict_sorted = defaultdict(list)
        for k, v in insert_code_patches_dict.items():
            insert_code_patches_dict_sorted[k] = sorted(
                v, key=lambda x: -1*x.priority)

        insert_code_patches_stackable = [
            p for p in patches if isinstance(p, InsertCodePatch) and p.stackable]
        for sp in insert_code_patches_stackable:
            assert len(sp.dependencies) == 0
            if sp.addr in insert_code_patches_dict_sorted:
                highest_priority_at_addr = insert_code_patches_dict_sorted[sp.addr][0]
                if highest_priority_at_addr != sp:
                    highest_priority_at_addr.asm_code += "\n"+sp.asm_code+"\n"
                    patches.remove(sp)

        default_symbols = self._default_symbols(patches)

        # deal with AddLabel patches
        lpatches = [p for p in patches if isinstance(p, AddLabelPatch)]
        for p in lpatches:
            self.name_map[p.name] = p.addr

        # check for duplicate labels, it is not very necessary for this backend
        # but it is better to behave in the same way of the reassembler backend
        relevant_patches = [p for p in patches if isinstance(
            p, (AddCodePatch, AddEntryPointPatch, InsertCodePatch))]
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
            raise DuplicateLabelsException(
                "found duplicate assembly labels: %s" % (str(duplicates)))

        # for now any added code will be executed by jumping out and back ie CGRex
        # apply all add code patches
        self.added_code_file_start = len(self.ncontent)
        self.name_map.force_insert("ADDED_CODE_START", (len(
            self.ncontent) % 0x1000) + self.added_code_segment)

        # 0) RawPatch:
        for patch in patches:
            if isinstance(patch, RawFilePatch):
                self.ncontent = utils.bytes_overwrite(
                    self.ncontent, patch.data, patch.file_addr)
                self.added_patches.append(patch)
                l.info("Added patch: %s", str(patch))
        for patch in patches:
            if isinstance(patch, RawMemPatch):
                self.patch_bin(patch.addr, patch.data)
                self.added_patches.append(patch)
                l.info("Added patch: %s", str(patch))

        for patch in patches:
            if isinstance(patch, RemoveInstructionPatch):
                if patch.ins_size is None:
                    ins = self.read_mem_from_file(patch.ins_addr, 16)
                    size = list(self.project.arch.capstone.disasm(ins, 0))[
                        0].size
                else:
                    size = patch.ins_size
                self.patch_bin(patch.ins_addr, b"\x90" * size)
                self.added_patches.append(patch)
                l.info("Added patch: %s", str(patch))

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
                self.ncontent = utils.bytes_overwrite(
                    self.ncontent, final_patch_data)
                self.added_patches.append(patch)
                l.info("Added patch: %s", str(patch))
        # some minimal alignment may be good
        self.ncontent = utils.pad_bytes(self.ncontent, 0x10)

        self.added_code_file_start = len(self.ncontent)
        if self.replace_note_segment:
            self.name_map.force_insert("ADDED_CODE_START", int(
                (curr_data_position + 0x10 - 1) / 0x10) * 0x10)
        else:
            self.name_map.force_insert("ADDED_CODE_START", (len(
                self.ncontent) % 0x1000) + self.added_code_segment)

        # add PIE thunk
        self.name_map["pie_thunk"] = self.get_current_code_position()
        if self.structs.elfclass == 64:
            pie_thunk = """
            _patcherex_begin_patch:
            call here
            here:
            pop rax
            sub rax, (here - _patcherex_begin_patch + {pie_thunk})
            ret
            """
        else:
            pie_thunk = """
            _patcherex_begin_patch:
            call here
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

        # 2) AddCodePatch / AddFunctionPatch
        # resolving symbols
        current_symbol_pos = self.get_current_code_position()
        for patch in patches:
            if isinstance(patch, AddCodePatch):
                if patch.is_c:
                    code_len = len(utils.compile_c(patch.asm_code,
                                                   optimization=patch.optimization,
                                                   compiler_flags=patch.compiler_flags))
                else:
                    code_len = len(self.compile_asm(
                        patch.asm_code, current_symbol_pos))
                if patch.name is not None:
                    self.name_map[patch.name] = current_symbol_pos
                current_symbol_pos += code_len
            elif isinstance(patch, AddFunctionPatch):
                code_len = len(self.compile_function(patch.asm_code, compiler_flags="-fPIE" if self.project.loader.main_object.pic else "",
                                                     bits=self.structs.elfclass, entry=current_symbol_pos))
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
                    new_code = self.compile_asm(patch.asm_code,
                                                self.get_current_code_position(),
                                                self.name_map)
                self.added_code += new_code
                self.ncontent = utils.bytes_overwrite(self.ncontent, new_code)
                self.added_patches.append(patch)
                l.info("Added patch: %s", str(patch))
            elif isinstance(patch, AddFunctionPatch):
                symbols = default_symbols.copy()
                symbols.update(patch.symbols or {})
                obj = self.project.loader.main_object
                entry = self.get_current_code_position(
                ) if not obj.pic else self.get_current_code_position() + obj.min_addr
                new_code = self.compile_function(patch.asm_code, compiler_flags="-fPIE" if self.project.loader.main_object.pic else "",
                                                 bits=self.structs.elfclass, entry=entry, symbols=symbols)
                self.added_code += new_code
                self.ncontent = utils.bytes_overwrite(self.ncontent, new_code)
                self.added_patches.append(patch)
                l.info("Added patch: %s", str(patch))

        # ?) FunctionWrapperPatch
        for patch in patches:
            if isinstance(patch, FunctionWrapperPatch):
                offset = self.project.loader.main_object.mapped_base if self.project.loader.main_object.pic else 0
                mem = self.read_mem_from_file(
                    patch.addr, self.project.factory.block(patch.addr).size)
                block = self.project.factory.block(patch.addr, byte_string=mem)

                movable_instructions = self.get_movable_instructions(block)
                if len(movable_instructions) == 0:
                    raise DetourException("No movable instructions found")
                movable_start = movable_instructions[0].address
                movable_end = movable_instructions[-1].address + \
                    movable_instructions[-1].size
                movable_size = movable_end - movable_start

                detour_size = len(self.compile_asm(
                    f"jmp {hex(self.get_current_code_position() + offset)}", patch.addr))

                movable_size = 0
                idx = -1
                for i, instr in enumerate(movable_instructions):
                    movable_size += instr.size
                    if movable_size >= detour_size:
                        idx = i
                        break
                else:
                    raise DetourException("Detour is too big")

                moved_size = sum(
                    [movable_instructions[i].size for i in range(idx + 1)])
                nop_size = moved_size - detour_size

                # compile function for size
                symbols = default_symbols.copy()
                symbols.update(patch.symbols or {})
                symbols["__original_function"] = patch.addr
                wrapper_size = len(self.compile_function(patch.asm_code, compiler_flags="-fPIE" if self.project.loader.main_object.pic else "",
                                                         bits=self.structs.elfclass, entry=self.get_current_code_position() + offset, symbols=symbols))
                jmp_to_wrapper_size = len(self.compile_asm(
                    f"jmp {hex(self.get_current_code_position() + offset)}", self.get_current_code_position() + wrapper_size + offset))

                # add detour
                jmp_code = f"jmp {hex(self.get_current_code_position() + offset + wrapper_size)}\n"
                jmp_code += "nop\n" * nop_size
                jmp_bytes = self.compile_asm(jmp_code, patch.addr)
                file_offset = self.project.loader.main_object.addr_to_offset(
                    patch.addr)
                self.ncontent = utils.bytes_overwrite(
                    self.ncontent, jmp_bytes, file_offset)

                # compile function
                symbols["__original_function"] = self.get_current_code_position(
                ) + wrapper_size + offset + jmp_to_wrapper_size
                new_code = self.compile_function(patch.asm_code, compiler_flags="-fPIE" if self.project.loader.main_object.pic else "",
                                                 bits=self.structs.elfclass, entry=self.get_current_code_position() + offset, symbols=symbols)
                self.added_code += new_code
                self.ncontent = utils.bytes_overwrite(self.ncontent, new_code)

                # add detour block
                #   jump to the wrapper function
                detour_code = f"jmp {hex(self.get_current_code_position() + offset - wrapper_size)}\n"
                #   copy movable instructions
                detour_code += "\n".join([self.capstone_to_asm(movable_instructions[i])
                                         for i in range(idx + 1)]) + "\n"
                #   jump to the original function
                detour_code += f"jmp {hex(patch.addr + moved_size)}\n"
                new_code = self.compile_asm(
                    detour_code, base=self.get_current_code_position() + offset)
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
                # only edx/rdx need to be saved, ref: glibc/sysdeps/{ARCH}/start.S
                if self.structs.elfclass == 32:
                    instructions = "push edx"
                    instructions += patch.asm_code
                    instructions += "pop edx"
                    instructions += "\njmp {}".format(hex(int(old_oep)))
                else:  # 64 bits
                    instructions = "push rdx"
                    instructions += patch.asm_code
                    instructions += "pop rdx"
                    instructions += "\njmp {}".format(hex(int(old_oep)))
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
                obj = self.project.loader.main_object
                prog_origin = patch.instruction_addr if not obj.pic else obj.addr_to_offset(
                    patch.instruction_addr)
                new_code = self.compile_asm(patch.new_asm,
                                            prog_origin,
                                            self.name_map)
                # Limiting the inline patch to a single block is not necessary
                # assert len(new_code) <= self.project.factory.block(patch.instruction_addr, num_inst=patch.num_instr, max_size=).size
                file_offset = self.project.loader.main_object.addr_to_offset(
                    patch.instruction_addr)
                self.ncontent = utils.bytes_overwrite(
                    self.ncontent, new_code, file_offset)
                self.added_patches.append(patch)
                l.info("Added patch: %s", str(patch))

        # 5) InsertCodePatch
        # these patches specify an address in some basic block, In general we will move the basic block
        # and fix relative offsets
        # With this backend heer we can fail applying a patch, in case, resolve dependencies
        insert_code_patches = [
            p for p in patches if isinstance(p, InsertCodePatch)]
        insert_code_patches = sorted(
            insert_code_patches, key=lambda x: -1*x.priority)
        applied_patches = []
        while True:
            name_list = [str(p) if (p is None or p.name is None)
                         else p.name for p in applied_patches]
            l.info("applied_patches is: |%s|", "-".join(name_list))
            assert all(a == b for a, b in zip(
                applied_patches, insert_code_patches))
            for patch in insert_code_patches[len(applied_patches):]:
                self.save_state(applied_patches)
                try:
                    l.info("Trying to add patch: %s", str(patch))
                    if patch.name is not None:
                        self.name_map[patch.name] = self.get_current_code_position()
                    new_code = self.insert_detour(patch)
                    self.added_code += new_code
                    self.ncontent = utils.bytes_overwrite(
                        self.ncontent, new_code)
                    applied_patches.append(patch)
                    self.added_patches.append(patch)
                    l.info("Added patch: %s", str(patch))
                except (DetourException, MissingBlockException, DoubleDetourException) as e:
                    l.warning(e)
                    insert_code_patches, removed = self.handle_remove_patch(
                        insert_code_patches, patch)
                    # print map(str,removed)
                    applied_patches = self.restore_state(
                        applied_patches, removed)
                    l.warning(
                        "One patch failed, rolling back InsertCodePatch patches. Failed patch: %s", str(patch))
                    break
                    # TODO: right now rollback goes back to 0 patches, we may want to go back less
                    # the solution is to save touched_bytes and ncontent indexed by applied patfch
                    # and go back to the biggest compatible list of patches
            else:
                break  # at this point we applied everything in current insert_code_patches
                # TODO symbol name, for now no name_map for InsertCode patches

        header_patches = [InsertCodePatch, InlinePatch, AddEntryPointPatch, AddCodePatch,
                          AddRWDataPatch, AddRODataPatch, AddRWInitDataPatch, AddFunctionPatch, FunctionWrapperPatch]

        # 5.5) ReplaceFunctionPatch
        for patch in patches:
            if isinstance(patch, ReplaceFunctionPatch):
                if isinstance(patch.addr, str):
                    if patch.addr in self.name_map:
                        patch.addr = self.name_map[patch.addr]
                    elif patch.addr in self.project.kb.functions:
                        patch.addr = self.project.kb.functions[patch.addr].addr
                    else:
                        raise Exception(
                            "Could not resolve address for %s" % patch.addr)
                symbols = default_symbols.copy()
                symbols.update(patch.symbols or {})
                new_code = self.compile_function(
                    patch.asm_code,
                    compiler_flags="-fPIE" if self.project.loader.main_object.pic else "",
                    bits=self.structs.elfclass,
                    entry=patch.addr,
                    symbols=symbols
                )
                file_offset = self.project.loader.main_object.addr_to_offset(
                    patch.addr)
                self.ncontent = utils.bytes_overwrite(
                    self.ncontent, b"\x90" * patch.size, file_offset)
                if patch.size >= len(new_code):
                    self.project.loader: cle.Loader
                    file_offset = self.project.loader.main_object.addr_to_offset(
                        patch.addr)
                    self.ncontent = utils.bytes_overwrite(
                        self.ncontent, new_code, file_offset)
                else:
                    header_patches.append(ReplaceFunctionPatch)
                    detour_pos = self.get_current_code_position()
                    offset = self.project.loader.main_object.mapped_base if self.project.loader.main_object.pic else 0
                    new_code = self.compile_function(patch.asm_code, compiler_flags="-fPIE" if self.project.loader.main_object.pic else "",
                                                     bits=self.structs.elfclass, entry=detour_pos + offset, symbols=patch.symbols)
                    self.added_code += new_code
                    self.ncontent = utils.bytes_overwrite(
                        self.ncontent, new_code)
                    # compile jmp
                    jmp_code = self.compile_jmp(
                        patch.addr, detour_pos + offset)
                    self.patch_bin(patch.addr, jmp_code)
                self.added_patches.append(patch)
                l.info("Added patch: %s", str(patch))

        if any(isinstance(p, ins) for ins in header_patches for p in self.added_patches) or \
                any(isinstance(p, SegmentHeaderPatch) for p in patches):
            # either implicitly (because of a patch adding code or data) or explicitly, we need to change segment headers

            # 6) SegmentHeaderPatch
            segment_header_patches = [
                p for p in patches if isinstance(p, SegmentHeaderPatch)]
            if len(segment_header_patches) > 1:
                msg = "more than one patch tries to change segment headers: " + \
                    "|".join([str(p) for p in segment_header_patches])
                raise IncompatiblePatchesException(msg)
            if len(segment_header_patches) == 1:
                segment_patch = segment_header_patches[0]
                segments = segment_patch.segment_headers
                l.info("Added patch: %s", str(segment_patch))
            else:
                segments = self.modded_segments

            for patch in [p for p in patches if isinstance(p, AddSegmentHeaderPatch)]:
                # add after the first
                segments = [segments[0]] + [patch.new_segment] + segments[1:]

            self.setup_headers(segments)
            self.set_added_segment_headers()
            l.debug("final symbol table: %s", repr(
                [(k, hex(v)) for k, v in self.name_map.items()]))
        else:
            l.info("no header patches, the segment header will not be touched")

    def check_if_movable(self, instruction, is_thumb=False):
        # the idea here is an instruction is movable if and only if
        # it has the same string representation when moved at different offsets is "movable"
        def bytes_to_comparable_str(ibytes, offset, bits):
            return " ".join(utils.instruction_to_str(utils.disassemble(ibytes, offset,
                                                                       bits=bits)[0]).split()[2:])

        instruction_bytes = instruction.bytes
        pos1 = bytes_to_comparable_str(
            instruction_bytes, 0x0, self.structs.elfclass)
        pos2 = bytes_to_comparable_str(
            instruction_bytes, 0x07f00000, self.structs.elfclass)
        pos3 = bytes_to_comparable_str(
            instruction_bytes, 0xfe000000, self.structs.elfclass)
        if "rip" in pos1:
            return False
        return pos1 == pos2 and pos2 == pos3

    def get_movable_instructions(self, block):
        # TODO there are two improvements here:
        # 1) being able to move the jmp and call at the end of a bb
        # 2) detect cases like call-pop and dependent instructions (which should not be moved)
        # get movable_instructions in the bb
        original_bbcode = block.bytes
        instructions = utils.disassemble(
            original_bbcode, block.addr, bits=self.structs.elfclass)

        if self.check_if_movable(instructions[-1]):
            movable_instructions = instructions
        else:
            movable_instructions = instructions[:-1]

        return movable_instructions

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
        # jmp back to the one after the last byte of the last non-out
        for i in reversed(classified_instructions):
            if i.overwritten != "out":
                jmp_back_target = i.address+len(i.bytes)
                break
        assert jmp_back_target is not None
        injected_code += "jmp %s" % hex(int(jmp_back_target) - offset) + "\n"
        # removing blank lines
        injected_code = "\n".join(
            [line for line in injected_code.split("\n") if line != ""])
        l.debug("injected code:\n%s", injected_code)

        compiled_code = self.compile_asm(injected_code,
                                         base=self.get_current_code_position(),
                                         name_map=self.name_map)
        return compiled_code

    def insert_detour(self, patch):
        # TODO allow special case to patch syscall wrapper epilogue
        # (not that important since we do not want to patch epilogue in syscall wrapper)
        block_addr = self.get_block_containing_inst(patch.addr)
        mem = self.read_mem_from_file(
            block_addr, self.project.factory.block(block_addr).size)
        block = self.project.factory.block(block_addr, byte_string=mem)

        l.debug("inserting detour for patch: %s",
                (map(hex, (block_addr, block.size, patch.addr))))

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
        l.debug("\n".join([utils.instruction_to_str(i)
                for i in movable_instructions]))
        assert any(i.overwritten != "out" for i in movable_instructions)

        # replace overwritten instructions with nops
        for i in movable_instructions:
            if i.overwritten != "out":
                for b in range(i.address, i.address+len(i.bytes)):
                    if b in self.touched_bytes:
                        raise DoubleDetourException(
                            "byte has been already touched: %08x" % b)
                    self.touched_bytes.add(b)
                self.patch_bin(i.address, one_byte_nop*len(i.bytes))

        # insert the jump detour
        offset = self.project.loader.main_object.mapped_base if self.project.loader.main_object.pic else 0
        detour_jmp_code = self.compile_jmp(
            detour_pos, self.get_current_code_position() + offset)
        self.patch_bin(detour_pos, detour_jmp_code)
        patched_bbcode = self.read_mem_from_file(block_addr, block.size)
        patched_bbinstructions = utils.disassemble(
            patched_bbcode, block_addr, bits=self.structs.elfclass)
        l.debug("patched bb instructions:\n %s",
                "\n".join([utils.instruction_to_str(i) for i in patched_bbinstructions]))

        new_code = self.compile_moved_injected_code(
            movable_instructions, patch.code, offset=offset)

        return new_code

    def compile_jmp(self, origin, target):
        jmp_str = '''
            jmp {target}
        '''.format(**{'target': hex(int(target))})
        return self.compile_asm(jmp_str, base=origin)

    @staticmethod
    def get_c_function_wrapper_code(function_symbol):
        wcode = []
        wcode.append("call {%s}" % function_symbol)

        return "\n".join(wcode)

    @staticmethod
    def compile_function(code, compiler_flags="", bits=32, entry=0x0, symbols=None):
        with utils.tempdir() as td:
            c_fname = os.path.join(td, "code.c")
            object_fname = os.path.join(td, "code.o")
            object2_fname = os.path.join(td, "code.2.o")
            linker_script_fname = os.path.join(td, "code.lds")

            with open(c_fname, 'w') as fp:
                fp.write(code)

            linker_script = "SECTIONS { .text : SUBALIGN(0) { . = " + hex(
                entry) + "; *(.text) "
            if symbols is not None:
                for i in symbols:
                    linker_script += i + " = " + hex(symbols[i]) + ";"
            linker_script += "}}"

            with open(linker_script_fname, 'w') as fp:
                fp.write(linker_script)

            res = utils.exec_cmd("clang -o %s %s -c %s %s" % (object_fname,
                                 "-m32" if bits == 32 else "-m64", c_fname, compiler_flags), shell=True)
            if res[2] != 0:
                raise CLangException(
                    "CLang error: " + str(res[0] + res[1], 'utf-8'))

            res = utils.exec_cmd("ld.lld -relocatable %s -T %s -o %s" %
                                 (object_fname, linker_script_fname, object2_fname), shell=True)
            if res[2] != 0:
                raise Exception("Linking Error: " +
                                str(res[0] + res[1], 'utf-8'))

            ld = cle.Loader(object2_fname, main_opts={"base_addr": 0x0})
            compiled = ld.memory.load(
                ld.all_objects[0].entry + entry, ld.memory.max_addr)
        return compiled
