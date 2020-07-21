import bisect
import logging
import os
import re
from collections import defaultdict

import capstone
import keystone

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
                               SegmentHeaderPatch)
from patcherex.utils import (CLangException, ObjcopyException,
                             UndefinedSymbolException)

l = logging.getLogger("patcherex.backends.DetourBackend")

class DetourBackendArm(DetourBackendElf):
    # how do we want to design this to track relocations in the blocks...
    def __init__(self, filename, base_address=None, replace_note_segment=False):
        super(DetourBackendArm, self).__init__(filename, base_address=base_address, replace_note_segment=replace_note_segment)

    def get_block_containing_inst(self, inst_addr):
        index = bisect.bisect_right(self.ordered_nodes, inst_addr) - 1
        node = self.cfg.model.get_any_node(self.ordered_nodes[index], is_syscall=False)
        if inst_addr in node.instruction_addrs:
            return node.addr
        else:
            if inst_addr % 2 == 0:
                return self.get_block_containing_inst(inst_addr + 1)
            else:
                raise MissingBlockException("Couldn't find a block containing address %#x" % inst_addr)

    def check_if_thumb(self, inst_addr):
        index = bisect.bisect_right(self.ordered_nodes, inst_addr) - 1
        node = self.cfg.model.get_any_node(self.ordered_nodes[index], is_syscall=False)
        if inst_addr in node.instruction_addrs:
            return node.thumb
        else:
            if inst_addr % 2 == 0:
                return self.check_if_thumb(inst_addr + 1)
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
        relevant_patches = [p for p in patches if (isinstance(p, (AddCodePatch, InsertCodePatch, AddEntryPointPatch)))]
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
                    ins = self.read_mem_from_file(patch.ins_addr, 4)
                    size = self.disassemble(ins, 0, is_thumb=self.check_if_thumb(patch.ins_addr))[0].size
                else:
                    size = patch.ins_size
                self.patch_bin(patch.ins_addr, b"\x00\xbf" * int((size + 2 - 1) / 2) if self.check_if_thumb(patch.ins_addr) else b"\x00\xF0\x20\xE3" * int((size + 4 - 1) / 4))
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
                # only r0 (a1) need to be saved, ref: glibc/sysdeps/{ARCH}/start.S
                instructions = "push {{r0}}"
                instructions += patch.asm_code
                instructions += "pop {{r0}}"
                instructions += "\nbl {}".format(hex(int(old_oep)))
                new_code = self.compile_asm(instructions,
                                             self.get_current_code_position(),
                                             self.name_map,
                                             is_thumb=patch.is_thumb)
                self.added_code += new_code
                self.added_patches.append(patch)
                self.ncontent = utils.bytes_overwrite(self.ncontent, new_code)
                self.set_oep(new_oep + 1 if patch.is_thumb else new_oep)
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
            assert all([a == b for a, b in zip(applied_patches, insert_code_patches)])
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
        if any([isinstance(p,ins) for ins in header_patches for p in self.added_patches]) or \
                any([isinstance(p,SegmentHeaderPatch) for p in patches]):
            # either implicitly (because of a patch adding code or data) or explicitly, we need to change segment headers

            # 6) SegmentHeaderPatch
            segment_header_patches = [p for p in patches if isinstance(p,SegmentHeaderPatch)]
            if len(segment_header_patches) > 1:
                msg = "more than one patch tries to change segment headers: " + "|".join([str(p) for p in segment_header_patches])
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
            return " ".join(utils.instruction_to_str(self.disassemble(ibytes, offset, is_thumb=is_thumb)[0]).split()[2:])

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
        is_thumb = self.check_if_thumb(block.addr)
        instructions = self.disassemble(original_bbcode, block.addr, is_thumb=is_thumb)

        if self.check_if_movable(instructions[-1], is_thumb=is_thumb):
            movable_instructions = instructions
        else:
            movable_instructions = instructions[:-1]

        return movable_instructions

    def find_detour_pos(self, block, detour_size, patch_addr):
        # iterates through the instructions to find where the detour can be stored
        movable_instructions = self.get_movable_instructions(block)

        movable_bb_start = movable_instructions[0].address
        movable_bb_size = self.project.factory.block(block.addr, num_inst=len(movable_instructions)).size

        possible_detour_starts = [i.address for i in movable_instructions]
        possible_detour_ends = [(movable_bb_start + movable_bb_size if i.address == movable_bb_start else i.address) - 1 for i in movable_instructions]

        l.debug("movable_bb_size: %d", movable_bb_size)
        l.debug("movable bb instructions:\n%s", "\n".join([utils.instruction_to_str(i) for i in movable_instructions]))

        # find a spot for the detour
        detour_pos = None
        for detour_start in range(movable_bb_start, movable_bb_start + movable_bb_size - detour_size, 2):
            if detour_start in possible_detour_starts and (detour_start + detour_size - 1) in possible_detour_ends:
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
                                              name_map=self.name_map, is_thumb=is_thumb)
        return compiled_code

    def insert_detour(self, patch):
        # TODO allow special case to patch syscall wrapper epilogue
        # (not that important since we do not want to patch epilogue in syscall wrapper)
        block_addr = self.get_block_containing_inst(patch.addr)
        mem = self.read_mem_from_file(block_addr if block_addr % 2 == 0 else block_addr - 1, self.project.factory.block(block_addr).size)
        block = self.project.factory.block(block_addr, byte_string=mem)

        l.debug("inserting detour for patch: %s", (map(hex, (block_addr, block.size, patch.addr))))

        detour_size = 4
        thumb_nop = b"\x00\xbf"
        arm_nop = b"\x00\xF0\x20\xE3"

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
                for b in range(i.address, i.address+len(i.bytes)):
                    if b in self.touched_bytes:
                        raise DoubleDetourException("byte has been already touched: %08x" % b)
                    self.touched_bytes.add(b)
                self.patch_bin(i.address, thumb_nop if self.check_if_thumb(i.address) else arm_nop)

        # insert the jump detour
        offset = self.project.loader.main_object.mapped_base if self.project.loader.main_object.pic else 0
        detour_jmp_code = self.compile_jmp(detour_pos, self.get_current_code_position() + offset, is_thumb=self.check_if_thumb(detour_pos))
        self.patch_bin(detour_pos, detour_jmp_code)
        patched_bbcode = self.read_mem_from_file(block_addr, block.size)
        patched_bbinstructions = self.disassemble(patched_bbcode, block_addr, is_thumb=self.check_if_thumb(block_addr))
        l.debug("patched bb instructions:\n %s",
                "\n".join([utils.instruction_to_str(i) for i in patched_bbinstructions]))

        new_code = self.compile_moved_injected_code(movable_instructions, patch.code, offset=offset, is_thumb=self.check_if_thumb(patch.addr))

        return new_code

    @staticmethod
    def capstone_to_asm(instruction):
            return instruction.mnemonic + " " + instruction.op_str.replace('{','{{').replace('}','}}')

    @staticmethod
    def disassemble(code, offset=0x0, is_thumb=False):
        offset = offset - 1 if is_thumb and offset % 2 == 1 else offset
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB if is_thumb else capstone.CS_MODE_ARM)
        md.detail = True
        if isinstance(code, str):
            code = bytes(map(ord, code))
        return list(md.disasm(code, offset))

    def compile_jmp(self, origin, target, is_thumb=False):
        jmp_str = '''
            bl {target}
        '''.format(**{'target': hex(int(target))})
        return self.compile_asm(jmp_str, base=origin, is_thumb=is_thumb)

    @staticmethod
    def compile_asm(code, base=None, name_map=None, is_thumb=False):
        #print "=" * 10
        #print code
        #if base != None: print hex(base)
        #if name_map != None: print {k: hex(v) for k,v in name_map.iteritems()}
        try:
            if name_map is not None:
                code = code.format(**name_map)  # compile_asm
            else:
                code = re.subn(r'{.*?}', "0x41414141", code)[0]  # solve symbols
        except KeyError as e:
            raise UndefinedSymbolException(str(e))
        try:
            ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_THUMB if is_thumb else keystone.KS_MODE_ARM)
            encoding, _ = ks.asm(code, base)
        except keystone.KsError as e:
            print("ERROR: %s" %e) #TODO raise some error
        return bytes(encoding)

    @staticmethod
    def get_c_function_wrapper_code(function_symbol):
        wcode = []
        wcode.append("bl {%s}" % function_symbol)

        return "\n".join(wcode)

    @staticmethod
    def compile_c(code, optimization='-Oz', compiler_flags="-m32", is_thumb=False):
        # TODO symbol support in c code
        with utils.tempdir() as td:
            c_fname = os.path.join(td, "code.c")
            object_fname = os.path.join(td, "code.o")
            bin_fname = os.path.join(td, "code.bin")

            fp = open(c_fname, 'w')
            fp.write(code)
            fp.close()

            res = utils.exec_cmd("clang -nostdlib -mno-sse -target arm-linux-gnueabihf -ffreestanding %s %s -o %s -c %s %s" \
                            % ("-mthumb" if is_thumb else "", optimization, object_fname, c_fname, compiler_flags), shell=True)
            if res[2] != 0:
                print("CLang error:")
                print(res[0])
                print(res[1])
                fp = open(c_fname, 'r')
                fcontent = fp.read()
                fp.close()
                print("\n".join(["%02d\t%s"%(i+1,j) for i, j in enumerate(fcontent.split("\n"))]))
                raise CLangException
            res = utils.exec_cmd("arm-linux-gnueabihf-objcopy -O binary -j .text %s %s" % (object_fname, bin_fname), shell=True)
            if res[2] != 0:
                print("objcopy error:")
                print(res[0])
                print(res[1])
                raise ObjcopyException
            fp = open(bin_fname, "rb")
            compiled = fp.read()
            fp.close()
        return compiled
