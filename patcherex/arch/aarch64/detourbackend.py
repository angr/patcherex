from patcherex.backends.detourbackend import *
from elftools.elf.elffile import ELFFile
from elftools.construct.lib import Container
from . import utils

class DetourBackend(Backend):
    # how do we want to design this to track relocations in the blocks...
    def __init__(self, filename, data_fallback=None, base_address=None, try_pdf_removal=True):
        super(DetourBackend, self).__init__(filename, project_options={"main_opts": {"base_addr": base_address}})

        self.modded_segments = self.dump_segments() # dump_segments also set self.structs

        self.cfg = self._generate_cfg()
        self.ordered_nodes = self._get_ordered_nodes(self.cfg)

        # header stuff
        self.ncontent = self.ocontent
        self.segments = None
        self.original_header_end = None

        # tag to track if already patched
        self.patched_tag = b"SHELLPHISH\x00"  # should not be longer than 0x20

        self.name_map = RejectingDict()

        # where to put the segments in memory
        self.added_code_segment = 0x06000000
        self.added_data_segment = 0x07000000
        current_hdr = self.structs.Elf_Ehdr.parse(self.ncontent)
        self.single_segment_header_size = current_hdr["e_phentsize"]
        assert self.single_segment_header_size >= self.structs.Elf_Phdr.sizeof()
        # we may need up to 3 additional segments (patch code, patch data, phdr)
        self.additional_headers_size = 3 * self.single_segment_header_size

        self.added_code = b""
        self.added_data = b""
        self.added_code_file_start = None
        self.added_data_file_start = None
        self.added_patches = []
        self.added_rwdata_len = 0
        self.added_rwinitdata_len = 0
        self.phdr_segment = None
        self.to_init_data = b""
        self.max_convertible_address = (1 << (32 if self.structs.elfclass == 32 else 48)) - 1

        self.saved_states = OrderedDict()
        # not all the touched bytes are bad, they are only a serious problem in case of InsertCodePatch
        self.touched_bytes = set()

        self.name_map["ADDED_DATA_START"] = (len(self.ncontent) % 0x1000) + self.added_data_segment

    def is_patched(self):
        return self.ncontent.startswith(self.patched_tag, self.structs.Elf_Ehdr.sizeof())

    def setup_headers(self, segments):
        #if self.is_patched():
        #    return

        # copying original program headers (potentially modified by patches)
        # in the new place (at the  end of the file)
        self.first_load = None
        load_segments_rounded = []
        for segment in segments:
            if segment["p_type"] == "PT_LOAD":
                if self.first_load is None:
                    self.first_load = segment
                load_segments_rounded.append((
                        # start of the segment, round down to multiple of 0x1000
                        (segment["p_vaddr"] - self.first_load["p_vaddr"]) - ((segment["p_vaddr"] - self.first_load["p_vaddr"]) % 0x1000), 
                        # end of the segment, round up to multiple of 0x1000
                        int((segment["p_vaddr"] + segment["p_memsz"] - self.first_load["p_vaddr"] + 0x1000 - 1) / 0x1000 * 0x1000) ))

        for segment in segments:
            if segment["p_type"] == "PT_PHDR":
                if self.phdr_segment is not None:
                    raise ValueError("Multiple PHDR segments!")
                self.phdr_segment = segment

                segment["p_filesz"] += self.additional_headers_size
                segment["p_memsz"]  += self.additional_headers_size

                phdr_size = max(segment["p_filesz"], segment["p_memsz"])

                load_segments_rounded = sorted(load_segments_rounded, key=lambda x: x[0])

                # combine overlapping load segments
                while True:
                    new_load_segments_rounded = []
                    i = 0
                    while i < len(load_segments_rounded) - 1:
                        prev_seg = load_segments_rounded[i]
                        next_seg = load_segments_rounded[i + 1]
                        if prev_seg[1] > next_seg[0]: # two segments overlap
                            new_load_segments_rounded.append((prev_seg[0], next_seg[1])) # append combine of two segments
                            i += 2
                        else:
                            new_load_segments_rounded.append(prev_seg) # append segment without overlap
                            i += 1
                    if i == len(load_segments_rounded) - 1:
                        new_load_segments_rounded.append(load_segments_rounded[i]) # append last segment if without overlapping
                    if new_load_segments_rounded == load_segments_rounded: # if no overlap
                        break
                    load_segments_rounded = new_load_segments_rounded # combined segments, run again

                for prev_seg, next_seg in zip(load_segments_rounded[:-1], load_segments_rounded[1:]):
                    potential_base = ((max(prev_seg[1], len(self.ncontent)) + 0xF) & ~0xF) # round up to 0x10
                    if next_seg[0] - potential_base > phdr_size: # if there is space between segments, put phdr here
                        self.phdr_start = potential_base
                        break
                else:
                    self.phdr_start = load_segments_rounded[-1][1] # otherwise put it after the last load segment

                segment["p_offset"]  = self.phdr_start
                segment["p_vaddr"]   = self.phdr_start + self.first_load["p_vaddr"]
                segment["p_paddr"]   = self.phdr_start + self.first_load["p_vaddr"]

        self.ncontent = self.ncontent.ljust(self.phdr_start, b"\x00")

        # change pointer to program headers to point at the end of the elf
        current_hdr = self.structs.Elf_Ehdr.parse(self.ncontent)
        old_phoff = current_hdr["e_phoff"]
        current_hdr["e_phoff"] = len(self.ncontent)
        self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Ehdr.build(current_hdr), 0)

        print("putting them at %#x" % self.phdr_start)
        print("current len: %#x" % len(self.ncontent))
        for segment in segments:
            if segment["p_type"] == "PT_PHDR":
                segment = self.phdr_segment
            self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Phdr.build(segment))
        self.original_header_end = len(self.ncontent)

        # we overwrite the first original program header,
        # we do not need it anymore since we have moved original program headers at the bottom of the file
        self.ncontent = utils.bytes_overwrite(self.ncontent, self.patched_tag, old_phoff)

        # adding space for the additional headers
        # I add two of them, no matter what, if the data one will be used only in case of the fallback solution
        # Additionally added program headers have been already copied by the for loop above
        self.ncontent = self.ncontent.ljust(len(self.ncontent)+self.additional_headers_size, b"\x00")

    def dump_segments(self, tprint=False):
        with open(self.filename, "rb") as f:
            elf = ELFFile(f)
            self.structs = elf.structs
            segments = []
            for i in range(elf.num_segments()):
                seg = elf.get_segment(i)
                segments.append(seg.header)
        return segments

    def set_added_segment_headers(self, nsegments):
        l.debug("added_data_file_start: %#x", self.added_data_file_start)
        added_segments = 0
        original_nsegments = nsegments

        # add a LOAD segment for the PHDR segment
        phdr_segment_header = Container(**{ "p_type":   1,                                      "p_offset": self.phdr_segment["p_offset"],
                                            "p_vaddr":  self.phdr_segment["p_vaddr"],           "p_paddr":  self.phdr_segment["p_paddr"],
                                            "p_filesz": self.phdr_segment["p_filesz"],          "p_memsz":  self.phdr_segment["p_memsz"],
                                            "p_flags":  0x4,                                    "p_align":  0x1000})
        self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Phdr.build(phdr_segment_header),
                                                self.original_header_end + (2 * self.structs.Elf_Phdr.sizeof()))
        added_segments += 1

        # add a LOAD segment for the DATA segment
        data_segment_header = Container(**{ "p_type":   1,                                      "p_offset": self.added_data_file_start,
                                            "p_vaddr":  self.name_map["ADDED_DATA_START"],      "p_paddr":  self.name_map["ADDED_DATA_START"],
                                            "p_filesz": len(self.added_data),                   "p_memsz":  len(self.added_data),
                                            "p_flags":  0x6,                                    "p_align":  0x1000})
        self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Phdr.build(data_segment_header),
                                                self.original_header_end + self.structs.Elf_Phdr.sizeof())
        added_segments += 1

        # add a LOAD segment for the CODE segment
        code_segment_header = Container(**{ "p_type":   1,                                      "p_offset": self.added_code_file_start,
                                            "p_vaddr":  self.name_map["ADDED_CODE_START"],      "p_paddr":  self.name_map["ADDED_CODE_START"],
                                            "p_filesz": len(self.added_code),                   "p_memsz":  len(self.added_code),
                                            "p_flags":  0x5,                                    "p_align":  0x1000})
        self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Phdr.build(code_segment_header),
                                            self.original_header_end)
        added_segments += 1

        # print original_nsegments,added_segments
        current_hdr = self.structs.Elf_Ehdr.parse(self.ncontent)
        current_hdr["e_phnum"] += added_segments
        self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Ehdr.build(current_hdr), 0)

    def set_oep(self, new_oep):
        # set original entry point
        current_hdr = self.structs.Elf_Ehdr.parse(self.ncontent)
        current_hdr["e_entry"] = new_oep
        self.ncontent = utils.bytes_overwrite(self.ncontent, self.structs.Elf_Ehdr.build(current_hdr), 0)

    def get_oep(self):
        # get original entry point
        current_hdr = self.structs.Elf_Ehdr.parse(self.ncontent)
        return current_hdr["e_entry"]

    # 3 inserting strategies
    # Jump out and jump back
    # move a single function out
    # extending all the functions, so all need to move

    def get_block_containing_inst(self, inst_addr):
        index = bisect.bisect_right(self.ordered_nodes, inst_addr) - 1
        node = self.cfg.model.get_any_node(self.ordered_nodes[index], is_syscall=False)
        if inst_addr in node.instruction_addrs:
            return node.addr
        else:
            raise MissingBlockException("Couldn't find a block containing address %#x" % inst_addr)

    def get_current_code_position(self):
        return self.name_map["ADDED_CODE_START"] + (len(self.ncontent) - self.added_code_file_start)

    def save_state(self,applied_patches):
        self.saved_states[tuple(applied_patches)] = (self.ncontent,set(self.touched_bytes),self.name_map.copy())

    def restore_state(self,applied_patches,removed_patches):
        # find longest sequence of patches for which we have a save state
        if len(removed_patches) > 0:
            cut = min([len(applied_patches)]+[applied_patches.index(p) for p in removed_patches if p in applied_patches])
            applied_patches = applied_patches[:cut]
        current_longest = self.saved_states[tuple(applied_patches)]
        self.ncontent, self.touched_bytes, self.name_map = current_longest
        #print "retrieving",applied_patches

        # cut dictionary to the current state
        todict = OrderedDict()
        for i, (k, v) in enumerate(self.saved_states.items()):
            if i > list(self.saved_states.keys()).index(tuple(applied_patches)):
                break
            todict[k]=v
        self.saved_states = todict

        return applied_patches

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
        relevant_patches = [p for p in patches if (isinstance(p, AddCodePatch) or
                isinstance(p, InsertCodePatch) or isinstance(p, AddEntryPointPatch))]
        all_code = ""
        for p in relevant_patches:
            if isinstance(p, InsertCodePatch):
                code = p.code
            else:
                code = p.asm_code
            all_code += "\n" + code + "\n"
        labels = utils.string_to_labels(all_code)
        duplicates = set([x for x in labels if labels.count(x) > 1])
        if len(duplicates) > 1:
            raise DuplicateLabelsException("found duplicate assembly labels: %s" % (str(duplicates)))

        # for now any added code will be executed by jumping out and back ie CGRex
        # apply all add code patches
        self.added_code_file_start = len(self.ncontent)
        self.name_map.force_insert("ADDED_CODE_START",(len(self.ncontent) % 0x1000) + self.added_code_segment)

        bits = self.structs.elfclass

        # 0) RawPatch:
        for patch in patches:
            if isinstance(patch, RawFilePatch):
                self.ncontent = utils.bytes_overwrite(self.ncontent, patch.data, patch.file_addr)
                self.added_patches.append(patch)
                l.info("Added patch: " + str(patch))
        for patch in patches:
            if isinstance(patch, RawMemPatch):
                self.patch_bin(patch.addr,patch.data)
                self.added_patches.append(patch)
                l.info("Added patch: " + str(patch))

        for patch in patches:
            if isinstance(patch, RemoveInstructionPatch):
                if patch.ins_size is None:
                    size = 4
                else:
                    size = patch.ins_size
                self.patch_bin(patch.ins_addr, b"\x1f\x20\x03\xd5" * int((size + 4 - 1) / 4))
                self.added_patches.append(patch)
                l.info("Added patch: " + str(patch))

        # 1) Add{RO/RW/RWInit}DataPatch
        self.added_data_file_start = len(self.ncontent)
        curr_data_position = self.name_map["ADDED_DATA_START"]
        for patch in patches:
            if isinstance(patch, AddRWDataPatch) or isinstance(patch, AddRODataPatch) or \
                    isinstance(patch, AddRWInitDataPatch):
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
                l.info("Added patch: " + str(patch))
        self.ncontent = utils.pad_bytes(self.ncontent, 0x10)  # some minimal alignment may be good

        self.added_code_file_start = len(self.ncontent)
        self.name_map.force_insert("ADDED_CODE_START", (len(self.ncontent) % 0x1000) + self.added_code_segment)

        # 2) AddCodePatch
        # resolving symbols
        current_symbol_pos = self.get_current_code_position()
        for patch in patches:
            if isinstance(patch, AddCodePatch):
                if patch.is_c:
                    code_len = len(utils.compile_c(patch.asm_code,
                                                   optimization=patch.optimization,
                                                   compiler_flags=patch.compiler_flags))
                else:
                    code_len = len(utils.compile_asm(patch.asm_code,
                                                                 current_symbol_pos,
                                                                 bits=bits))
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
                    new_code = utils.compile_asm(patch.asm_code,
                                                 self.get_current_code_position(),
                                                 self.name_map,
                                                 bits=bits)
                self.added_code += new_code
                self.ncontent = utils.bytes_overwrite(self.ncontent, new_code)
                self.added_patches.append(patch)
                l.info("Added patch: " + str(patch))

        # 3) AddEntryPointPatch
        # basically like AddCodePatch but we detour by changing oep
        # and we jump at the end of all of them
        # resolving symbols
        if any([isinstance(p, AddEntryPointPatch) for p in patches]):
            pre_entrypoint_code_position = self.get_current_code_position()
            current_symbol_pos = self.get_current_code_position()
            entrypoint_patches = [p for p in patches if isinstance(p,AddEntryPointPatch)]
            between_restore_entrypoint_patches = sorted([p for p in entrypoint_patches if not p.after_restore], \
                key=lambda x:-1*x.priority)
            after_restore_entrypoint_patches = sorted([p for p in entrypoint_patches if p.after_restore], \
                key=lambda x:-1*x.priority)

            # current_symbol_pos += len(utils.compile_asm(ASM_ENTRY_POINT_PUSH_ENV,
            #                                                         current_symbol_pos,
            #                                                         bits=bits))
            # for patch in between_restore_entrypoint_patches:
            #     code_len = len(utils.compile_asm(patch.asm_code,
            #                                                  current_symbol_pos,
            #                                                  bits=bits))
            #     if patch.name is not None:
            #         self.name_map[patch.name] = current_symbol_pos
            #     current_symbol_pos += code_len
            # now compile for real
            # new_code = utils.compile_asm(ASM_ENTRY_POINT_PUSH_ENV,
            #                              self.get_current_code_position(),
            #                              bits=bits)
            # self.added_code += new_code
            # self.ncontent = utils.bytes_overwrite(self.ncontent, new_code)
            for patch in between_restore_entrypoint_patches:
                new_code = utils.compile_asm(patch.asm_code,
                                             self.get_current_code_position(),
                                             self.name_map,
                                             bits=bits)
                self.added_code += new_code
                self.added_patches.append(patch)
                l.info("Added patch: " + str(patch))
                self.ncontent = utils.bytes_overwrite(self.ncontent, new_code)

            # restore_code = ASM_ENTRY_POINT_RESTORE_ENV
            # current_symbol_pos += len(utils.compile_asm(restore_code,
            #                                                         current_symbol_pos,
            #                                                         bits=bits))
            # for patch in after_restore_entrypoint_patches:
            #     code_len = len(utils.compile_asm(patch.asm_code,
            #                                                  current_symbol_pos,
            #                                                  bits=bits))
            #     if patch.name is not None:
            #         self.name_map[patch.name] = current_symbol_pos
            #     current_symbol_pos += code_len
            # now compile for real
            # new_code = utils.compile_asm(restore_code,
            #                              self.get_current_code_position(),
            #                              bits=bits)
            # self.added_code += new_code
            # self.ncontent = utils.bytes_overwrite(self.ncontent, new_code)
            for patch in after_restore_entrypoint_patches:
                new_code = utils.compile_asm(patch.asm_code,
                                             self.get_current_code_position(),
                                             self.name_map,
                                             bits=bits)
                self.added_code += new_code
                self.ncontent = utils.bytes_overwrite(self.ncontent, new_code)
                self.added_patches.append(patch)
                l.info("Added patch: " + str(patch))

            oep = self.get_oep()
            self.set_oep(pre_entrypoint_code_position)
            new_code = utils.compile_jmp(self.get_current_code_position(),oep)
            self.added_code += new_code
            self.ncontent += new_code

        # 4) InlinePatch
        # we assume the patch never patches the added code
        for patch in patches:
            if isinstance(patch, InlinePatch):
                obj = self.project.loader.main_object
                prog_origin = patch.instruction_addr if not obj.pic else obj.addr_to_offset(patch.instruction_addr)
                new_code = utils.compile_asm(patch.new_asm,
                                                prog_origin,
                                                self.name_map,
                                                bits=bits)
                # Limiting the inline patch to a single block is not necessary
                # assert len(new_code) <= self.project.factory.block(patch.instruction_addr, num_inst=patch.num_instr, max_size=).size
                file_offset = self.project.loader.main_object.addr_to_offset(patch.instruction_addr)
                self.ncontent = utils.bytes_overwrite(self.ncontent, new_code, file_offset)
                self.added_patches.append(patch)
                l.info("Added patch: " + str(patch))

        # 5) InsertCodePatch
        # these patches specify an address in some basic block, In general we will move the basic block
        # and fix relative offsets
        # With this backend heer we can fail applying a patch, in case, resolve dependencies
        insert_code_patches = [p for p in patches if isinstance(p, InsertCodePatch)]
        insert_code_patches = sorted([p for p in insert_code_patches],key=lambda x:-1*x.priority)
        applied_patches = []
        while True:
            name_list = [str(p) if (p is None or p.name is None) else p.name for p in applied_patches]
            l.info("applied_patches is: |" + "-".join(name_list)+"|")
            assert all([a == b for a, b in zip(applied_patches, insert_code_patches)])
            for patch in insert_code_patches[len(applied_patches):]:
                self.save_state(applied_patches)
                try:
                    l.info("Trying to add patch: " + str(patch))
                    if patch.name is not None:
                        self.name_map[patch.name] = self.get_current_code_position()
                    new_code = self.insert_detour(patch)
                    self.added_code += new_code
                    self.ncontent = utils.bytes_overwrite(self.ncontent, new_code)
                    applied_patches.append(patch)
                    self.added_patches.append(patch)
                    l.info("Added patch: " + str(patch))
                except (DetourException, MissingBlockException, DoubleDetourException) as e:
                    l.warning(e)
                    insert_code_patches, removed = self.handle_remove_patch(insert_code_patches,patch)
                    #print map(str,removed)
                    applied_patches = self.restore_state(applied_patches, removed)
                    l.warning("One patch failed, rolling back InsertCodePatch patches. Failed patch: "+str(patch))
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
            elif len(segment_header_patches) == 1:
                segment_patch = segment_header_patches[0]
                segments = segment_patch.segment_headers
                l.info("Added patch: " + str(segment_patch))
            else:
                segments = self.modded_segments

            for patch in [p for p in patches if isinstance(p,AddSegmentHeaderPatch)]:
                # add after the first
                segments = [segments[0]] + [patch.new_segment] + segments[1:]

            self.setup_headers(segments)
            self.set_added_segment_headers(len(segments))
            l.debug("final symbol table: "+ repr([(k,hex(v)) for k,v in self.name_map.items()]))
        else:
            l.info("no patches, the binary will not be touched")

    def handle_remove_patch(self,patches,patch):
        # note the patches contains also "future" patches
        l.info("Handling removal of patch: "+str(patch))
        cleaned_patches = [p for p in patches if p != patch]
        removed_patches = [patch]
        while True:
            removed = False
            for p in cleaned_patches:
                for d in p.dependencies:
                    if d not in cleaned_patches:
                        l.info("Removing depending patch: "+str(p)+" depends from "+str(d))
                        removed = True
                        if p in cleaned_patches:
                            cleaned_patches.remove(p)
                        if p not in removed_patches:
                            removed_patches.append(p)
            if removed == False:
                break
        return cleaned_patches,removed_patches

    def check_if_movable(self, instruction):
        # the idea here is an instruction is movable if and only if
        # it has the same string representation when moved at different offsets is "movable"
        def bytes_to_comparable_str(ibytes, offset, bits):
            return " ".join(utils.instruction_to_str(utils.disassemble(ibytes, offset,
                                                                        bits=bits)[0]).split()[2:])

        instruction_bytes = instruction.bytes
        pos1 = bytes_to_comparable_str(instruction_bytes, 0x0, self.structs.elfclass)
        pos2 = bytes_to_comparable_str(instruction_bytes, 0x07f00000, self.structs.elfclass)
        pos3 = bytes_to_comparable_str(instruction_bytes, 0xfe000000, self.structs.elfclass)
        return pos1 == pos2 and pos2 == pos3

    def maddress_to_baddress(self, addr):
        if addr >= self.max_convertible_address:
            msg = "%08x higher than max_convertible_address (%08x)" % (addr,self.max_convertible_address)
            raise InvalidVAddrException(msg)
        baddr = self.project.loader.main_object.addr_to_offset(addr)
        if baddr is None:
            raise InvalidVAddrException(hex(addr))
        else:
            return baddr

    def get_memory_translation_list(self, address, size):
        # returns a list of address ranges that map to a given virtual address and size
        start = address
        end = address+size-1  # we will take the byte at end
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
            ndata = new_content[ndata_pos:ndata_pos+(end-start)]
            self.ncontent = utils.bytes_overwrite(self.ncontent, ndata, start)
            ndata_pos += len(ndata)

    def read_mem_from_file(self, address, size):
        mem = b""
        for start, end in self.get_memory_translation_list(address, size):
            mem += self.ncontent[start : end]
        return mem

    def get_movable_instructions(self, block):
        # TODO there are two improvements here:
        # 1) being able to move the jmp and call at the end of a bb
        # 2) detect cases like call-pop and dependent instructions (which should not be moved)
        # get movable_instructions in the bb
        original_bbcode = block.bytes
        instructions = utils.disassemble(original_bbcode, block.addr, bits=self.structs.elfclass)

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

    def compile_moved_injected_code(self, classified_instructions, patch_code, offset=0):
        # create injected_code (pre, injected, culprit, post, jmp_back)
        injected_code = "_patcherex_begin_patch:\n"
        injected_code += "\n".join([utils.capstone_to_asm(i)
                                    for i in classified_instructions
                                    if i.overwritten == 'pre'])
        injected_code += "\n"
        injected_code += "; --- custom code start\n" + patch_code + "\n" + "; --- custom code end\n" + "\n"
        injected_code += "\n".join([utils.capstone_to_asm(i)
                                    for i in classified_instructions
                                    if i.overwritten == 'culprit'])
        injected_code += "\n"
        injected_code += "\n".join([utils.capstone_to_asm(i)
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

        compiled_code = utils.compile_asm(injected_code,
                                              base=self.get_current_code_position(),
                                              name_map=self.name_map,
                                              bits=self.structs.elfclass)
        return compiled_code

    def insert_detour(self, patch):
        # TODO allow special case to patch syscall wrapper epilogue
        # (not that important since we do not want to patch epilogue in syscall wrapper)
        block_addr = self.get_block_containing_inst(patch.addr)
        mem = self.read_mem_from_file(block_addr, self.project.factory.block(block_addr).size)
        block = self.project.factory.block(block_addr, byte_string=mem)

        l.debug("inserting detour for patch: %s" % (map(hex, (block_addr, block.size, patch.addr))))

        detour_size = 4
        arm_nop = b"\x1f\x20\x03\xd5"

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
                    else:
                        self.touched_bytes.add(b)
                self.patch_bin(i.address, arm_nop)

        # insert the jump detour
        offset = self.project.loader.main_object.mapped_base if self.project.loader.main_object.pic else 0
        detour_jmp_code = utils.compile_jmp(detour_pos, self.get_current_code_position() + offset)
        self.patch_bin(detour_pos, detour_jmp_code)
        patched_bbcode = self.read_mem_from_file(block_addr, block.size)
        patched_bbinstructions = utils.disassemble(patched_bbcode, block_addr, bits=self.structs.elfclass)
        l.debug("patched bb instructions:\n %s",
                "\n".join([utils.instruction_to_str(i) for i in patched_bbinstructions]))

        new_code = self.compile_moved_injected_code(movable_instructions, patch.code, offset=offset)

        return new_code

    def get_final_content(self):
        return self.ncontent

    def save(self, filename=None):
        if filename is None:
            filename = self.filename + "_patched"

        final_content = self.get_final_content()
        with open(filename, "wb") as f:
            f.write(final_content)

        os.chmod(filename, 0o755)


def init_backend(program_name, options):
    return DetourBackend(program_name, **options)
