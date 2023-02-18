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

class DetourBackendPpcBooke(DetourBackendPpc):
    def __init__(self, filename, base_address=None, try_reuse_unused_space=False, replace_note_segment=False, try_without_cfg=False, use_pickle=False):
        super().__init__(filename, base_address=base_address, replace_note_segment=replace_note_segment, try_without_cfg=try_without_cfg, use_pickle=use_pickle)

        self.added_code_segment = 0x840000
        self.added_data_segment = 0x850000

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
