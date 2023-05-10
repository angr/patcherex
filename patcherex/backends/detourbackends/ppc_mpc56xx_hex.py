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

class DetourBackendPpcMpc56xxHex(DetourBackendPpc):
    def __init__(self, filename, base_address=None, try_reuse_unused_space=False, replace_note_segment=False, try_without_cfg=False, use_pickle=False):
        self.td = tempfile.mkdtemp()
        self.filename = os.path.join(self.td, "tmp.elf")
        res = utils.exec_cmd(["objcopy", "-I", "ihex", "-O", "elf32-big", filename, self.filename])
        if res[2] != 0:
            raise Exception(f"objcopy:\n{str(res[0] + res[1], 'utf-8')}")
        self.project = angr.Project(filename, arch=archinfo.ArchPcode("PowerPC:BE:32:MPC8270"), auto_load_libs=False, load_debug_info=True, main_opts={'base_addr': 0, 'entry_point': 0})
        regions = None
        self._identifer = None
        with open(self.filename, "rb") as f:
            self.ocontent = f.read()

        if try_reuse_unused_space:
            raise NotImplementedError()
        super().__init__(self.filename, base_address=base_address, replace_note_segment=replace_note_segment, try_without_cfg=try_without_cfg, use_pickle=use_pickle, skip_super_init=True)
        self.added_code_segment = 0x840000
        self.added_data_segment = 0x850000
        self.name_map.update(ADDED_DATA_START = (len(self.ncontent) % 0x1000) + self.added_data_segment)

    def save(self, filename=None):
        final_content = self.get_final_content()
        with open(self.filename, "wb") as f:
            f.write(final_content)

        res = utils.exec_cmd(["objcopy", "-O", "ihex", self.filename, filename])
        if res[2] != 0:
            raise Exception(f"objcopy:\n{str(res[0] + res[1], 'utf-8')}")

    def setup_headers(self, segments):
        pass

    def set_added_segment_headers(self):
        pass

    def _generate_cfg(self):
        """
        Generate a control flow graph, make sure necessary steps are performed, and return a CFG.

        :return: The CFG object
        :rtype: angr.analyses.CFG
        """
        regions = [
        (0x000749d0,   0x000749d0 + 0x0000029c),
        (0x00074550,   0x00074550 + 0x0000036c),
        (0x000733e0,   0x000733e0 + 0x000000f4),
        (0x000741d0,   0x000741d0 + 0x000001b4),
        (0x000749d0,   0x000749d0 + 0x0000029c),
        (0x00074d70,   0x00074d70 + 0x000000dc),
        (0x00073600,   0x00073600 + 0x00000078),
        (0x00183d70,   0x00183d70 + 0x00000018),
        (0x00074550,   0x00074550 + 0x0000036c),
        (0x000748c0,   0x000748c0 + 0x00000018),
        (0x00074470,   0x00074470 + 0x000000e0),
        (0x00073b60,   0x00073b60 + 0x000002a0),
        (0x00074e50,   0x00074e50 + 0x000002bc),
        (0x001835e0,   0x001835e0 + 0x00000190),
        (0x00183c90,   0x00183c90 + 0x00000094),
        (0x000748c0,   0x000748c0 + 0x00000018),
        (0x00074c70,   0x00074c70 + 0x00000080),
        (0x00074cf0,   0x00074cf0 + 0x00000074),
        (0x00074d70,   0x00074d70 + 0x000000dc),
        (0x000733e0,   0x000733e0 + 0x000000f4),
        (0x000749d0,   0x000749d0 + 0x0000029c),
        (0x6000592c,   0x6000592c + 0x00000168),
        ]
        # TODO
        # 1) ida-like cfg
        # 2) with some strategies we don't need the cfg, we should be able to apply those strategies even if the cfg fails
        l.info("Start generating CFG.")
        cfg = self.project.analyses.CFGFast(exclude_sparse_regions=False, use_patches=True,show_progressbar=True, resolve_indirect_jumps=True, data_references=True, cross_references=False, skip_unmapped_addrs=True, normalize=True, force_smart_scan=True, force_complete_scan=False)
        l.info("Finish generating CFG.")

        return cfg