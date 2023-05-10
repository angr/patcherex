import bisect
import logging
import os
import re
import angr
import archinfo
from collections import defaultdict
import tempfile
import intelhex
import keystone
import io

import cle
from elftools.elf.elffile import ELFFile
from patcherex import utils
from patcherex.backends.detourbackends._elf import DetourBackendElf, l
from patcherex.backends.detourbackends.ppc import DetourBackendPpc
from patcherex.backends.detourbackends._utils import (AttrDict,
    DetourException, DoubleDetourException, DuplicateLabelsException,
    IncompatiblePatchesException, MissingBlockException, RejectingDict)
from patcherex.patches import (AddCodePatch, AddEntryPointPatch, AddLabelPatch,
                               AddRODataPatch, AddRWDataPatch,
                               AddRWInitDataPatch, AddSegmentHeaderPatch,
                               InlinePatch, InsertCodePatch, InsertFunctionPatch,
                               RawFilePatch, RawMemPatch, RemoveInstructionPatch,
                               ReplaceFunctionPatch, SegmentHeaderPatch)
from patcherex.utils import CLangException, ObjcopyException

l = logging.getLogger("patcherex.backends.DetourBackend")

class DetourBackendPpcMpc56xxHex(DetourBackendPpc):

    vle_binutils_path = os.path.realpath(os.path.join(os.path.dirname(__file__), '..', '..', 'binary_dependencies', 'powerpc-eabivle', 'bin'))


    def __init__(self, filename, base_address=None, try_reuse_unused_space=False, replace_note_segment=False, try_without_cfg=False, use_pickle=False):
        self.filename = filename
        self.project = angr.Project(self.filename, arch=archinfo.ArchPcode("PowerPC:BE:32:MPC8270"), auto_load_libs=False, load_debug_info=True, main_opts={'backend': 'hex', 'base_addr': 0, 'entry_point': 0})
        self._identifer = None
        with open(self.filename, "rb") as f:
            self.ocontent = f.read()

        self.ihex = intelhex.IntelHex(self.filename)
        self.name_map = RejectingDict()
        self.ncontent = self.ocontent

    def apply_patches(self, patches):
        for patch in patches:
            if isinstance(patch, InlinePatch):
                new_code = self.compile_asm(patch.new_asm, patch.instruction_addr, self.name_map)
                self.ihex.puts(patch.instruction_addr, new_code)
                l.info("Patched %s at %#x with %s", self.filename, patch.instruction_addr, patch.new_asm)
                sio = io.StringIO()
                self.ihex.write_hex_file(sio, byte_count=0x20)
                self.ncontent = sio.getvalue()
                sio.close()
            elif isinstance(patch, RawMemPatch):
                self.ihex.puts(patch.addr, patch.data)
                l.info("Patched %s at %#x with %s", self.filename, patch.addr, patch.data)
                sio = io.StringIO()
                self.ihex.write_hex_file(sio, byte_count=0x20)
                self.ncontent = sio.getvalue()
                sio.close()
            else:
                raise NotImplementedError(f"Unsupported patch type {type(patch)}")

    def disassemble(self, code, offset=0x0, is_thumb=False):
        if isinstance(code, str):
            code = bytes(map(ord, code))
        with utils.tempdir() as td:
            with open(os.path.join(td, "code.bin"), "wb") as f:
                f.write(code)

            res = utils.exec_cmd(f"{os.path.join(DetourBackendPpcMpc56xxHex.vle_binutils_path, 'powerpc-eabivle-objdump')} -D -b binary --adjust-vma={hex(offset)} -EB {os.path.join(td, 'code')}.bin | tail +8", shell=True)
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

    def compile_asm(self, code, base=None, name_map=None, is_thumb=False, dummy=False):
        try:
            if name_map is not None:
                code = code.format(**name_map)  # compile_asm
            else:
                code = re.subn(r'{.*?}', "0x41414141", code)[0]  # solve symbols
        except KeyError as e:
            raise UndefinedSymbolException(str(e)) from e

        code = re.subn(r' r(\d+)', r' \1', code)[0]

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
            res = utils.exec_cmd(f"{os.path.join(DetourBackendPpcMpc56xxHex.vle_binutils_path, 'powerpc-eabivle-as')} -o {os.path.join(td, 'code')}.o {os.path.join(td, 'code')}.s", shell=True)
            if res[2] != 0:
                raise Exception(f"powerpc-eabivle-as:\n{str(res[0] + res[1], 'utf-8')}")
            res = utils.exec_cmd(f"{os.path.join(DetourBackendPpcMpc56xxHex.vle_binutils_path, 'powerpc-eabivle-objcopy')} -O binary -j .text {os.path.join(td, 'code')}.o {os.path.join(td, 'code')}.bin", shell=True)
            if res[2] != 0:
                raise Exception(f"powerpc-eabivle-objcopy:\n{str(res[0] + res[1], 'utf-8')}")
            with open(os.path.join(td, "code.bin"), "rb") as f:
                if base is not None:
                    f.seek(base)
                result = f.read()
                disasms = self.disassemble(result, base if base is not None else 0x0)
                return result


    def save(self, filename=None):
        if filename is None:
            filename = self.filename + "_patched"

        final_content = self.get_final_content()
        with open(filename, "w") as f:
            f.write(final_content)

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