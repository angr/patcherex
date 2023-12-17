from .target import Target
from ..components.assemblers.keystone import Keystone, keystone
from ..components.disassemblers.capstone import Capstone, capstone
from ..components.compilers.clang import Clang
from ..components.binfmt_tools.elf import ELF
from ..components.binary_analyzers.angr import Angr
from ..components.utils.utils import Utils
from ..components.allocation_managers.allocation_manager import AllocationManager


class ElfAArch64Linux(Target):
    NOP_BYTES = b"\x1f\x20\x03\xd5"
    NOP_SIZE = 4
    JMP_ASM = "b {dst}"
    JMP_SIZE = 4

    @staticmethod
    def detect_target(binary_path):
        with open(binary_path, "rb") as f:
            magic = f.read(0x14)
            if magic.startswith(b"\x7fELF") and magic.startswith(
                b"\xb7\x00", 0x12
            ):  # EM_AARCH64
                return True
        return False

    def get_assembler(self, assembler):
        assembler = assembler or "keystone"
        if assembler == "keystone":
            return Keystone(
                self.p, keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN
            )
        raise NotImplementedError()

    def get_allocation_manager(self, allocation_manager):
        allocation_manager = allocation_manager or "default"
        if allocation_manager == "default":
            return AllocationManager(self.p)
        raise NotImplementedError()

    def get_compiler(self, compiler):
        compiler = compiler or "clang"
        if compiler == "clang":
            return Clang(self.p, compiler_flags=["-target", "aarch64-linux-gnu"])
        raise NotImplementedError()

    def get_disassembler(self, disassembler):
        disassembler = disassembler or "capstone"
        if disassembler == "capstone":
            return Capstone(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        raise NotImplementedError()

    def get_binfmt_tool(self, binfmt_tool):
        binfmt_tool = binfmt_tool or "pyelftools"
        if binfmt_tool == "pyelftools":
            return ELF(self.p, self.binary_path)
        raise NotImplementedError()

    def get_binary_analyzer(self, binary_analyzer):
        binary_analyzer = binary_analyzer or "angr"
        if binary_analyzer == "angr":
            return Angr(self.binary_path)
        raise NotImplementedError()

    def get_utils(self, utils):
        utils = utils or "default"
        if utils == "default":
            return Utils(self.p, self.binary_path)
        raise NotImplementedError()
