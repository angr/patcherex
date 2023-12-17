from .patch import Patch
from .raw_patches import ModifyRawBytesPatch
from ..components.allocation_managers.allocation_manager import MemoryFlag


class ModifyDataPatch(ModifyRawBytesPatch):
    def __init__(self, addr, new_bytes) -> None:
        super().__init__(addr, new_bytes, addr_type="mem")


class InsertDataPatch(Patch):
    def __init__(self, addr_or_name, data) -> None:
        self.addr = None
        self.name = None
        if isinstance(addr_or_name, int):
            self.addr = addr_or_name
        elif isinstance(addr_or_name, str):
            self.name = addr_or_name
        self.data = data

    def apply(self, p):
        if self.addr:
            p.binfmt_tool.update_binary_content(self.addr, self.data)
        elif self.name:
            block = p.allocation_manager.allocate(
                len(self.data), flag=MemoryFlag.RWX
            )  # FIXME: why RW not work?
            p.symbols[self.name] = block.mem_addr
            p.binfmt_tool.update_binary_content(block.file_addr, self.data)


class RemoveDataPatch(ModifyRawBytesPatch):
    def __init__(self, addr, size) -> None:
        super().__init__(addr, b"\x00" * size, addr_type="mem")
