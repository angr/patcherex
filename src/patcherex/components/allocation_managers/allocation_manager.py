import enum
import logging

logger = logging.getLogger(__name__)


class Block:
    subclasses = []

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        Block.subclasses.append(cls)

    def __init__(self, addr, size, is_free=True):
        self.addr = addr
        self.size = size
        self.is_free = is_free

    def __lt__(self, other):
        return self.addr < other.addr

    def __repr__(self):
        return f"<{self.__class__.__name__} addr={hex(self.addr)} size={hex(self.size)} is_free={self.is_free}>"

    def coalesce(self, other):
        if self.is_free == other.is_free and self.addr + self.size == other.addr:
            self.size += other.size
            return True
        return False


class FileBlock(Block):
    pass


class MemoryBlock(Block):
    def __init__(self, addr, size, is_free=True):
        super().__init__(addr, size, is_free)

    def __repr__(self):
        return f"<{self.__class__.__name__} addr={hex(self.addr)} size={hex(self.size)} is_free={self.is_free}>"


class MemoryFlag(enum.IntFlag):
    UNDEF = enum.auto()
    R = 0x4
    W = 0x2
    X = 0x1
    RW = R | W
    RX = R | X
    RWX = R | W | X


class MappedBlock(Block):
    def __init__(self, file_addr, mem_addr, size, is_free=True, flag=None):
        super().__init__(None, size, is_free)
        self.file_addr = file_addr
        self.mem_addr = mem_addr
        self.flag = flag

    def __lt__(self, other):
        return self.mem_addr < other.mem_addr

    def __repr__(self):
        return f"<{self.__class__.__name__} file_addr={hex(self.file_addr)} mem_addr={hex(self.mem_addr)} size={hex(self.size)} is_free={self.is_free} flag={str(self.flag)}>"

    def coalesce(self, other):
        if (
            self.flag == other.flag
            and self.is_free == other.is_free
            and self.file_addr + self.size == other.file_addr
            and self.mem_addr + self.size == other.mem_addr
        ):
            self.size += other.size
            return True
        return False


class AllocationManager:
    def __init__(self, p):
        self.blocks = {cls: [] for cls in Block.subclasses}
        self.p = p
        self.new_mapped_blocks = []

    def add_block(self, block):
        self.blocks[type(block)].append(block)
        self.blocks[type(block)].sort()
        self.coalesce(self.blocks[type(block)])

    def _find_in_mapped_blocks(self, size, flag=MemoryFlag.RWX, align=0x1):
        best_fit = None
        for block in self.blocks[MappedBlock]:
            if block.is_free and block.size >= size and block.flag & flag == flag:
                # check for alignment
                offset = align - (block.mem_addr % align)
                if block.size >= size + offset:
                    if block.size == size + offset and offset > 0:
                        block.is_free = False
                        return block
                    elif best_fit is None or block.size < best_fit.size:
                        best_fit = block

        if best_fit:
            # Adjust for alignment
            offset = align - (best_fit.mem_addr % align)
            remaining_size = best_fit.size - size - offset
            allocated_block = MappedBlock(
                best_fit.file_addr + offset,
                best_fit.mem_addr + offset,
                size,
                is_free=False,
                flag=flag,
            )
            self.add_block(allocated_block)
            if offset > 0:
                self.add_block(
                    MappedBlock(
                        best_fit.file_addr,
                        best_fit.mem_addr,
                        offset,
                        is_free=True,
                        flag=flag,
                    )
                )
            best_fit.file_addr += size + offset
            best_fit.mem_addr += size + offset
            best_fit.size = remaining_size
            if best_fit.size == 0:
                self.blocks[MappedBlock].remove(best_fit)
            return allocated_block

    def _create_new_mapped_block(self, size, flag=MemoryFlag.RWX, align=0x1):
        # map 0x1000 bytes # TODO: currently we won't use available file/mem blocks, instead we create new one at the end of the file
        file_addr = None
        mem_addr = None
        for block in self.blocks[FileBlock]:
            if block.size == -1:
                file_addr = block.addr
                block.addr += 0x1000
        for block in self.blocks[MemoryBlock]:
            if block.size == -1:
                # mem_addr % 0x1000 should equal to file_addr % 0x1000 TODO
                mem_addr = block.addr + (file_addr % 0x1000)
                block.addr = mem_addr + 0x1000
        if file_addr and mem_addr:
            self.add_block(
                MappedBlock(file_addr, mem_addr, 0x1000, is_free=True, flag=flag)
            )
            self.new_mapped_blocks.append(
                MappedBlock(file_addr, mem_addr, 0x1000, is_free=True, flag=flag)
            )
            return True
        return False

    def allocate(self, size, flag=MemoryFlag.RWX, align=0x1):
        logger.debug(
            f"allocating size: {size}, flag: {flag.__repr__()}, align: {align}"
        )
        block = self._find_in_mapped_blocks(size, flag, align)
        if block:
            return block
        logger.debug(
            f"memory_allocate: failed to allocate memory of size {size} with flag {flag.__repr__()}, creating new area and retrying"
        )
        if self._create_new_mapped_block(size, flag, align):
            return self.allocate(size, flag, align)
        else:
            raise MemoryError("Insufficient memory")

    def free(self, block):
        block.is_free = True
        self.coalesce(self.blocks[type(block)])

    def coalesce(self, blocks: list):
        for curr, next in zip(blocks, blocks[1:]):
            if curr.coalesce(next):
                blocks.remove(next)
                self.coalesce(blocks)
                return

    def finalize(self):
        for block in self.new_mapped_blocks:
            for mapped_block in self.blocks[MappedBlock]:
                if mapped_block.is_free:
                    if (
                        block.mem_addr + block.size
                        == mapped_block.mem_addr + mapped_block.size
                        and block.mem_addr <= mapped_block.mem_addr
                    ):
                        self.blocks[MappedBlock].remove(mapped_block)
                        block.size -= mapped_block.size
                        return self.finalize()

        for block in self.new_mapped_blocks:
            if block.file_addr + block.size > self.p.binfmt_tool.file_size:
                self.p.binfmt_tool.file_size = block.file_addr + block.size

        logger.debug(f"finalized blocks: {self.blocks}")
        logger.debug(f"new mapped blocks: {self.new_mapped_blocks}")
