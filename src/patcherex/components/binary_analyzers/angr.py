from .binary_analyzer import BinaryAnalyzer
import angr
from archinfo import ArchARM
import logging

logger = logging.getLogger(__name__)


class Angr(BinaryAnalyzer):
    _DEFAULT_LOAD_BASE = 0x400000

    def __init__(self, binary_path, **kwargs) -> None:
        self.binary_path = binary_path
        self.kwargs = kwargs
        self._p = None
        self._cfg = None

    def normalize_addr(self, addr):
        if self.p.loader.main_object.pic:
            return addr - self._DEFAULT_LOAD_BASE
        return addr

    def denormalize_addr(self, addr):
        if self.p.loader.main_object.pic:
            return addr + self._DEFAULT_LOAD_BASE
        return addr

    @property
    def p(self):
        if self._p is None:
            logger.info("Loading binary with angr")
            if "load_options" not in self.kwargs:
                self.kwargs["load_options"] = {"auto_load_libs": False}
            self._p = angr.Project(self.binary_path, **self.kwargs)
            logger.info("Loaded binary with angr")
        return self._p

    @property
    def cfg(self):
        if self._cfg is None:
            logger.info("Generating CFG with angr")
            self._cfg = self.p.analyses.CFGFast(
                normalize=True, data_references=True, force_complete_scan=False
            )
            logger.info("Generated CFG with angr")
        return self._cfg

    def mem_addr_to_file_offset(self, addr):
        addr = self.denormalize_addr(addr)
        file_addr = self.p.loader.main_object.addr_to_offset(addr)
        if file_addr is None:
            logger.error(
                f"Cannot convert memory address {hex(addr)} to file offset, will use the memory address instead"
            )
            return addr
        return file_addr

    def get_basic_block(self, addr):
        if self.is_thumb(addr):
            addr += 1
        addr = self.denormalize_addr(addr)
        bb = None
        for node in self.cfg.model.nodes():
            if addr in node.instruction_addrs:
                bb = node
                break
        assert bb is not None
        return {
            "start": self.normalize_addr(bb.addr),
            "end": self.normalize_addr(bb.addr + bb.size),
            "size": bb.size,
            "instruction_addrs": [
                self.normalize_addr(addr)
                - (1 if self.is_thumb(self.normalize_addr(addr)) else 0)
                for addr in bb.instruction_addrs
            ],
        }

    def get_instr_bytes_at(self, addr):
        addr = self.denormalize_addr(addr)
        addr += 1 if self.is_thumb(addr) else 0
        return self.p.factory.block(addr, num_inst=1).bytes

    def get_unused_funcs(self):
        logger.info("Getting unused functions with angr")
        unused_funcs = []
        assert self.cfg is not None
        for func in self.p.kb.functions.values():
            if func.size == 0:
                continue
            for dst, xrefs in self.p.kb.xrefs.xrefs_by_dst.items():
                if dst == func.addr:
                    break
            else:
                unused_funcs.append(
                    {
                        "addr": self.normalize_addr(func.addr)
                        - (1 if self.is_thumb(self.normalize_addr(func.addr)) else 0),
                        "size": func.size,
                    }
                )
        return unused_funcs

    def get_all_symbols(self):
        assert self.cfg is not None
        logger.info("Getting all symbols with angr")
        symbols = {}
        for symbol in self.p.loader.main_object.symbols:
            if not symbol.name or not symbol.is_function:
                continue
            symbols[symbol.name] = self.normalize_addr(symbol.rebased_addr)
        for func in self.p.kb.functions.values():
            if func.is_simprocedure or func.is_alignment:
                continue
            symbols[func.name] = self.normalize_addr(func.addr)
        return symbols

    def get_function(self, name_or_addr):
        assert self.cfg is not None
        if isinstance(name_or_addr, (str, int)):
            if isinstance(name_or_addr, int):
                name_or_addr += 1 if self.is_thumb(name_or_addr) else 0
                name_or_addr = self.denormalize_addr(name_or_addr)
            if name_or_addr in self.p.kb.functions:
                func = self.p.kb.functions[name_or_addr]
                return {
                    "addr": self.normalize_addr(func.addr)
                    - (1 if self.is_thumb(self.normalize_addr(func.addr)) else 0),
                    "size": func.size,
                }
            return None
        else:
            raise Exception(f"Invalid type for name_or_addr: {type(name_or_addr)}")

    def is_thumb(self, addr):
        if not isinstance(self.p.arch, ArchARM):
            return False
        addr = self.denormalize_addr(addr)

        for node in self.cfg.model.nodes():
            if addr in node.instruction_addrs:
                return node.thumb
        else:
            if addr % 2 == 0:
                return self.is_thumb(self.normalize_addr(addr + 1))
            else:
                logger.error(f"Cannot find a block containing address {hex(addr)}")
                return False
