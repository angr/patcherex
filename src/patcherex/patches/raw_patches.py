from .patch import Patch
import logging

logger = logging.getLogger(__name__)


class ModifyRawBytesPatch(Patch):
    def __init__(self, addr, new_bytes, addr_type="mem") -> None:
        self.addr = addr
        self.new_bytes = new_bytes
        self.addr_type = addr_type

    def apply(self, p):
        if self.addr_type == "raw":
            offset = self.addr
        elif self.addr_type == "mem":
            offset = p.binary_analyzer.mem_addr_to_file_offset(self.addr)
            if not offset:
                logger.warning(
                    "failed to convert mem addr to file offset, will just default to raw addr"
                )
                offset = self.addr
        else:
            raise NotImplementedError()
        p.binfmt_tool.update_binary_content(offset, self.new_bytes)
