import keystone
from .assembler import Assembler
import logging

logger = logging.getLogger(__name__)


class Keystone(Assembler):
    def __init__(self, p, arch, mode):
        super().__init__(p)
        self.arch = arch
        self.mode = mode
        self.ks = keystone.Ks(arch, mode)

    def _assemble(self, code, base=0, **kwargs):
        binary, _ = self.ks.asm(code, base)
        logger.debug(f"Assembled bytes: {bytes(binary)}")
        return bytes(binary)
