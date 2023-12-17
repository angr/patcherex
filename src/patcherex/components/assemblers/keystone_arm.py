import keystone
from .assembler import Assembler
import logging

logger = logging.getLogger(__name__)


class KeystoneArm(Assembler):
    def __init__(self, p):
        super().__init__(p)
        self.ks_arm = keystone.Ks(
            keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM + keystone.KS_MODE_LITTLE_ENDIAN
        )
        self.ks_thumb = keystone.Ks(
            keystone.KS_ARCH_ARM,
            keystone.KS_MODE_THUMB + keystone.KS_MODE_LITTLE_ENDIAN,
        )

    def _assemble(self, code, base=0, is_thumb=False):
        ks = self.ks_thumb if is_thumb else self.ks_arm
        binary, _ = ks.asm(code, base)
        logger.debug(f"Assembled bytes: {bytes(binary)}")
        return bytes(binary)
