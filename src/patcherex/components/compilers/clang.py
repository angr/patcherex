from .compiler import Compiler
import logging

logger = logging.getLogger(__name__)


class Clang(Compiler):
    def __init__(self, p, clang_version=15, compiler_flags=[]):
        super().__init__(p)
        self._compiler = f"clang-{clang_version}"
        self._linker = f"ld.lld-{clang_version}"
        self._compiler_flags = compiler_flags
