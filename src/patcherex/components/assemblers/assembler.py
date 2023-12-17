import logging

logger = logging.getLogger(__name__)


class Assembler:
    def __init__(self, p):
        self.p = p

    def resolve_symbols(self, code, symbols={}):
        _symbols = {}
        _symbols.update(self.p.symbols)
        _symbols.update(self.p.binary_analyzer.get_all_symbols())
        _symbols.update(symbols)

        for symbol, addr in _symbols.items():
            code = code.replace(f"{{{symbol}}}", hex(addr))
        return code

    def _assemble(self, code, base=0, **kwargs):
        raise NotImplementedError()

    def _pre_assemble_hook(self, code, base=0):
        return code

    def assemble(self, code, base=0, symbols={}, **kwargs):
        logger.debug(f"Assembling `{code}` at {hex(base)}")
        code = self.resolve_symbols(code, symbols=symbols)
        code = self._pre_assemble_hook(code, base=base)

        return self._assemble(code, base=base, **kwargs)
