import logging, tempfile, os, subprocess, cle

logger = logging.getLogger(__name__)


class Compiler:
    def __init__(self, p):
        self.p = p

    def compile(self, code, base=0, symbols={}, extra_compiler_flags=[], **kwargs):
        with tempfile.TemporaryDirectory() as td:
            # source file
            with open(os.path.join(td, "code.c"), "w") as f:
                f.write(code)

            # linker script
            _symbols = {}
            _symbols.update(self.p.symbols)
            _symbols.update(self.p.binary_analyzer.get_all_symbols())
            _symbols.update(symbols)
            linker_script = (
                "SECTIONS { .text : SUBALIGN(0) { . = " + hex(base) + "; *(.text) "
            )
            for name, addr in _symbols.items():
                linker_script += name + " = " + hex(addr) + ";"
            linker_script += "} }"
            with open(os.path.join(td, "linker.ld"), "w") as f:
                f.write(linker_script)

            # compile to object file
            try:
                args = (
                    [self._compiler]
                    + self._compiler_flags
                    + extra_compiler_flags
                    + [
                        "-c",
                        os.path.join(td, "code.c"),
                        "-o",
                        os.path.join(td, "obj.o"),
                    ]
                )
                subprocess.run(args, check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                logger.error(e.stderr.decode("utf-8"))
                raise e

            # link object file
            try:
                args = [self._linker] + [
                    "-relocatable",
                    os.path.join(td, "obj.o"),
                    "-T",
                    os.path.join(td, "linker.ld"),
                    "-o",
                    os.path.join(td, "obj_linked.o"),
                ]
                subprocess.run(args, check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                logger.error(e.stderr.decode("utf-8"))
                raise e

            # extract compiled code
            ld = cle.Loader(
                os.path.join(td, "obj_linked.o"), main_opts={"base_addr": 0x0}
            )
            compiled = ld.memory.load(
                ld.all_objects[0].entry + base, ld.memory.max_addr
            )
        return compiled
