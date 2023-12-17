from .assembler import Assembler
from ..assets.assets import Assets
import logging, os, subprocess, tempfile

logger = logging.getLogger(__name__)


class Bcc(Assembler):
    def __init__(self, p):
        super().__init__(p)
        self.assets_path = Assets("bcc").path

    def _assemble(self, code, base=0, **kwargs):
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "code.s"), "w") as f:
                f.write(f".org {hex(base)}\n")
                f.write(code)
            try:
                subprocess.run(
                    [
                        os.path.join(self.assets_path, "sparc-gaisler-elf-as"),
                        "-Aleon",
                        os.path.join(td, "code.s"),
                        "-o",
                        os.path.join(td, "obj.o"),
                    ],
                    check=True,
                    capture_output=True,
                )
            except subprocess.CalledProcessError as e:
                logger.error(e.stderr.decode("utf-8"))
                raise e
            try:
                subprocess.run(
                    [
                        os.path.join(self.assets_path, "sparc-gaisler-elf-objcopy"),
                        "-O",
                        "binary",
                        "-j",
                        ".text",
                        os.path.join(td, "obj.o"),
                        os.path.join(td, "obj.bin"),
                    ],
                    check=True,
                    capture_output=True,
                )
            except subprocess.CalledProcessError as e:
                logger.error(e.stderr.decode("utf-8"))
                raise e
            with open(os.path.join(td, "obj.bin"), "rb") as f:
                if base != 0:
                    f.seek(base)
                binary = f.read()
                logger.debug(f"Assembled bytes: {bytes(binary)}")
                return bytes(binary)
