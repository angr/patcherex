from .assembler import Assembler
from ..assets.assets import Assets
import logging, os, subprocess, tempfile, re

logger = logging.getLogger(__name__)


class PpcVle(Assembler):
    def __init__(self, p):
        super().__init__(p)
        self.assets_path = Assets("ppc_vle").path

    def _assemble(self, code, base=0, **kwargs):
        code = re.subn(r"\br(\d+)\b", r"\1", code)[0]

        if base is not None:
            # produce a list of {instr_offset: instr} pairs
            branch_instrs = {}
            instr_count = 0
            for line in code.splitlines():
                line = line.strip()
                if (
                    line.startswith(".")
                    or line.startswith("#")
                    or line == ""
                    or line.endswith(":")
                ):
                    continue
                # if line matches "b 0x*" or "bl 0x*", add it to the branch_instrs dict
                if re.match(r"b[a-z]* 0x[0-9a-fA-F]+", line):
                    branch_instrs[instr_count] = line
                instr_count += 1

            for i in range(instr_count):
                if i in branch_instrs:
                    branch_instrs[i] = (
                        branch_instrs[i].split(" ")[0]
                        + " "
                        + hex(int(branch_instrs[i].split(" ")[1], 16) - base - 4 * i)
                    )

            instr_count = 0
            for line_count, line in enumerate(code.splitlines()):
                if (
                    line.startswith(".")
                    or line.startswith("#")
                    or line == ""
                    or line.endswith(":")
                ):
                    continue
                if instr_count in branch_instrs:
                    code = code.splitlines()
                    code[line_count] = branch_instrs[instr_count]
                    code = "\n".join(code)
                instr_count += 1

        # set base address
        if base is not None:
            code = f".org {hex(base)}\n" + code

        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "code.s"), "w") as f:
                f.write(code)
            try:
                subprocess.run(
                    [
                        os.path.join(self.assets_path, "powerpc-eabivle-as"),
                        "-o",
                        os.path.join(td, "obj.o"),
                        os.path.join(td, "code.s"),
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
                        os.path.join(self.assets_path, "powerpc-eabivle-objcopy"),
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
