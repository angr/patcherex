import keystone, logging, re
from .keystone import Keystone

logger = logging.getLogger(__name__)


class KeystoneSparc(Keystone):
    def _pre_assemble_hook(self, code, base=0):
        # Hack for sparc, remove this hack if keystone supports sparc relative addressing correctly
        # https://www.gaisler.com/doc/sparcv8.pdf
        # call (B.24.), all branches instr (B.21.) jumps to PC + 4ximm, so we need to convert absolute address to relative address
        if self.arch != keystone.KS_ARCH_SPARC:
            return code
        result = ""
        lineno = 0
        for line in code.splitlines():
            line = line.strip()
            if (
                line.startswith(".")
                or line.startswith("#")
                or line == ""
                or line.endswith(":")
            ):
                result += line + "\n"
                continue
            if re.match(r"(call|b|ba) 0x[0-9a-fA-F]+", line):
                instr, addr = line.split(" ")
                addr = int(addr, 16)
                disp = addr - base
                imm = disp >> 2
                logger.debug(
                    f"converting {line} to {instr} {hex(imm)} (base: {hex(base)})"
                )
                if instr == "call":
                    result += f"{instr} {hex(base + imm - lineno)}\n"
                elif instr == "b" or instr == "ba":
                    result += f"{instr} {hex(addr - (4 * lineno))}\n"
            else:
                result += line + "\n"
            lineno += 1
        return result
