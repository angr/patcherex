
import struct

from . import utils
from .utils import ASMConverter
import compilerex


class Patch:
    def __init__(self, name):
        self.name = name
        self.dependencies = []
        #TODO patch to string


class InlinePatch(Patch):
    def __init__(self, instruction_addr, new_asm, name=None, num_instr=1):
        super(InlinePatch, self).__init__(name)
        self.instruction_addr = instruction_addr
        self.num_instr = num_instr
        self.new_asm = new_asm

    def __repr__(self):
        return "InlinePatch [%s] %08x (%d)" % (self.name,self.instruction_addr,len(self.new_asm))


class AddRODataPatch(Patch):
    def __init__(self, data, name=None):
        super(AddRODataPatch, self).__init__(name)
        if not isinstance(data, bytes):
            raise TypeError("Data must be a bytestring.")
        self.data = data

    def __repr__(self):
        return "AddRODataPatch [%s] (%d)" % (self.name,len(self.data))


class AddRWDataPatch(Patch):
    def __init__(self, tlen, name=None):
        super(AddRWDataPatch, self).__init__(name)
        assert type(tlen) == int
        self.len = tlen

    def __repr__(self):
        return "AddRWDataPatch [%s] (%d)" % (self.name,self.len)


class AddRWInitDataPatch(Patch):
    def __init__(self, data, name=None):
        super(AddRWInitDataPatch, self).__init__(name)
        self.data = data
        if not isinstance(data, bytes):
            raise TypeError("Data must be a bytestring.")

    def __repr__(self):
        return "AddRWInitDataPatch [%s] (%d)" % (self.name,len(self.data))


class AddLabelPatch(Patch):
    def __init__(self, addr, name=None, is_global=True):
        super(AddLabelPatch, self).__init__(name)
        self.addr = addr
        self.is_global = is_global

    def __repr__(self):
        return "AddLabelPatch [%s] (%#8x)" % (self.name,self.addr)


class CodePatch(Patch):
    """
    Base class for all code patches
    """
    def __init__(self, name, asm_code, is_c=False, is_att=False, optimization="-Oz", compiler_flags="-m32", is_thumb=False):
        super(CodePatch, self).__init__(name)

        self.asm_code = asm_code
        self.is_c = is_c
        self.optimization = optimization
        self.is_att = is_att
        self.compiler_flags = compiler_flags
        self.is_thumb = is_thumb

    def att_asm(self, c_as_asm=False):
        """
        Get the AT&T style assembly code
        :return: The asm code in AT&T style
        :rtype: str
        """

        if self.is_att:
            return self.asm_code
        if not self.is_c:
            return ASMConverter.intel_to_att(self.asm_code)
        else:
            if not c_as_asm:
                code = utils.compile_c(self.asm_code, optimization=self.optimization,
                                       compiler_flags=self.compiler_flags)
                asm_str = ".byte " + ", ".join([hex(b) for b in code])
                return asm_str
            else:
                return compilerex.c_to_asm(self.asm_code, [self.compiler_flags], syntax="att")

    def intel_asm(self, c_as_asm=False):
        """
        Get the intel style assembly code
        :return: The asm code in intel style
        :rtype: str
        """

        if self.is_att:
            raise NotImplementedError("Conversion of Intel to ATT syntax not supported")

        if not self.is_c:
            return self.asm_code
        else:
            if not c_as_asm:
                code = utils.compile_c(self.asm_code, optimization=self.optimization,
                                       compiler_flags=self.compiler_flags)
                asm_str = ".byte " + ", ".join([hex(b) for b in code])
                return asm_str
            else:
                return compilerex.c_to_asm(self.asm_code, [self.compiler_flags], syntax="intel")


class AddCodePatch(CodePatch):
    def __init__(self, asm_code, name=None, is_c=False, is_att=False, optimization="-Oz", compiler_flags="-m32", is_thumb=False):
        super(AddCodePatch, self).__init__(name, asm_code, is_c=is_c, is_att=is_att,
                                           optimization=optimization, compiler_flags=compiler_flags, is_thumb=is_thumb)

    def __repr__(self):
        return "AddCodePatch [%s] (%d) %s %s" % (self.name,len(self.asm_code),self.is_c,self.optimization)


class AddEntryPointPatch(CodePatch):
    def __init__(self, asm_code, name=None, is_att=False, priority=1, after_restore=False, is_thumb=True):
        super(AddEntryPointPatch, self).__init__(name, asm_code, is_att=is_att, is_thumb=is_thumb)
        self.priority = priority
        self.after_restore = after_restore

    def __repr__(self):
        return "AddEntryPointPatch [%s] (%d), pr: %d, %s" % (self.name,len(self.asm_code),self.priority,
                self.after_restore)


class InsertCodePatch(CodePatch):
    def __init__(self, addr, code, name=None, is_att=False, priority=1, stackable=False):
        super(InsertCodePatch, self).__init__(name, asm_code=code, is_att=is_att)
        self.addr = addr
        self.priority = priority
        self.stackable = stackable

    @property
    def code(self):
        return self.asm_code

    def __repr__(self):
        return "InsertCodePatch [%s] %08x (%d), pr: %d" % (self.name,self.addr,len(self.code),self.priority)

class ReplaceFunctionPatch(CodePatch):
    def __init__(self, addr, size, code, name=None, is_att=False, priority=1, symbols=None):
        super(ReplaceFunctionPatch, self).__init__(name, asm_code=code, is_att=is_att)
        self.addr = addr
        self.size = size
        self.symbols = symbols
        self.priority = priority

    def __repr__(self):
        return "ReplaceFunctionPatch [%s] %08x (%d), pr: %d" % (self.name,self.addr,len(self.asm_code),self.priority)


class RawFilePatch(Patch):

    def __init__(self, file_addr, data, name=None):
        super(RawFilePatch, self).__init__(name)
        self.file_addr = file_addr
        self.data = data

    def __repr__(self):
        return "RawFilePatch [%s] %08x (%d)" % (self.name,self.file_addr,len(self.data))


class RawMemPatch(Patch):
    def __init__(self, addr, data, name=None):
        super(RawMemPatch, self).__init__(name)
        self.addr = addr
        if not isinstance(data, bytes):
            raise TypeError("Data must be a bytestring.")
        self.data = data

    def __repr__(self):
        return "RawMemPatch [%s] %08x (%d)" % (self.name,self.addr,len(self.data))


class SegmentHeaderPatch(Patch):
    def __init__(self, segment_headers, name=None):
        super(SegmentHeaderPatch, self).__init__(name)
        self.segment_headers = segment_headers

    def __repr__(self):
        return "SegmentHeaderPatch [%s] (%d)" % (self.name,len(self.segment_headers))


class AddSegmentHeaderPatch(Patch):
    def __init__(self, new_segment, name=None):
        super(AddSegmentHeaderPatch, self).__init__(name)
        self.new_segment = new_segment

    def __str__(self):
        return "AddSegmentHeaderPatch [%s] (%s)" % (self.name,map(hex,self.new_segment))


class PointerArrayPatch(Patch):
    def __init__(self, addr, pointers, name=None):
        super(PointerArrayPatch, self).__init__(name)
        self.addr = addr
        self.pointers = pointers
        self.data = b"".join([ struct.pack("<I", p) for p in self.pointers ])

    def __repr__(self):
        return "PointerArrayPatch [%s] %#08x (%d)" % (self.name, self.addr, len(self.data))


class RemoveInstructionPatch(Patch):
    def __init__(self, ins_addr, ins_size, name=None):
        super(RemoveInstructionPatch, self).__init__(name)

        self.ins_addr = ins_addr
        self.ins_size = ins_size

    def __repr__(self):
        size = str(self.ins_size) if self.ins_size else "(unknown)"
        return "RemoveInstructionPatch @ %#x, %s bytes" % (self.ins_addr, size)
