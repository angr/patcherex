class Patch(object):
    def __init__(self, name):
        self.name = name
        self.dependencies = []
        #TODO patch to string


class InlinePatch(Patch):
    def __init__(self, instruction_addr, new_asm, name=None):
        super(InlinePatch, self).__init__(name)
        self.instruction_addr = instruction_addr
        self.new_asm = new_asm

    def __str__(self):
        return "InlinePatch [%s] %08x (%d)" % (self.name,self.instruction_addr,len(self.new_asm))


class AddRODataPatch(Patch):
    def __init__(self, data, name=None):
        super(AddRODataPatch, self).__init__(name)
        self.data = data

    def __str__(self):
        return "AddRODataPatch [%s] (%d)" % (self.name,len(self.data))

class AddRWDataPatch(Patch):
    def __init__(self, tlen, name=None):
        super(AddRWDataPatch, self).__init__(name)
        assert type(tlen) == int
        self.len = tlen

    def __str__(self):
        return "AddRWDataPatch [%s] (%d)" % (self.name,self.len)

class AddRWInitDataPatch(Patch):
    def __init__(self, data, name=None):
        super(AddRWInitDataPatch, self).__init__(name)
        self.data = data

    def __str__(self):
        return "AddRWInitDataPatch [%s] (%d)" % (self.name,len(self.data))

class AddCodePatch(Patch):
    def __init__(self, asm_code, name=None, is_c=False):
        super(AddCodePatch, self).__init__(name)
        self.asm_code = asm_code
        self.is_c = is_c

    def __str__(self):
        return "AddCodePatch [%s] (%d) %s" % (self.name,len(self.asm_code),self.is_c)


class AddEntryPointPatch(Patch):
    def __init__(self, asm_code, name=None, priority=1):
        super(AddEntryPointPatch, self).__init__(name)
        self.asm_code = asm_code
        self.priority = priority

    def __str__(self):
        return "AddEntryPointPatch [%s] (%d), pr: %d" % (self.name,len(self.asm_code),self.priority)


class InsertCodePatch(Patch):
    def __init__(self, addr, code, name=None, priority=1):
        super(InsertCodePatch, self).__init__(name)
        self.addr = addr
        self.code = code
        self.priority = priority

    def __str__(self):
        return "InsertCodePatch [%s] %08x (%d), pr: %d" % (self.name,self.addr,len(self.code),self.priority)


class RawFilePatch(Patch):
    def __init__(self, file_addr, data, name=None):
        super(RawFilePatch, self).__init__(name)
        self.file_addr = file_addr
        self.data = data

    def __str__(self):
        return "RawFilePatch [%s] %08x (%d)" % (self.name,self.file_addr,len(self.data))


class RawMemPatch(Patch):
    def __init__(self, addr, data, name=None):
        super(RawMemPatch, self).__init__(name)
        self.addr = addr
        self.data = data

    def __str__(self):
        return "RawMemPatch [%s] %08x (%d)" % (self.name,self.addr,len(self.data))

class SegmentHeaderPatch(Patch):
    def __init__(self, segment_headers, name=None):
        super(SegmentHeaderPatch, self).__init__(name)
        self.segment_headers = segment_headers

    def __str__(self):
        return "SegmentHeaderPatch [%s] (%d)" % (self.name,len(self.segment_headers))


