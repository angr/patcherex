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


class AddDataPatch(Patch):
    def __init__(self, data, name=None):
        super(AddDataPatch, self).__init__(name)
        self.data = data

    def __str__(self):
        return "AddDataPatch [%s] (%d)" % (self.name,len(self.data))


class AddCodePatch(Patch):
    def __init__(self, asm_code, name=None):
        super(AddCodePatch, self).__init__(name)
        self.asm_code = asm_code

    def __str__(self):
        return "AddCodePatch [%s] (%d)" % (self.name,len(self.asm_code))


class AddEntryPointPatch(Patch):
    def __init__(self, asm_code, name=None, priority=1):
        super(AddEntryPointPatch, self).__init__(name)
        self.asm_code = asm_code
        self.priority = priority

    def __str__(self):
        return "AddEntryPointPatch [%s] (%d), %d" % (self.name,len(self.asm_code),self.priority)


class InsertCodePatch(Patch):
    def __init__(self, addr, code, name=None):
        super(InsertCodePatch, self).__init__(name)
        self.addr = addr
        self.code = code

    def __str__(self):
        return "InsertCodePatch [%s] %08x (%d)" % (self.name,self.addr,len(self.code))


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
        return "RawFilePatch [%s] %08x (%d)" % (self.name,self.addr,len(self.data))


