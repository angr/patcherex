#pylint: disable=import-error,no-self-use
import idaapi
import idc
import string

class GenericPatchWidget(idaapi.Form):

    def get_patch_address(self):
        return 0

    def get_patch_name(self):
        return ""

    def get_patch_data(self):
        return ""

    @classmethod
    def on_perform_post_operations(cls, patch_type, name, address, data):
        pass

    @classmethod
    def on_pre_update(cls, patch_type, name, address, data):
        pass

    @classmethod
    def on_post_update(cls, patch_type, name, address, data):
        pass

    @classmethod
    def on_delete(cls, patch_type, name, address, data):
        pass

    @classmethod
    def get_gui_format_of(cls, patch_type, address, name, data):
        return list(map(str, [patch_type, address, name, data]))

class AddLabelPatchWidget(GenericPatchWidget):
    form_code = r"""STARTITEM 0
Edit Label Patch
<Address:{patch_address}>
<Name:{patch_name}>
"""
    patch_type = "AddLabelPatch"
    comment_format = "Add label '%s' at %#x"

    def __init__(self, address=None, name="AddRODataPatch", data=None):
        address = address if address else idc.get_screen_ea()
        super(AddLabelPatchWidget, self).__init__(self.form_code, {
            "patch_address": idaapi.Form.NumericInput(tp=idaapi.Form.FT_ADDR, value=address),
            "patch_name": idaapi.Form.StringInput(value=str(name)),
        })

    def get_patch_address(self):
        return self.patch_address.value

    def get_patch_name(self):
        return self.patch_name.value

    def get_patch_data(self):
        return {"addr": self.get_patch_address(), "name": self.get_patch_name(), "is_global": True}

    @classmethod
    def on_perform_post_operations(cls, patch_type, name, address, data):
        original = idc.get_cmt(address, 1)
        if original is not None:
            prefix = original + "\n"
        else:
            prefix = ""
        idc.set_cmt(address,
                    str(prefix + cls.comment_format % (name, address)),
                    1)

    @classmethod
    def on_pre_update(cls, patch_type, name, address, data):
        added_comment = str(cls.comment_format % (name, address))
        if idc.get_cmt(address, 1) is not None and added_comment in idc.get_cmt(address, 1):
            comment = idc.get_cmt(address, 1).replace("\n" + added_comment, "").replace(added_comment, "")
            idc.set_cmt(address, comment, 1)

    @classmethod
    def on_post_update(cls, patch_type, name, address, data):
        cls.on_perform_post_operations(patch_type, name, address, data)

    @classmethod
    def on_delete(cls, patch_type, name, address, data):
        cls.on_pre_update(patch_type, name, address, data)

    @classmethod
    def get_gui_format_of(cls, patch_type, name, address, data):
        if patch_type != cls.patch_type:
            print("Got patch type %s, but expected \"%s\"" % (patch_type, cls.patch_type))
        new_patch_type = "Add Label"
        new_address = "%#x" % address
        new_name = name
        new_data = ""
        return list(map(str, [new_patch_type, new_address, new_name, new_data]))

class AddRODataPatchWidget(GenericPatchWidget):
    form_code = r"""STARTITEM 0
Edit Read Only Data Insertion Patch
<Name:{patch_name}>
<Hex:{rHex}>
<Raw Bytes:{rRaw}>{type_group}>
<Data (hexidecimal, non hex characters ignored):{ro_data}>
"""
    patch_type = "AddRODataPatch"

    def __init__(self, address=0, name="AddRODataPatch", data={"data": []}):
        assert type(data['data']) is list and (not data['data'] or type(data['data'][0]) is int)
        init_bytes = bytes(data["data"])
        formatted = (self.format_byte_string(init_bytes) if address == 0 else init_bytes)
        super(AddRODataPatchWidget, self).__init__(self.form_code, {
            "patch_name": idaapi.Form.StringInput(value=str(name)),
            "type_group": idaapi.Form.RadGroupControl(("rHex", "rRaw"), value=address),
            "ro_data": idaapi.Form.MultiLineTextControl(text=formatted,
                                                        flags=idaapi.Form.MultiLineTextControl.TXTF_FIXEDFONT)
            })

    @staticmethod
    def format_byte_string(byte_string):
        if type(byte_string) is not bytes:
            print(repr(byte_string))
            print(repr(byte_string))
            print(repr(byte_string))
            print(repr(byte_string))
            print(repr(byte_string))
            # import ipdb; ipdb.set_trace()
        return ' '.join(f'{byte:02x}' for byte in byte_string)

    def get_patch_address(self): # Use the address to store whether or not it's raw
        return self.type_group.value

    def get_patch_name(self):
        return self.patch_name.value

    def get_patch_data(self):
        assert type(self.ro_data.value) is str
        v = self.ro_data.value.encode()

        if self.rHex.selected:
            stripped = ''.join(chr(b) for b in v if chr(b) in string.hexdigits)
            final = bytes.fromhex(stripped)
        else:
            final = v
        return {"data": list(final), "name": self.get_patch_name()}

    @classmethod
    def get_gui_format_of(cls, patch_type, name, address, data):
        print(repr(data))
        if patch_type != cls.patch_type:
            print("Got patch type %s, but expected \"%s\"" % (patch_type, cls.patch_type))
        new_patch_type = "Insert RO Data"
        new_address = ""
        new_name = name

        new_data = (cls.format_byte_string(bytes(data["data"])) if address == 0
                    else bytes(data["data"]))
        return list(map(str, [new_patch_type, new_address, new_name, new_data]))

class AddRWDataPatchWidget(GenericPatchWidget):
    form_code = r"""STARTITEM 0
Edit Read/Write Data Addition Patch
<Name:{patch_name}>
<Size:{patch_size}>
"""
    patch_type = "AddRWDataPatch"

    def __init__(self, address=None, name="AddRWDataPatch", data={"tlen": 0}):
        init_len = data["tlen"]
        super(AddRWDataPatchWidget, self).__init__(self.form_code, {
            "patch_name": idaapi.Form.StringInput(value=str(name)),
            "patch_size": idaapi.Form.NumericInput(value=init_len, tp=idaapi.Form.FT_HEX),
            })

    def get_patch_address(self):
        return ""

    def get_patch_name(self):
        return self.patch_name.value

    def get_patch_length(self):
        return self.patch_size.value

    def get_patch_data(self):
        return {"tlen": self.get_patch_length(), "name": self.get_patch_name()}

    @classmethod
    def get_gui_format_of(cls, patch_type, name, address, data):
        if patch_type != cls.patch_type:
            print("Got patch type %s, but expected \"%s\"" % (patch_type, cls.patch_type))
        new_patch_type = "Insert RW Data"
        new_address = ""
        new_name = name
        new_data = "Length: %#x" % data["tlen"]
        return list(map(str, [new_patch_type, new_address, new_name, new_data]))

class InsertCodePatchWidget(GenericPatchWidget):

    form_code = r"""STARTITEM 0
Edit Code Insertion Patch
<Address:{patch_address}>
<Name:{patch_name}>
<Code:{patch_code}>
"""
    patch_type = "InsertCodePatch"
    comment_format = "'%s': Insert code at %#x:\n%s"

    def __init__(self, address=None, name="InsertCodePatch", data={"code": ""}):
        address = address if address else idc.get_screen_ea()
        super(InsertCodePatchWidget, self).__init__(self.form_code, {
            "patch_address": idaapi.Form.NumericInput(tp=idaapi.Form.FT_ADDR, value=address),
            "patch_name": idaapi.Form.StringInput(value=str(name)),
            "patch_code": idaapi.Form.MultiLineTextControl(text=str(data["code"]),
                                                           flags=idaapi.Form.MultiLineTextControl.TXTF_FIXEDFONT),
        })

    def get_patch_address(self):
        return self.patch_address.value

    def get_patch_name(self):
        return self.patch_name.value

    def get_patch_data(self):
        return {"code": self.patch_code.value, "addr": self.get_patch_address(), "name": self.get_patch_name()}

    @classmethod
    def on_perform_post_operations(cls, patch_type, name, address, data):
        original = idc.get_cmt(address, 1)
        if original is not None:
            prefix = original + "\n"
        else:
            prefix = ""
        idc.set_cmt(address,
                    str(prefix + cls.comment_format % (name, address, data["code"])),
                    1)

    @classmethod
    def on_pre_update(cls, patch_type, name, address, data):
        added_comment = str(cls.comment_format % (name, address, data["code"]))
        if idc.get_cmt(address, 1) is not None and added_comment in idc.get_cmt(address, 1):
            comment = idc.get_cmt(address, 1).replace("\n" + added_comment, "").replace(added_comment, "")
            idc.set_cmt(address, comment, 1)

    @classmethod
    def on_post_update(cls, patch_type, name, address, data):
        cls.on_perform_post_operations(patch_type, name, address, data)

    @classmethod
    def on_delete(cls, patch_type, name, address, data):
        cls.on_pre_update(patch_type, name, address, data)

    @classmethod
    def get_gui_format_of(cls, patch_type, address, name, data):
        if patch_type != cls.patch_type:
            print("Got patch type %s, but expected \"%s\"" % (patch_type, cls.patch_type))
        new_patch_type = "Insert Code"
        new_address = "%#x" % address
        new_name = name
        new_data = data["code"].split("\n")[0]
        if len(data["code"].split("\n")) > 1:
            new_data = new_data + " . . ."
        return list(map(str, [new_patch_type, new_address, new_name, new_data]))


class AddCodePatchWidget(GenericPatchWidget):

    form_code = r"""STARTITEM 0
Edit Code Addition Patch
<Name:{patch_name}>
<Assembly Code:{rASMCode}>
<C Code:{rCCode}>{type_group}>
<Code:{patch_code}>
"""
    patch_type = "AddCodePatch"

    def __init__(self, address=None, name="AddCodePatch", data={"asm_code": "", "is_c": False}):
        super(AddCodePatchWidget, self).__init__(self.form_code, {
            "patch_name": idaapi.Form.StringInput(value=str(name)),
            "type_group": idaapi.Form.RadGroupControl(("rASMCode", "rCCode"), value=(1 if data["is_c"] else 0)),
            "patch_code": idaapi.Form.MultiLineTextControl(text=str(data["asm_code"]),
                                                           flags=idaapi.Form.MultiLineTextControl.TXTF_FIXEDFONT),
        })

    def get_patch_address(self):
        return ""

    def get_patch_name(self):
        return self.patch_name.value

    def get_patch_data(self):
        info = idaapi.get_inf_structure()
        flags = "-m64" if info.is_64bit() else "-m32"
        return {"asm_code": self.patch_code.value, "is_c": self.rCCode.selected,
                "name": self.get_patch_name(), "compiler_flags": flags}

    @classmethod
    def get_gui_format_of(cls, patch_type, address, name, data):
        if patch_type != cls.patch_type:
            print("Got patch type %s, but expected \"%s\"" % (patch_type, cls.patch_type))
        new_patch_type = "Add Code"
        new_address = ""
        new_name = name
        new_data = data["asm_code"].split("\n")[0]
        if len(data["asm_code"].split("\n")) > 1:
            new_data = new_data + " . . ."
        return list(map(str, [new_patch_type, new_address, new_name, new_data]))


class RemoveInstructionPatchWidget(GenericPatchWidget):
    form_code = r"""STARTITEM 0
Edit Remove Instruction Patch
<Address:{patch_address}>
<Name:{patch_name}>
"""
    patch_type = "RemoveInstructionPatch"
    comment_format = "'%s': Remove instruction at %#x"

    def __init__(self, address=None, name="RemoveInstructionPatch", data=None):
        address = address if address else idc.get_screen_ea()
        super(RemoveInstructionPatchWidget, self).__init__(self.form_code, {
            "patch_address": idaapi.Form.NumericInput(tp=idaapi.Form.FT_ADDR, value=address),
            "patch_name": idaapi.Form.StringInput(value=str(name)),
        })

    def get_patch_address(self):
        return self.patch_address.value

    def get_patch_name(self):
        return self.patch_name.value

    def get_patch_data(self):
        return {"ins_addr": self.get_patch_address(), "ins_size": None, "name": self.get_patch_name()}

    @classmethod
    def on_perform_post_operations(cls, patch_type, name, address, data):
        original = idc.get_cmt(address, 1)
        if original is not None:
            prefix = original + "\n"
        else:
            prefix = ""
        idc.set_cmt(address,
                    str(prefix + cls.comment_format % (name, address)),
                    1)

    @classmethod
    def on_pre_update(cls, patch_type, name, address, data):
        added_comment = str(cls.comment_format % (name, address))
        if idc.get_cmt(address, 1) is not None and added_comment in idc.get_cmt(address, 1):
            comment = idc.get_cmt(address, 1).replace("\n" + added_comment, "").replace(added_comment, "")
            idc.set_cmt(address, comment, 1)

    @classmethod
    def on_post_update(cls, patch_type, name, address, data):
        cls.on_perform_post_operations(patch_type, name, address, data)

    @classmethod
    def on_delete(cls, patch_type, name, address, data):
        cls.on_pre_update(patch_type, name, address, data)

    @classmethod
    def get_gui_format_of(cls, patch_type, name, address, data):
        if patch_type != cls.patch_type:
            print("Got patch type %s, but expected \"%s\"" % (patch_type, cls.patch_type))
        new_patch_type = "Remove Instruction"
        new_address = "%#x" % address
        new_name = name
        new_data = ""
        return list(map(str, [new_patch_type, new_address, new_name, new_data]))



class SaveWidget(idaapi.Form):

    form_code = r"""STARTITEM 0
Save Patch List
<File:{file_opener}>
"""

    def __init__(self):
        self.inc = 0
        super(SaveWidget, self).__init__(self.form_code, {
            "file_opener": idaapi.Form.FileInput(open=True),
        })

    def get_file_name(self):
        return self.file_opener.value


class LoadWidget(idaapi.Form):

    form_code = r"""STARTITEM 0
Load Patch List
<File:{file_opener}>
"""

    def __init__(self):
        self.inc = 0
        super(LoadWidget, self).__init__(self.form_code, {
            "file_opener": idaapi.Form.FileInput(open=True),
        })

    def get_file_name(self):
        return self.file_opener.value


class RunPatcherexWidget(idaapi.Form):

    form_code = r"""STARTITEM 0
Patcherex Output Options
<Output file:{file_opener}>
"""

    def __init__(self):
        self.inc = 0
        super(RunPatcherexWidget, self).__init__(self.form_code, {
            "file_opener": idaapi.Form.FileInput(open=True),
        })

    def get_file_name(self):
        return self.file_opener.value


class PatchTypeWidget(idaapi.Form):

    form_code = r"""STARTITEM 0
Select Patch Type
%s{radio}>
"""
    line_template = "<%s:{%s}>"

    def __init__(self, types):
        filler = []
        for patch_type in types:
            filler.append(self.line_template % (types[patch_type]["desc"], patch_type))
        filled_form_code = self.form_code % '\n'.join(filler)
        self.type_keys = list(types.keys())
        super(PatchTypeWidget, self).__init__(filled_form_code, {
            "radio": idaapi.Form.RadGroupControl(tuple(types.keys()))
        })

    def Compile(self):
        ret = super(PatchTypeWidget, self).Compile()
        getattr(self, self.type_keys[0]).selected = True
        return ret

    def get_chosen_patch_type(self):
        return self.type_keys[self.radio.value]
