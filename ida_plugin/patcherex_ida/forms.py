#pylint: disable=import-error,no-self-use
import idaapi
import idc
import string

class GenericPatchForm(idaapi.Form):

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
        return map(str, [patch_type, address, name, data])

class AddLabelPatchForm(GenericPatchForm):
    form_code = r"""STARTITEM 0
Edit Label Patch
<Address:{patch_address}>
<Name:{patch_name}>
"""
    patch_type = "AddLabelPatch"
    comment_format = "Patcherex patch to add a label '%s' at %#x"

    def __init__(self, address=None, name="AddRODataPatch", data=None):
        address = address if address else idc.ScreenEA()
        super(AddLabelPatchForm, self).__init__(self.form_code, {
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
        original = idc.RptCmt(address)
        if original is not None:
            prefix = original + "\n"
        else:
            prefix = ""
        idc.MakeRptCmt(address,
                       str(prefix + cls.comment_format % (name, address)))

    @classmethod
    def on_pre_update(cls, patch_type, name, address, data):
        added_comment = str(cls.comment_format % (name, address))
        if idc.RptCmt(address) is not None and added_comment in idc.RptCmt(address):
            idc.MakeRptCmt(address, idc.RptCmt(address).replace("\n" + added_comment, ""))
            idc.MakeRptCmt(address, idc.RptCmt(address).replace(added_comment, ""))

    @classmethod
    def on_post_update(cls, patch_type, name, address, data):
        cls.on_perform_post_operations(patch_type, name, address, data)

    @classmethod
    def on_delete(cls, patch_type, name, address, data):
        cls.on_pre_update(patch_type, name, address, data)

    @classmethod
    def get_gui_format_of(cls, patch_type, name, address, data):
        if patch_type != cls.patch_type:
            print "Got patch type %s, but expected \"%s\"" % (patch_type, cls.patch_type)
        new_patch_type = "Add Label"
        new_address = hex(long(address))[:-1]
        new_name = name
        new_data = ""
        return map(str, [new_patch_type, new_address, new_name, new_data])

class AddRODataPatchForm(GenericPatchForm):
    form_code = r"""STARTITEM 0
Edit Read Only Data Insertion Patch
<Name:{patch_name}>
<Data (hexidecimal, non hex characters ignored):{ro_data}>
"""
    patch_type = "AddRODataPatch"

    def __init__(self, address=None, name="AddRODataPatch", data={"data": u""}):
        init_bytes = str(data["data"].encode("latin1"))
        formatted = self.format_byte_string(init_bytes)
        super(AddRODataPatchForm, self).__init__(self.form_code, {
            "patch_name": idaapi.Form.StringInput(value=str(name)),
            "ro_data": idaapi.Form.MultiLineTextControl(text=str(formatted),
                                                        flags=idaapi.Form.MultiLineTextControl.TXTF_FIXEDFONT)
            })

    @staticmethod
    def format_byte_string(byte_string):
        return ' '.join(byte.encode("hex") for byte in byte_string)

    def get_patch_address(self):
        return ""

    def get_patch_name(self):
        return self.patch_name.value

    def get_patch_data(self):
        stripped = ''.join(char for char in self.ro_data.value if char in string.hexdigits)
        final = stripped.decode("hex").decode("latin1")
        return {"data": final, "name": self.get_patch_name()}

    @classmethod
    def get_gui_format_of(cls, patch_type, name, address, data):
        if patch_type != cls.patch_type:
            print "Got patch type %s, but expected \"%s\"" % (patch_type, cls.patch_type)
        new_patch_type = "Insert RO Data"
        new_address = ""
        new_name = name
        new_data = cls.format_byte_string(str(data["data"].encode("latin1")))
        return map(str, [new_patch_type, new_address, new_name, new_data])

class InsertCodePatchForm(GenericPatchForm):

    form_code = r"""STARTITEM 0
Edit Code Insertion Patch
<Address:{patch_address}>
<Name:{patch_name}>
<Code:{patch_code}>
"""
    patch_type = "InsertCodePatch"
    comment_format = "Patcherex patch '%s' to insert code at %#x:\n%s"

    def __init__(self, address=None, name="InsertCodePatch", data={"code": ""}):
        address = address if address else idc.ScreenEA()
        super(InsertCodePatchForm, self).__init__(self.form_code, {
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
        original = idc.RptCmt(address)
        if original is not None:
            prefix = original + "\n"
        else:
            prefix = ""
        idc.MakeRptCmt(address,
                       str(prefix + cls.comment_format % (name, address, data["code"])))

    @classmethod
    def on_pre_update(cls, patch_type, name, address, data):
        added_comment = str(cls.comment_format % (name, address, data["code"]))
        if idc.RptCmt(address) is not None and added_comment in idc.RptCmt(address):
            idc.MakeRptCmt(address, idc.RptCmt(address).replace("\n" + added_comment, ""))
            idc.MakeRptCmt(address, idc.RptCmt(address).replace(added_comment, ""))

    @classmethod
    def on_post_update(cls, patch_type, name, address, data):
        cls.on_perform_post_operations(patch_type, name, address, data)

    @classmethod
    def on_delete(cls, patch_type, name, address, data):
        cls.on_pre_update(patch_type, name, address, data)

    @classmethod
    def get_gui_format_of(cls, patch_type, address, name, data):
        if patch_type != cls.patch_type:
            print "Got patch type %s, but expected \"%s\"" % (patch_type, cls.patch_type)
        new_patch_type = "Insert Code"
        new_address = hex(long(address))[:-1]
        new_name = name
        new_data = data["code"].split("\n")[0]
        if len(data["code"].split("\n")) > 1:
            new_data = new_data + " . . ."
        return map(str, [new_patch_type, new_address, new_name, new_data])


class SaveForm(idaapi.Form):

    form_code = r"""STARTITEM 0
Save Patch List
<File:{file_opener}>
"""

    def __init__(self):
        self.inc = 0
        super(SaveForm, self).__init__(self.form_code, {
            "file_opener": idaapi.Form.FileInput(open=True),
        })

    def get_file_name(self):
        return self.file_opener.value


class LoadForm(idaapi.Form):

    form_code = r"""STARTITEM 0
Load Patch List
<File:{file_opener}>
"""

    def __init__(self):
        self.inc = 0
        super(LoadForm, self).__init__(self.form_code, {
            "file_opener": idaapi.Form.FileInput(open=True),
        })

    def get_file_name(self):
        return self.file_opener.value


class RunPatcherexForm(idaapi.Form):

    form_code = r"""STARTITEM 0
Patcherex Output Options
<File:{file_opener}>
<Compiler Options:{compiler_options}>
"""

    def __init__(self):
        self.inc = 0
        super(RunPatcherexForm, self).__init__(self.form_code, {
            "file_opener": idaapi.Form.FileInput(open=True),
            "compiler_options": idaapi.Form.StringInput(),
        })

    def get_file_name(self):
        return self.file_opener.value

    def get_compiler_options(self):
        return self.compiler_options.value


class PatchTypeForm(idaapi.Form):

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
        self.type_keys = types.keys()
        super(PatchTypeForm, self).__init__(filled_form_code, {
            "radio": idaapi.Form.RadGroupControl(tuple(types.keys()))
        })

    def Compile(self):
        ret = super(PatchTypeForm, self).Compile()
        getattr(self, self.type_keys[0]).selected = True
        return ret

    def get_chosen_patch_type(self):
        return self.type_keys[self.radio.value]