#pylint: disable=import-error,no-self-use
import idaapi
import idc

class GenericPatchForm(idaapi.Form):

    def get_patch_address(self):
        return 0

    def get_patch_name(self):
        return ""

    def get_patch_data(self):
        return ""

    def perform_post_operations(self, patch_type, patch_name, patch_address, patch_data):
        pass

    @staticmethod
    def on_pre_update(patch_type, name, address, data):
        pass

    @staticmethod
    def on_delete(patch_type, name, address, data):
        pass

    @staticmethod
    def get_gui_format_of(patch_type, address, name, data):
        return map(str, [patch_type, address, name, data])

class InsertCodePatchForm(GenericPatchForm):

    form_code = r"""STARTITEM 0
Edit Patch
<Address:{patch_address}>
<Name:{patch_name}>
<Code:{patch_code}>
"""
    patch_type = "InsertCodePatch"
    comment_format = "Patcherex patch '%s' to insert code at 0x%x:\n%s"

    def __init__(self, address=None, name="Patch", data={"code": ""}):
        address = address if address else idc.ScreenEA()
        self.inc = 0
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

    def on_perform_post_operations(self, patch_type, name, address, data):
        original = idc.RptCmt(address)
        if original is not None:
            prefix = original + "\n"
        else:
            prefix = ""
        idc.MakeRptCmt(address,
                       prefix + self.comment_format % (name, address, data["code"]))

    @staticmethod
    def on_pre_update(patch_type, name, address, data):
        added_comment = InsertCodePatchForm.comment_format % (name, address, data["code"])
        if added_comment in idc.RptCmt(address):
            idc.MakeRptCmt(address, idc.RptCmt(address).replace("\n" + added_comment, ""))
            idc.MakeRptCmt(address, idc.RptCmt(address).replace(added_comment, ""))

    @staticmethod
    def on_delete(patch_type, name, address, data):
        InsertCodePatchForm.on_pre_update(patch_type, name, address, data)

    @staticmethod
    def get_gui_format_of(patch_type, address, name, data):
        if patch_type != InsertCodePatchForm.patch_type:
            print "Got patch type %s, but expected \"%s\"" % (patch_type, InsertCodePatchForm.patch_type)
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
Patcherex Output File
<File:{file_opener}>
"""

    def __init__(self):
        self.inc = 0
        super(RunPatcherexForm, self).__init__(self.form_code, {
            "file_opener": idaapi.Form.FileInput(open=True),
        })

    def get_file_name(self):
        return self.file_opener.value


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
