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

class CodePatchForm(GenericPatchForm):

    form_code = r"""STARTITEM 0
Edit Patch
<Address:{patch_address}>
<Name:{patch_name}>
<Code:{patch_code}>
"""

    def __init__(self, address=None, name="Patch", data=""):
        address = address if address else idc.ScreenEA()
        self.inc = 0
        super(CodePatchForm, self).__init__(self.form_code, {
            "patch_address": idaapi.Form.NumericInput(tp=idaapi.Form.FT_ADDR, value=address),
            "patch_name": idaapi.Form.StringInput(value=str(name)),
            "patch_code": idaapi.Form.MultiLineTextControl(text=str(data),
                                                           flags=idaapi.Form.MultiLineTextControl.TXTF_FIXEDFONT),
        })

    def get_patch_address(self):
        return self.patch_address.value

    def get_patch_name(self):
        return self.patch_name.value

    def get_patch_data(self):
        return self.patch_code.value

    @staticmethod
    def get_gui_format_of(patch_type, address, name, data):
        if patch_type != "typeCode":
            print "Got patch type", patch_type, ", expected \"typeCode\""
        new_patch_type = "Code"
        new_address = hex(long(address))[:-1]
        new_name = name
        new_data = data.split("\n")[0]
        if len(data.split("\n")) > 1:
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
