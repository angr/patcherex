#pylint: disable=import-error,wildcard-import,unused-wildcard-import,no-self-use,unused-argument
import idaapi
from idaapi import Choose2
import json
import re
import subprocess
import threading
import tempfile
import sys
from forms import *


PATCH_TYPES = {"InsertCodePatch": {"desc": "Insert Assembly", "handler_form": InsertCodePatchForm}}

class ItemManager(object):
    def __init__(self):
        self.internal_items = []

    def __getitem__(self, index):
        patch_type = self.internal_items[index]["type"]
        address = self.internal_items[index]["address"]
        name = self.internal_items[index]["name"]
        data = self.internal_items[index]["data"]
        handler_form = PATCH_TYPES[self.internal_items[index]["type"]]["handler_form"]
        return handler_form.get_gui_format_of(patch_type, address, name, data)

    def __len__(self):
        return len(self.internal_items)

    def check_name_collisions(self, name):
        for item in self.internal_items:
            if item["name"] == name:
                return item["name"]
        return False

    def gen_valid_name(self, start_name):
        alt_name = start_name
        while True:
            conflict = self.check_name_collisions(alt_name)
            if conflict:
                match = re.search(r"_[0-9]+\Z", conflict)
                if match:
                    num = int(conflict[match.start() + 1:match.end()])
                    base_str = conflict[:match.start()]
                else:
                    num = 0
                    base_str = conflict
                alt_name = base_str + "_" + str(num + 1)
            else:
                break
        return alt_name

    def add_item(self, patch_type, address, name, data):
        valid_name = self.gen_valid_name(name)
        self.internal_items.append({"type": patch_type,
                                    "address": address,
                                    "name": valid_name,
                                    "data": data})
        return len(self.internal_items) - 1

    def get_item(self, index):
        return self.internal_items[index]

    def set_item(self, index, updates):
        if "name" in updates:
            updates = dict(updates)
            updates["name"] = self.gen_valid_name(updates["name"])
        self.internal_items[index].update(updates)

    def delete_item(self, index):
        del self.internal_items[index]
        return index

    def get_serialized(self):
        return json.dumps(self.internal_items)

    def load_serialized(self, contents):
        self.internal_items = json.loads(contents)

class PatcherexWindow(Choose2):
    def __init__(self):
        Choose2.__init__(
            self,
            "Patcherex",
            [
                ["Type", 10 | Choose2.CHCOL_PLAIN],
                ["Address", 10 | Choose2.CHCOL_HEX],
                ["Name", 30 | Choose2.CHCOL_PLAIN],
                ["Data", 30 | Choose2.CHCOL_FORMAT]
            ])
        self.items = ItemManager()
        self.popup_names = ["Add Patch", "Remove Patch", "Edit Patch", "Refresh"]
        self.OnInsertLine()

    def OnClose(self):
        print "Patcherex closing"

    def OnEditLine(self, n):
        params = dict(self.items.get_item(n))
        del params["type"]
        form = PATCH_TYPES[self.items.get_item(n)["type"]]["handler_form"](**params)
        form.Compile()
        if form.Execute():
            updates = {}
            updates["address"] = form.get_patch_address()
            updates["name"] = form.get_patch_name()
            updates["data"] = form.get_patch_data()
            self.items.set_item(n, updates)
        form.Free()
        self.Refresh()

    def OnInsertLine(self):
        form = PatchTypeForm(PATCH_TYPES)
        form.Compile()
        if form.Execute():
            option = form.get_chosen_patch_type()
            patch_form = PATCH_TYPES[option]["handler_form"]()
            patch_form.Compile()
            if patch_form.Execute():
                patch_type = option
                patch_name = patch_form.get_patch_name()
                patch_address = patch_form.get_patch_address()
                patch_data = patch_form.get_patch_data()
                self.items.add_item(patch_type, patch_address, patch_name, patch_data)
        form.Free()

    def OnSelectLine(self, n):
        self.OnEditLine(n)

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnDeleteLine(self, n):
        return self.items.delete_item(n)

    def OnRefresh(self, n):
        return n

    def OnGetIcon(self, n):
        return 5

    def OnGetLineAttr(self, n): # Can be used to set line color, e.g. blue = [0xFF, 0]
        return None

    def get_serialized_items(self):
        return self.items.get_serialized()

    def load_serialized_items(self, contents):
        self.items.load_serialized(contents)
        self.Refresh()

class UnsupportedArchitectureException(Exception):
    pass

class SaveHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        form = SaveForm()
        form.Compile()
        if form.Execute():
            file_name = form.get_file_name()
            try:
                out_file = open(file_name, "wb")
            except IOError as e:
                idaapi.warning("Unable to open %s (%s)" % (file_name, e.strerror))
            else:
                with out_file:
                    out_file.write(patcherex_window.get_serialized_items())
        form.Free()

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_FORM if ctx.form_title == "Patcherex" else idaapi.AST_DISABLE_FOR_FORM

class LoadHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        form = LoadForm()
        form.Compile()
        if form.Execute():
            file_name = form.get_file_name()
            try:
                out_file = open(file_name, "rb")
            except IOError as e:
                idaapi.warning("Unable to open %s (%s)" % (file_name, e.strerror))
            else:
                with out_file:
                    contents = out_file.read()
                    patcherex_window.load_serialized_items(contents)
        form.Free()

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_FORM if ctx.form_title == "Patcherex" else idaapi.AST_DISABLE_FOR_FORM

class RunPatcherexHandler(idaapi.action_handler_t):
    config = """
techniques:
    manualpatcher:
        options:
            patch_file: %s
backend:
    name: reassembler_backend
    options:
"""
    def activate(self, ctx):
        form = RunPatcherexForm()
        form.Compile()
        if form.Execute():
            file_name = form.get_file_name()
            patch_output_file = tempfile.NamedTemporaryFile(delete=False)
            patch_output_file.write(patcherex_window.get_serialized_items())
            patch_output_file.close()
            config_file = tempfile.NamedTemporaryFile(delete=False)
            config_file.write(self.config % patch_output_file.name) # TODO: Find better way to do this (can't import yaml)
            config_file.close()
            print "Calling patcherex . . ."
            popen_and_call(RunPatcherexHandler.patcherex_finish,
                           {"args": ["patcherex", "-c", config_file.name, "single", idaapi.get_input_file_path(), file_name]})

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_FORM if ctx.form_title == "Patcherex" else idaapi.AST_DISABLE_FOR_FORM

    @staticmethod
    def patcherex_finish(proc):
        if proc.returncode != 0:
            idaapi.warning("Patcherex failed. See output window.")
        else:
            idaapi.info("Patcherex completed successfully.")

    @staticmethod
    def menu_activate():
        RunPatcherexHandler().activate(None)

class PopHook(idaapi.UI_Hooks):
    def __init__(self, actname_list):
        idaapi.UI_Hooks.__init__(self)
        self.acts = actname_list

    def finish_populating_tform_popup(self, form, popup):
        if idaapi.get_tform_title(form) == "Patcherex":
            for act in self.acts:
                idaapi.attach_action_to_popup(form, popup, "patcherex:" + act, None)

# http://stackoverflow.com/questions/2581817/python-subprocess-callback-when-cmd-exits
def popen_and_call(onExit, popenArgs):
    """
    Runs the given args in a subprocess.Popen, and then calls the function
    onExit when the subprocess completes.
    onExit is a callable object, and popenArgs is a list/tuple of args that
    would give to subprocess.Popen.
    """
    def runInThread(onExit, popenArgs):
        proc = subprocess.Popen(**popenArgs)
        proc.wait()
        onExit(proc)
        return
    thread = threading.Thread(target=runInThread, args=(onExit, popenArgs))
    thread.start()
    # returns immediately after the thread starts
    return thread

commands = [("save", "Save patches to file . . .", SaveHandler, None, None),
            ("load", "Load patches from file . . .", LoadHandler, None, None),
            ("run_patcherex", "Run Patcherex . . .", RunPatcherexHandler, "File/Produce file/", RunPatcherexHandler.menu_activate)]

if __name__ == "__main__" or True:
    if idaapi.get_inf_structure().procName != "metapc":
        raise UnsupportedArchitectureException("Only x86 metapc is supported.")
    if globals().get("patcherex_window") is None:
        for command in commands:
            idaapi.register_action(
                idaapi.action_desc_t(
                    "patcherex:" + command[0],
                    command[1],
                    command[2]()))
            if command[3] is not None:
                idaapi.add_menu_item(command[3], command[1], "", 0, command[4], (None,))
        hooks = PopHook([command[0] for command in commands])
        hooks.hook()
        print "Spawning new Patcherex"
        patcherex_window = PatcherexWindow()
        patcherex_window.Show()
    else:
        patcherex_window.Show()
