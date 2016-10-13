#pylint: disable=import-error,wildcard-import,unused-wildcard-import,no-self-use,unused-argument
import idaapi
from idaapi import Choose2
import json
import re
import subprocess
import threading
import tempfile
from patcherex_ida.forms import *
from collections import namedtuple


PATCH_TYPES = {"InsertCodePatch": {"desc": "Insert Assembly", "handler_form": InsertCodePatchForm}}

class ItemManager(object):
    def __init__(self):
        self.internal_items = []

    def __getitem__(self, index):
        patch_type = self.internal_items[index]["patch_type"]
        address = self.internal_items[index]["address"]
        name = self.internal_items[index]["name"]
        data = self.internal_items[index]["data"]
        handler_form = PATCH_TYPES[self.internal_items[index]["patch_type"]]["handler_form"]
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
        self.internal_items.append({"patch_type": patch_type,
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

    def OnClose(self):
        pass

    def OnEditLine(self, n):
        params = dict(self.items.get_item(n))
        patch_type = params["patch_type"]
        del params["patch_type"]
        form = PATCH_TYPES[patch_type]["handler_form"](**params)
        form.Compile()
        if form.Execute():
            PATCH_TYPES[patch_type]["handler_form"].on_pre_update(**self.items.get_item(n))
            updates = {}
            updates["address"] = form.get_patch_address()
            updates["name"] = form.get_patch_name()
            updates["data"] = form.get_patch_data()
            form.on_perform_post_operations(patch_type, **updates)
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
                params = {}
                params["patch_type"] = option
                params["name"] = patch_form.get_patch_name()
                params["address"] = patch_form.get_patch_address()
                params["data"] = patch_form.get_patch_data()
                patch_form.on_perform_post_operations(**params)
                self.items.add_item(**params)
        form.Free()

    def OnSelectLine(self, n):
        self.OnEditLine(n)

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnDeleteLine(self, n):
        PATCH_TYPES[self.items.get_item(n)["patch_type"]]["handler_form"].on_delete(**self.items.get_item(n))
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
        RunPatcherexHandler.menu_activate(None)

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_FORM if ctx.form_title == "Patcherex" else idaapi.AST_DISABLE_FOR_FORM

    @staticmethod
    def patcherex_finish(proc):
        if proc.returncode != 0:
            idaapi.warning("Patcherex failed. See output window.")
        else:
            idaapi.info("Patcherex completed successfully.")

    @staticmethod
    def menu_activate(arg):
        form = RunPatcherexForm()
        form.Compile()
        if form.Execute():
            file_name = form.get_file_name()
            patch_output_file = tempfile.NamedTemporaryFile(delete=False)
            patch_output_file.write(patcherex_window.get_serialized_items())
            patch_output_file.close()
            config_file = tempfile.NamedTemporaryFile(delete=False)
            config_file.write(RunPatcherexHandler.config % patch_output_file.name) # TODO: Find better way to do this (can't import yaml)
            config_file.close()
            print "Calling patcherex . . ."
            popen_and_call(RunPatcherexHandler.patcherex_finish,
                           {"args": ["patcherex", "-c", config_file.name, "single", idaapi.get_input_file_path(), file_name]})


class AddPatchHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        AddPatchHandler.menu_activate(None)

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_FORM if ctx.form_title == "Patcherex" else idaapi.AST_DISABLE_FOR_FORM

    @staticmethod
    def menu_activate(arg):
        patcherex_window.OnInsertLine()

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

PatcherexCommand = namedtuple("PatcherexCommand", ["name",
                                                   "description",
                                                   "handler_class",
                                                   "shortcut",
                                                   "menu_path"])
commands = []

commands.append(PatcherexCommand(**{"name": "save",
                                    "description": "Save patches to file . . .",
                                    "handler_class": SaveHandler,
                                    "shortcut": None,
                                    "menu_path": None}))

commands.append(PatcherexCommand(**{"name": "load",
                                    "description": "Load patches from file . . .",
                                    "handler_class": LoadHandler,
                                    "shortcut": None,
                                    "menu_path": None}))

commands.append(PatcherexCommand(**{"name": "run_patcherex",
                                    "description": "Run Patcherex . . .",
                                    "handler_class": RunPatcherexHandler,
                                    "shortcut": "Ctrl-Shift-R",
                                    "menu_path": "File/Produce file/"}))

commands.append(PatcherexCommand(**{"name": "add_patch",
                                    "description": "Add Patcherex patch . . .",
                                    "handler_class": AddPatchHandler,
                                    "shortcut": "Ctrl-Shift-N",
                                    "menu_path": "Edit/Patch program/"}))

if globals().get("patcherex_window", None) is None:
    patcherex_window = None

class PatcherexPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Patcherex plugin for IDA"
    help = "Use Ctrl-Shift-P to access Patcherex"
    wanted_name = "Patcherex"
    wanted_hotkey = "Ctrl-Shift-P"

    def __init__(self):
        super(PatcherexPlugin, self).__init__()
        self.patcherex_window = None

    def init(self):
        global patcherex_window
        if idaapi.get_inf_structure().procName != "metapc":
            print "Only x86 metapc is supported by Patcherex"
            return idaapi.PLUGIN_SKIP
        for command in commands:
            idaapi.register_action(
                idaapi.action_desc_t("patcherex:" + command.name,
                                     command.description,
                                     command.handler_class()))
            if command[4] is not None:
                idaapi.add_menu_item(command.menu_path,
                                     command.description,
                                     command.shortcut,
                                     0,
                                     command.handler_class.menu_activate,
                                     (None,))
        hooks = PopHook([command[0] for command in commands])
        hooks.hook()
        if patcherex_window is None:
            print "Patcherex starting"
            self.patcherex_window = PatcherexWindow()
            patcherex_window = self.patcherex_window
        else:
            self.patcherex_window = patcherex_window
        return idaapi.PLUGIN_OK

    def run(self, arg):
        self.patcherex_window.Show()

    def term(self):
        self.patcherex_window.Close()

def PLUGIN_ENTRY():
    return PatcherexPlugin()
