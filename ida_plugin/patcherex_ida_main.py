#pylint: disable=import-error,wildcard-import,unused-wildcard-import,no-self-use,unused-argument
import base64
import idaapi
from idaapi import Choose
import json
import re
import subprocess
import threading
import tempfile
import shlex
import os
from patcherex_ida.forms import *
from collections import namedtuple


PATCH_TYPES = {"InsertCodePatch": {"desc": "Insert Assembly", "handler_widget": InsertCodePatchWidget},
               "AddRODataPatch": {"desc": "Insert Read Only Data", "handler_widget": AddRODataPatchWidget},
               "AddLabelPatch": {"desc": "Add a Label", "handler_widget": AddLabelPatchWidget},
               "RemoveInstructionPatch": {"desc": "Remove an instruction", "handler_widget": RemoveInstructionPatchWidget},
               "AddRWDataPatch": {"desc": "Add Space for Read/Write Data", "handler_widget": AddRWDataPatchWidget},
               "AddCodePatch": {"desc": "Add assembly or C code into the binary", "handler_widget": AddCodePatchWidget}}

class ItemManager(object):
    def __init__(self, get_items, set_items):
        self.get_items = get_items
        self.set_items = set_items
        self.internal_items = None
        self.internal_items = self.load_serialized(self.get_items())

    def pre_sync(self):
        self._load_serialized(self.get_items())

    def post_sync(self):
        s = self._get_serialized()
        self.set_items(s)

    def __getitem__(self, index):
        return self._get_handler_for_item(index).get_gui_format_of(**self.get_item(index))

    def __len__(self):
        return len(self.internal_items)

    def check_name_collisions(self, name, replacement_index):
        for i, item in enumerate(self.internal_items):
            if (replacement_index is None) or (replacement_index != i):
                if item["name"] == name:
                    return item["name"]
        return False

    def gen_valid_name(self, start_name, replacement_index=None):
        alt_name = start_name
        while True:
            conflict = self.check_name_collisions(alt_name, replacement_index=replacement_index)
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
        self.pre_sync()
        self._add_item(patch_type, address, name, data)
        self.post_sync()

    def _add_item(self, patch_type, address, name, data):
        valid_name = self.gen_valid_name(name)
        self.internal_items.append({"patch_type": patch_type,
                                    "address": address,
                                    "name": valid_name,
                                    "data": data})
        new_index = len(self.internal_items) - 1
        self._get_handler_for_item(new_index).on_perform_post_operations(**self._get_item(new_index))
        return len(self.internal_items) - 1

    def get_item(self, index):
        self.pre_sync()
        return self._get_item(index)

    def _get_item(self, index):
        return self.internal_items[index]

    def set_item(self, index, updates):
        self.pre_sync()
        self._set_item(index, updates)
        self.post_sync()

    def _set_item(self, index, updates):
        if "name" in updates:
            updates = dict(updates)
            updates["name"] = self.gen_valid_name(updates["name"], replacement_index=index)
        self._get_handler_for_item(index).on_pre_update(**self._get_item(index))
        self.internal_items[index].update(updates)
        self._get_handler_for_item(index).on_post_update(**self._get_item(index))

    def delete_item(self, index):
        self.pre_sync()
        self._delete_item(index)
        self.post_sync()
        return index

    def _delete_item(self, index):
        self._get_handler_for_item(index).on_delete(**self._get_item(index))
        del self.internal_items[index]

    def _get_handler_for_item(self, n):
        return PATCH_TYPES[self._get_item(n)["patch_type"]]["handler_widget"]

    def _get_serialized(self):
        return json.dumps(self.internal_items)

    def _load_serialized(self, contents):
        if self.internal_items is not None:
            self._uninitialize_patches()
        self.internal_items = []

        stuff = json.loads(contents) if contents else None
        if stuff is not None:
            for item in stuff:
                self._add_item(**item)

    def get_serialized(self):
        self.pre_sync()
        return self._get_serialized()

    def load_serialized(self, contents):
        self._load_serialized(contents)
        self.post_sync()

    def uninitialize_patches(self):
        self.pre_sync()
        self._uninitialize_patches()

    def _uninitialize_patches(self):
        while len(self.internal_items) != 0:
            self._delete_item(0)

class PatcherexWindow(Choose):
    def __init__(self):
        Choose.__init__(
            self,
            "Patcherex",
            [
                ["Type", 10 | Choose.CHCOL_PLAIN],
                ["Address", 10 | Choose.CHCOL_HEX],
                ["Name", 30 | Choose.CHCOL_PLAIN],
                ["Data", 30 | Choose.CHCOL_FORMAT]
            ])
        self.node = idaapi.netnode()
        self.node.create("$ patcherex")
        self.items = ItemManager(self._get_items, self._set_items)
        self.popup_names = ["Add Patch", "Remove Patch", "Edit Patch", "Refresh"]

    def _get_items(self):
        val = self.node.getblob(0, "I")
        if val is None:
            return val
        val_dec = base64.b64decode(val).decode("utf-8")
        print(f"Got: [{val_dec!r}] {val!r}")
        return val_dec

    def _set_items(self, val: str):
        assert isinstance(val, str)
        val_enc = base64.b64encode(val.encode('utf-8'))
        print(f"Set: [{val!r}] {val_enc!r}")
        self.node.setblob(val_enc, 0, "I")

    def load_saved_patches(self):
        SaveLoadHook.loading()

    def OnClose(self):
        pass

    def OnEditLine(self, n):
        params = dict(self.items.get_item(n))
        patch_type = params["patch_type"]
        del params["patch_type"]
        widget = PATCH_TYPES[patch_type]["handler_widget"](**params)
        widget.Compile()
        if widget.Execute():
            updates = {}
            updates["address"] = widget.get_patch_address()
            updates["name"] = widget.get_patch_name()
            updates["data"] = widget.get_patch_data()
            self.items.set_item(n, updates)
        widget.Free()
        self.Refresh()

    def OnInsertLine(self):
        widget = PatchTypeWidget(PATCH_TYPES)
        widget.Compile()
        if widget.Execute():
            option = widget.get_chosen_patch_type()
            patch_widget = PATCH_TYPES[option]["handler_widget"]()
            patch_widget.Compile()
            if patch_widget.Execute():
                params = {}
                params["patch_type"] = option
                params["name"] = patch_widget.get_patch_name()
                params["address"] = patch_widget.get_patch_address()
                params["data"] = patch_widget.get_patch_data()
                self.items.add_item(**params)
        widget.Free()
        self.Refresh()

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

    def uninitialize_patches(self):
        self.items.uninitialize_patches()

    def is_used(self):
        return len(self.items) != 0

class UnsupportedArchitectureException(Exception):
    pass

class SaveHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        widget = SaveWidget()
        widget.Compile()
        if widget.Execute():
            file_name = widget.get_file_name()
            self.do_save(file_name)
        widget.Free()

    @classmethod
    def do_save(cls, file_name):
        contents = patcherex_window.get_serialized_items()
        if file_name is not None:
            try:
                out_file = open(file_name, "wb")
            except IOError as e:
                idaapi.warning("Unable to open %s for saving (%s)" % (file_name, e.strerror))
            else:
                with out_file:
                    out_file.write(contents)
        else:
            patcherex_window._set_items(contents)

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if ctx.widget_title == "Patcherex" else idaapi.AST_DISABLE_FOR_WIDGET

class LoadHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        widget = LoadWidget()
        widget.Compile()
        if widget.Execute():
            file_name = widget.get_file_name()
            self.do_load(file_name)
        widget.Free()

    @classmethod
    def do_load(cls, file_name):
        if file_name is not None:
            try:
                out_file = open(file_name, "rb")
            except IOError as e:
                idaapi.warning("Unable to open %s for loading (%s)" % (file_name, e.strerror))
            else:
                with out_file:
                    contents = out_file.read()
        else:
            contents = patcherex_window._get_items()
            if contents is None:
                return
        patcherex_window.load_serialized_items(contents)

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if ctx.widget_title == "Patcherex" else idaapi.AST_DISABLE_FOR_WIDGET

class RunPatcherexHandler(idaapi.action_handler_t):
    config = """{"techniques": {"manualpatcher": {"options": {"patch_file": null}}}, "backend": {"name": "detourbackend", "options": {"base_address": 0}}}"""
    def activate(self, ctx):
        RunPatcherexHandler.menu_activate(None)

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET

    @staticmethod
    def patcherex_finish(proc):
        if proc.returncode != 0:
            out_str = "Patcherex failed. See attached terminal."
            idaapi.warning(out_str)
            print(out_str)
        else:
            out_str = "Patcherex completed successfully."
            idaapi.info(out_str)
            print(out_str)

    @staticmethod
    def menu_activate(arg):
        widget = RunPatcherexWidget()
        widget.Compile()
        if widget.Execute():
            file_name = widget.get_file_name()
            patch_output_file = tempfile.NamedTemporaryFile(delete=False, mode="w+")
            patch_output_file.write(patcherex_window.get_serialized_items())
            patch_output_file.close()
            config_file = tempfile.NamedTemporaryFile(delete=False, mode="w+")
            p_config = json.loads(RunPatcherexHandler.config)
            p_config["techniques"]["manualpatcher"]["options"]["patch_file"] = patch_output_file.name
            p_config["backend"]["options"]["base_address"] = idaapi.get_imagebase()
            config_file.write(json.dumps(p_config))
            config_file.close()

            args = ["patcherex", "-c", config_file.name, "--json", "single", idaapi.get_input_file_path(), file_name]
            print(f"Calling patcherex with {repr(args)} . . .")
            popen_and_call(RunPatcherexHandler.patcherex_finish,
                           {"args": args })


class AddPatchHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        AddPatchHandler.menu_activate(None)

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET

    @staticmethod
    def menu_activate(arg):
        patcherex_window.OnInsertLine()

class PopHook(idaapi.UI_Hooks):
    def __init__(self, actname_list):
        idaapi.UI_Hooks.__init__(self)
        self.acts = actname_list

    def finish_populating_widget_popup(self, widget, popup):
        if idaapi.get_widget_title(widget) == "Patcherex":
            for act in self.acts:
                idaapi.attach_action_to_popup(widget, popup, "patcherex:" + act, None)

class SaveLoadHook(idaapi.UI_Hooks):
    def saving(self):
        if patcherex_window.is_used():
            SaveHandler.do_save(None)

    # Not a real idaapi hook; called from PatcherexWindow.load_saved_patches
    @classmethod
    def loading(cls):
        LoadHandler.do_load(None)

    @staticmethod
    def get_preferred_path():
        idb_path = os.path.abspath(idc.GetIdbPath())
        no_idb_ext = os.path.splitext(os.path.basename(idb_path))[0]
        save_path = os.path.join(os.path.split(idb_path)[0], no_idb_ext + "_patcherex.json")
        return save_path

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

if globals().get("patcherex_hooks", None) is None:
    patcherex_hooks = None

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
        global patcherex_hooks
        if idaapi.get_inf_structure().procname != "metapc":
            print("Only x86 metapc is supported by Patcherex")
            return idaapi.PLUGIN_SKIP
        for command in commands:
            name = "patcherex:" + command.name
            idaapi.register_action(
                idaapi.action_desc_t(name,
                                     command.description,
                                     command.handler_class(),
                                     command.shortcut))
            if command.menu_path:
                idaapi.attach_action_to_menu(command.menu_path, name, idaapi.SETMENU_APP)
        if patcherex_hooks is None:
            patcherex_hooks = [PopHook([command.name for command in commands]), SaveLoadHook()]
            for hook in patcherex_hooks:
                hook.hook()
        if patcherex_window is None:
            print("Patcherex starting")
            self.patcherex_window = PatcherexWindow()
            patcherex_window = self.patcherex_window
        else:
            self.patcherex_window = patcherex_window
            patcherex_window.load_saved_patches()
        return idaapi.PLUGIN_OK

    def run(self, arg):
        self.patcherex_window.Show()

    def term(self):
        self.patcherex_window.uninitialize_patches()
        self.patcherex_window.Close()

def PLUGIN_ENTRY():
    return PatcherexPlugin()
