import logging
import json
import patcherex.patches

l = logging.getLogger("patcherex.techniques.ManualPatcher")


class ManualPatcher:
    def __init__(self, binary_fname, backend, patch_file):
        with open(patch_file, "rb") as patch_file_obj:
            self.patches = json.load(patch_file_obj)
        self.binary_fname = binary_fname
        self.backend = backend

    def get_patches(self):
        patches = []
        for patch in self.patches:
            patcher = getattr(patcherex.patches, patch["patch_type"])
            if patcher is None:
                raise ValueError("Got unknown patch type %s" % patch["patch_type"])
            patches.append(patcher(**patch["data"]))
        return patches

def init_technique(program_name, backend, options):
    return ManualPatcher(program_name, backend, **options)
