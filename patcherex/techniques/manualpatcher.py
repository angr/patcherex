import logging
import json
import patcherex.patches

l = logging.getLogger("patcherex.techniques.ManualPatcher")

class ManualPatcher(object):
    def __init__(self, binary_fname, backend, patch_file):
        patch_file_obj = open(patch_file, "rb")
        self.patches = json.load(patch_file_obj)
        self.binary_fname = binary_fname
        self.backend = backend

    def get_patches(self):
        patches = []
        for patch in self.patches:
            patcher = getattr(patcherex.patches, patch["type"])
            if patcher is None:
                raise ValueError("Got unknown patch type %s" % patch["type"])
            patches.append(patcher(**patch["data"]))
        return patches

def init_technique(program_name, backend, options):
    return ManualPatcher(program_name, backend, **options)
