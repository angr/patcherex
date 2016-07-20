import fidget
from ..patches import RawFilePatch

class Fidget(object):
    def __init__(self, binary_fname, backend, mode='normal'):
        self.binary_fname = binary_fname
        self.backend = backend
        if mode == 'normal':
            technique = fidget.FidgetDefaultTechnique()
        elif mode == 'safe':
            technique = fidget.FidgetDefaultTechnique(safe=True)
        elif mode == 'huge':
            technique = fidget.FidgetDefaultTechnique(largemode=True)
        elif mode == 'hugesafe':
            technique = fidget.FidgetDefaultTechnique(safe=True, largemode=True)

        self.fidgetress = fidget.Fidget(binary_fname)
        self.fidgetress.patch_stack(technique)

    def get_patches(self):
        return [RawFilePatch(offset, data) for offset, data in self.fidgetress.dump_patches()]

    def get_stack_increases(self):
        return self.fidgetress.stack_increases
