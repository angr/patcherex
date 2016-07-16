import fidget
from ..patches import RawFilePatch

class Fidget(object):
    def __init__(self, binary_fname, backend, mode='normal'):
        self.binary_fname = binary_fname
        self.backend = backend
        if mode == 'normal':
            technique = fidget.techniques.FidgetDefaultTechnique()
        elif mode == 'safe':
            technique = fidget.techniques.FidgetDefaultTechnique(safe=True)
        elif mode == 'huge':
            technique = fidget.techniques.FidgetDefaultTechnique(largemode=True)
        elif mode == 'hugesafe':
            technique = fidget.techniques.FidgetDefaultTechnique(safe=True, largemode=True)

        self.fidgetress = fidget.Fidget(binary_fname)
        self.fidgetress.patch_stack(stack={'technique': technique})

    def get_patches(self):
        return [RawFilePatch(offset, data) for offset, data in self.fidgetress.dump_patches()]
