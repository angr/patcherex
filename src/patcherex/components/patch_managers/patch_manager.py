class PatchManager:
    def __init__(self):
        self.patches = []
        self.analyzed = False

    def add_patch(self, patch):
        self.analyzed = False
        self.patches.append(patch)

    def add_patches(self, patches):
        for patch in patches:
            self.add_patch(patch)

    def export_patches(self, filename):
        raise NotImplementedError()

    def import_patches(self, filename):
        raise NotImplementedError()

    def analyze_patches(self, ignore_conflicts=False):
        raise NotImplementedError()

    def apply_patches(self, best_effort=False):
        raise NotImplementedError()
