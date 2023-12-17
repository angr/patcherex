class Patch:
    def __init__(self, parent=None) -> None:
        self.parent = parent

    def apply(self, p):
        raise NotImplementedError()
