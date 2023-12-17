from .patch import Patch


class InsertLabelPatch(Patch):
    def __init__(self, addr) -> None:
        self.addr = addr
        raise NotImplementedError()


class ModifyLabelPatch(Patch):
    def __init__(self, addr) -> None:
        self.addr = addr
        raise NotImplementedError()


class RemoveLabelPatch(Patch):
    def __init__(self, addr) -> None:
        self.addr = addr
        raise NotImplementedError()
