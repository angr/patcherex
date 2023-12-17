from .raw_patches import *
from .data_patches import *
from .dummy_patches import *
from .instruction_patches import *
from .function_patches import *


# Other Patches
class ModifyEntryPointPatch(Patch):
    def __init__(self, addr, parent=None) -> None:
        self.addr = addr
        super().__init__(parent)


# Complex Patches
class InsertFunctionWrapperPatch(Patch):
    def __init__(self, addr, wrapper_code, parent=None) -> None:
        self.addr = addr
        self.wrapper_code = wrapper_code
        super().__init__(parent)
