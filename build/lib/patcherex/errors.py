
class PatcherexError(Exception):
    pass

class FunctionalityError(PatcherexError):
    pass

class SizeError(PatcherexError):
    pass

#
# Reassembler errors
#

class ReassemblerError(PatcherexError):
    pass

class CompilationError(ReassemblerError):
    pass

class ReassemblerNotImplementedError(ReassemblerError):
    pass

#
# Binary optimization errors
#

class BinaryOptimizationError(PatcherexError):
    pass

class BinaryOptimizationNotImplementedError(BinaryOptimizationError):
    pass

#
# Simple pointer encryption errors
#

class SimplePtrEncError(PatcherexError):
    pass

#
# ASMConverter errors
#

class ASMConverterError(PatcherexError, ValueError):
    pass

class ASMConverterNotImplementedError(PatcherexError):
    pass
