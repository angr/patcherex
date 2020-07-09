import importlib

def DetourBackend(filename, data_fallback=None, base_address=None, try_pdf_removal=True):
    with open(filename, "rb") as f:
        start_bytes = f.read(0x14)
        if start_bytes.startswith(b"\x7fCGC"):
            detourbackendclass = getattr(importlib.import_module("patcherex.backends.detourbackends.cgc"), "DetourBackendCgc")
            return detourbackendclass(filename, data_fallback=data_fallback, base_address=base_address, try_pdf_removal=try_pdf_removal)
        elif start_bytes.startswith(b"\x7fELF"):
            # more details can be found at glibc/elf/elf.h
            if start_bytes.startswith(b"\x03\x00", 0x12): # EM_386
                detourbackendclass = getattr(importlib.import_module("patcherex.backends.detourbackends.i386"), "DetourBackendi386")
            elif start_bytes.startswith(b"\x3e\x00", 0x12): # EM_X86_64
                detourbackendclass = getattr(importlib.import_module("patcherex.backends.detourbackends.i386"), "DetourBackendi386")
            elif start_bytes.startswith(b"\xb7\x00", 0x12): # EM_AARCH64
                detourbackendclass = getattr(importlib.import_module("patcherex.backends.detourbackends.aarch64"), "DetourBackendAarch64")
            elif start_bytes.startswith(b"\x28\x00", 0x12): # EM_ARM
                detourbackendclass = getattr(importlib.import_module("patcherex.backends.detourbackends.arm"), "DetourBackendArm")
            else:
                raise Exception("Unsupported architecture.")
            return detourbackendclass(filename, base_address=base_address)
        else:
            raise Exception("Unsupported file type.")

def init_backend(program_name, options):
    return DetourBackend(program_name, **options)
