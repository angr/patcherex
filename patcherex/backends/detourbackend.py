import importlib

def DetourBackend(filename, data_fallback=None, base_address=None, try_pdf_removal=True, try_reuse_unused_space=False, replace_note_segment=False, try_without_cfg=False, variant=None):
    with open(filename, "rb") as f:
        start_bytes = f.read(0x14)
        if start_bytes.startswith(b"\x7fCGC"):
            detourbackendclass = getattr(importlib.import_module("patcherex.backends.detourbackends.cgc"), "DetourBackendCgc")
            return detourbackendclass(filename, data_fallback=data_fallback, try_pdf_removal=try_pdf_removal)
        elif start_bytes.startswith(b"\x7fELF"):
            # more details can be found at glibc/elf/elf.h
            if start_bytes.startswith(b"\x03\x00", 0x12): # EM_386
                detourbackendclass = getattr(importlib.import_module("patcherex.backends.detourbackends.i386"), "DetourBackendi386")
            elif start_bytes.startswith(b"\x3e\x00", 0x12): # EM_X86_64
                detourbackendclass = getattr(importlib.import_module("patcherex.backends.detourbackends.i386"), "DetourBackendi386")
            elif start_bytes.startswith(b"\xb7\x00", 0x12): # EM_AARCH64
                detourbackendclass = getattr(importlib.import_module("patcherex.backends.detourbackends.aarch64"), "DetourBackendAarch64")
            elif start_bytes.startswith(b"\x28\x00", 0x12): # EM_ARM
                if variant == "stm32":
                        detourbackendclass = getattr(importlib.import_module("patcherex.backends.detourbackends.arm_stm32"), "DetourBackendArmStm32")
                else:
                    detourbackendclass = getattr(importlib.import_module("patcherex.backends.detourbackends.arm"), "DetourBackendArm")
            elif start_bytes.startswith(b"\x08\x00", 0x12) or \
                 start_bytes.startswith(b"\x00\x08", 0x12): # EM_MIPS
                detourbackendclass = getattr(importlib.import_module("patcherex.backends.detourbackends.mips"), "DetourBackendMips")
            elif start_bytes.startswith(b"\x14\x00", 0x12) or \
                 start_bytes.startswith(b"\x00\x14", 0x12) or \
                 start_bytes.startswith(b"\x15\x00", 0x12) or \
                 start_bytes.startswith(b"\x00\x15", 0x12): # EM_PPC / EM_PPC64
                detourbackendclass = getattr(importlib.import_module("patcherex.backends.detourbackends.ppc"), "DetourBackendPpc")
            elif start_bytes.startswith(b"\x53\x00", 0x12):
                detourbackendclass = getattr(importlib.import_module("patcherex.backends.detourbackends.avr"), "DetourBackendAVR")
            else:
                raise Exception("Unsupported architecture.")
            return detourbackendclass(filename, base_address=base_address, try_reuse_unused_space=try_reuse_unused_space, replace_note_segment=replace_note_segment, try_without_cfg=try_without_cfg)
        else:
            raise Exception("Unsupported file type.")

def init_backend(program_name, options):
    return DetourBackend(program_name, **options)
