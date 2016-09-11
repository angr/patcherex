import patcherex

import logging
import struct
from patcherex.patches import *

l = logging.getLogger("patcherex.techniques.CpudId")


class CpuId(object):

    def __init__(self,binary_fname,backend):
        self.binary_fname = binary_fname
        self.patcher = backend

    def get_patches(self):
        patches = []
        added_code = '''
            ; int allocate(size_t length, int is_X, void **addr) [5]
            call {print_hex_eax_newline}
            mov eax, esp
            call {print_hex_eax_newline}
            pushf
            pop eax
            call {print_hex_eax_newline}
            call {print_some_regs}

            mov eax, cs
            call {print_hex_eax_newline}
            mov eax, ds
            call {print_hex_eax_newline}
            mov eax, es
            call {print_hex_eax_newline}
            mov eax, fs
            call {print_hex_eax_newline}
            mov eax, ss
            call {print_hex_eax_newline}

            mov eax, 0x5
            mov ebx, 0x1000
            xor ecx, ecx
            mov edx, {allocate_result}
            int 0x80
            mov eax, [{allocate_result}]
            call {print_hex_eax_newline}

            mov eax, 0
            cpuid
            call {print_some_regs}

            mov eax, 1
            cpuid
            call {print_some_regs}

            mov eax, 2
            cpuid
            call {print_some_regs}

            mov eax, 3
            cpuid
            call {print_some_regs}

            mov eax, 7
            xor ecx, ecx
            cpuid
            call {print_some_regs}

            mov eax, 0x80000000
            cpuid
            call {print_some_regs}
            mov eax, 0x80000001
            cpuid
            call {print_some_regs}
            mov eax, 0x80000002
            cpuid
            call {print_some_regs}
            mov eax, 0x80000003
            cpuid
            call {print_some_regs}
            mov eax, 0x80000004
            cpuid
            call {print_some_regs}
            mov eax, 0x80000005
            cpuid
            call {print_some_regs}
            mov eax, 0x80000006
            cpuid
            call {print_some_regs}
            mov eax, 0x80000007
            cpuid
            call {print_some_regs}
            mov eax, 0x80000008
            cpuid
            call {print_some_regs}

            sgdt [{space}]
            mov eax, DWORD [{space}]
            call {print_hex_eax_newline}
            mov eax, DWORD [{space}+4]
            call {print_hex_eax_newline}
            mov eax, DWORD [{space}+8]
            call {print_hex_eax_newline}

            sldt [{space}]
            mov eax, DWORD [{space}]
            call {print_hex_eax_newline}
            mov eax, DWORD [{space}+4]
            call {print_hex_eax_newline}
            mov eax, DWORD [{space}+8]
            call {print_hex_eax_newline}

            str eax
            call {print_hex_eax_newline}

            mov eax,ds
            lsl ebx, eax
            mov eax, ebx
            call {print_hex_eax_newline}

            mov eax,ds
            lar ebx, eax
            mov eax, ebx
            call {print_hex_eax_newline}
        '''
        patches.append(AddEntryPointPatch(added_code,name="cpuid"))

        added_code = '''
            ; print eax as hex
            pusha
            call {print_hex_eax_newline}
            mov eax, ebx
            call {print_hex_eax_newline}
            mov eax, ecx
            call {print_hex_eax_newline}
            mov eax, edx
            call {print_hex_eax_newline}
            mov eax, esi
            call {print_hex_eax_newline}
            mov eax, edi
            call {print_hex_eax_newline}
            mov eax, ebp
            call {print_hex_eax_newline}
            popa
            ret
        '''
        patches.append(AddCodePatch(added_code,name="print_some_regs"))
        added_code = '''
            ; print eax as hex
            pusha
            mov ecx,32
            mov ebx,eax
            _print_reg_loop:
                rol ebx,4
                mov edi,ebx
                and edi,0x0000000f
                lea eax,[{hex_array}+edi]
                mov ebp,ebx
                mov ebx,0x1
                call {print}
                mov ebx,ebp
                sub ecx,4
                jnz _print_reg_loop
            lea eax, [{new_line}]
            mov ebx,0x1
            call {print}
            popa
            ret
        '''
        patches.append(AddCodePatch(added_code,name="print_hex_eax_newline"))
        added_code = '''
            ; eax=buf,ebx=len
            pusha
            mov ecx,eax
            mov edx,ebx
            mov eax,0x2
            mov ebx,0x1
            mov esi,0x0
            int 0x80
            popa
            ret
        '''
        patches.append(AddCodePatch(added_code,name="print"))
        patches.append(AddRODataPatch(b"0123456789abcdef",name="hex_array"))
        patches.append(AddRODataPatch(b"\n",name="new_line"))
        patches.append(AddRWDataPatch(len("XXXX"),name="allocate_result"))
        patches.append(AddRWDataPatch(len("XXXXXXXXXXXXXXXXXXXX"),name="space"))

        return patches

def init_technique(program_name, backend, options):
    return CpuId(program_name, backend, **options)
