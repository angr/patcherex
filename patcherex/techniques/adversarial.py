import patcherex
import angr
import struct

import patcherex.utils as utils
import patcherex.cfg_utils as cfg_utils

import capstone
import logging
from patcherex.patches import *

l = logging.getLogger("patcherex.techniques.Adversarial")


class Adversarial(object):

    def __init__(self,binary_fname,backend):
        self.binary_fname = binary_fname
        self.patcher = backend

    def get_debug_patches(self):
        patches = []
        patches.append(AddRODataPatch(b"0123456789abcdef\n", "hex_array"))
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
        patches.append(AddCodePatch(added_code,"print"))
        added_code = '''
            ; print eax as hex
            pusha
            mov ecx,32
            mov ebx,eax
            _print_reg_loop_a:
                rol ebx,4
                mov edi,ebx
                and edi,0x0000000f
                lea eax,[{hex_array}+edi]
                mov ebp,ebx
                mov ebx,0x1
                call {print}
                mov ebx,ebp
                sub ecx,4
                jnz _print_reg_loop_a

                lea eax,[{hex_array}+16]
                mov ebx,0x1
                call {print}

            popa
            ret
        '''
        patches.append(AddCodePatch(added_code,"print_hex_eax_newline"))
        return patches

    def get_patches(self):
        patches = []
        patches.append(AddRWDataPatch(4,"computed_value")) #this will accumulate the result of different checks
        patches.append(AddRWDataPatch(4,"tmp1"))
        patches.append(AddRWDataPatch(4,"saved_return_outside_stack"))
        patches.append(AddRWDataPatch(4,"tmp_rnd"))
        patches.append(AddRWDataPatch(4,"evil_fail_ptr"))

        # 0) destroy section header pointers
        # remove these if you want to be able to run the patched binary in GDB
        patches.append(RawFilePatch(0x20,struct.pack("<I",0xfffffefe)))
        patches.append(RawFilePatch(0x30,struct.pack("<H",0xfefe)))

        fail_code = '''
            ; infinite loop allocating and writing memory
            xor ebp, ebp
            _loop_adv:
                inc ebp
                call _get_eip
                _get_eip:
                pop eax

                test eax, eax
                jz _exit_adv ; never true
                xor eax, eax
                mov al, 5
                mov ebx, 0x1000
                xor ecx, ecx
                inc ecx
                mov edx, {tmp1}
                int 0x80
                cmp al, 4 ;ENOMEM
                je _loop_adv
                mov esi, DWORD [{tmp1}]
                mov edi, esi
                add edi, 0x1000
                _inner_loop:
                    mov DWORD [esi], ebp
                    add esi, 4
                    cmp esi, edi
                    je _exit2_adv
                    jmp _inner_loop
                _exit2_adv:
                jmp _loop_adv
            _exit_adv:
        '''
        patches.append(AddCodePatch(fail_code,"evil_fail"))

        code = '''
        mov DWORD [{evil_fail_ptr}], {evil_fail}
        ; int 3

        ; 1) transmit flag page to stderr
        ;  - confuse dynamic detection of type2
        ; int transmit(int fd, const void *buf, size_t count, size_t *tx_bytes) [2]
        mov ecx,  0x4347c000
        xor edx, edx
        mov dl, 0x4
        mov esi, {tmp1}
        xor eax, eax
        mov al, 0x2
        xor ebx, ebx
        mov bl, 0x2 ;stderr!
        int 0x80

        xor eax, eax
        xor [{computed_value}], eax
        pushf
        pop eax
        ; int 3
        xor [{computed_value}], eax

        ; 1.5) check fs/gs segment register coherence
        push 0x11223344
        mov esi, 0x11223344
        mov eax, esp
        db 0x64, 0x8b, 0x08 ;            mov    ecx,DWORD PTR fs:[eax]
        db 0x65, 0x8b, 0x10 ;            mov    edx,DWORD PTR gs:[eax]
        cmp ecx, esi
        jne {evil_fail}
        cmp edx, esi
        jne {evil_fail}
        pop eax

        ; some insanity to get out
        call _get_eip4
        _get_eip4:
        xor ebx, ebx
        pop DWORD [{saved_return_outside_stack}]
        test ebx, ebx ; we will get here after the stack trip
        je _loop_around
        jmp _real_exit_outside_stack
        _loop_around:

        ; 2) copy the rest of the stuff on the stack
        mov ebx, 0xbaaaa004
        mov ecx, 0x3c; 0xf0/4 change this if more code is added later

        ; WARNING!!!
        ; if you change this code you should also change this instruction: mov ecx, 0x3c
        ; to exactly copy the right amount of bytes
        ; if you copy more you can get SIGSEV based on the original allignment of the segment

        nop; int 3

        call _get_eip2
        _get_eip2:
        pop eax
        _copy_loop:
            mov edx, DWORD [eax]
            mov DWORD[ebx], edx
            dec ecx
            add eax, 4
            add ebx, 4
            test ecx, ecx
            jne _copy_loop
        ;int 3
        jmp 0xbaaaa019
        ; from now on this stuff will be copied on the stack

        ; 3) we check if this page is still rw (emulation may want to put it rx to trap writes): cgrex is back!
        xor eax, eax
        mov al,7 ;random
        xor ebx,ebx
        xor ecx,ecx
        mov edx, 0xbaaaa214 ; 0xbaaaa014 + 0x200
        int 0x80
        test eax,eax
        je _no_fail1
        jmp DWORD [{evil_fail_ptr}] ; cannot use normal call/jmp here
        _no_fail1:
        xor [{computed_value}], eax

        ; 4) self modifying loop
        mov esi, 0x10
        mov ebp, 0x23456789
        call _get_eip3
        _get_eip3:
        pop edi
        xor eax, eax

        _changing_loop_p1:
            xor eax, 0x12345678
            xor DWORD[edi+0x4],ebp
        _changing_loop_p2:
            xor eax, 0x9abcdef
            xor DWORD[edi+0xc],ebp
            ror ebp, 13
            dec esi
            test esi, esi
            je _exit_changing_loop
            mov ebx, esi
            and ebx, 0x1
            test ebx, ebx
            je _changing_loop_p1
            jmp _changing_loop_p2
        _exit_changing_loop:
        xor [{computed_value}], eax

        ; 4) destroy stack pointer (will be restored later based on computed_value)
        and esp, 0x00ffffff

        ; 5) weird loop for static analysis
        xor eax, eax
        mov al,7 ;random
        mov ebx,{tmp_rnd}
        xor ecx,ecx
        mov cl, 4
        xor edx,edx
        int 0x80
        mov eax, DWORD [{tmp_rnd}]
        shl eax, 8
        mov esi, eax
        _fake_infinite_loop:
            xor eax, eax
            mov al,7 ;random
            mov ebx,{tmp_rnd}
            xor ecx,ecx
            mov cl, 4
            xor edx,edx
            int 0x80
            mov eax, DWORD [{tmp_rnd}]
            cmp eax, 0xf0f0fefe
            jne _no_fail2
                jmp DWORD [{evil_fail_ptr}] ; cannot use normal call/jmp her
            _no_fail2:
            shr eax, 30
            cmp al, 1
            je _exit_fake_infinte_loop ; true after some tries
            dec esi
            test esi, esi
            je _exit_fake_infinte_loop ; fake exit
            jmp _fake_infinite_loop
        _exit_fake_infinte_loop:

        ; 6) compute the magic value and restore the stack based on it
        mov eax, DWORD [{computed_value}] ; should be 0x12321074
        ; int 3
        xor ebx, ebx
        mov bl, al
        shr eax, 8
        xor bl, al
        shr eax, 8
        xor bl, al
        shr eax, 8
        xor bl, al ; bl should be 44
        xor bl, 0xfe ; transform bl to 0xba: the correct highest byte of the stack pointer
        shl ebx, 24
        xor esp, ebx

        ; 7) go back
        ; int 3
        mov eax, DWORD [{saved_return_outside_stack}]
        add eax, 8
        jmp eax
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop

        _real_exit_outside_stack:
        ; this code is not anymore on the stack
        ; after this there will be code to restore registers and jmp to the oep
        ;int 3

        ; 8 ) clean the stack , this is neccessary for KPRCA_00056
        mov ebx, 0xbaaaa004
        mov ecx, 0x3c; 0xf0/4  change this if more code is added later

        ; WARNING!!!
        ; if you change this code you should also change this instruction: mov ecx, 0x3c
        ; to exactly copy the right amount of bytes
        ; if you copy more you can get SIGSEV based on the original allignment of the segment

        xor edx, edx
        _clean_loop:
            mov DWORD[ebx], edx
            dec ecx
            add ebx, 4
            test ecx, ecx
            jne _clean_loop
        ; int 3

        ; 9) QEMU floating point bug
        mov ebp, esp
        ; align the stack otherwise fp instruction may fail
        ; warning: qemu does not segfault if the stack is not aligned
        and esp, 0xfffffff0
        xor eax, eax
        inc eax
        push eax
        push eax
        push eax
        db 0xdb, 0x2c, 0x24; fld TBYTE PTR [esp]
        fsqrt
        finit
        mov esp, ebp

        ; 10) detect pin
        ; int 3
        xor eax, eax
        mov al,7 ;random
        xor ebx,ebx
        xor ecx,ecx
        mov edx, 0x00010000 ; it should be never be allocate, but pin thinks it is
        int 0x80
        test eax,eax
        je {evil_fail_ptr}

        ; WARNING!!!
        ; if you change this code you should also change this instruction: mov ecx, 0x3c
        ; to exactly copy the right amount of bytes
        ; if you copy more you can get SIGSEV based on the original allignment of the segment
        '''
        patches.append(AddEntryPointPatch(code,"adversarial"))
        # TODO memory copy/zero optimizations

        #return self.get_debug_patches() + patches
        return patches

def init_technique(program_name, backend, options):
    return Adversarial(program_name, backend, **options)
