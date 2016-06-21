import patcherex
import angr
import patcherex.utils as utils
import patcherex.cfg_utils as cfg_utils

import capstone
import logging
from patcherex.patches import *

l = logging.getLogger("patcherex.techniques.TrasmitProtection")


class TransmitProtection(object):

    def __init__(self,binary_fname,backend,allow_reg_reuse=True):
        self.binary_fname = binary_fname
        self.patcher = backend
        self.nslot = 16


    def compute_patches(self,victim_addr):
        patches = []
        '''
                mov esi, edx ; current index
                _len_loop:
                    xor eax, eax eax ;array pointer
                    movz ebx, cx
                    add ebx, esi ;ebx = current considered transmitted byte

                    _insert_loop:
                        cmp bx, WORD [{last_transmit_array}+eax]
                        jb _reloop_insert_loop
                        cmp bx, WORD [{last_transmit_array}+eax+2]
                        ja _reloop_insert_loop

                        _push_down_loop:
                            mov edi, eax
                            mov dx, WORD [{last_transmit_array}+edi]
                            mov WORD [{last_transmit_array}+edi], dx
                            inc edi
                            cmp edi, %d
                            jne _push_down_loop

                        mov WORD [{last_transmit_array}+eax+2], bx

                        _reloop_insert_loop:
                            inc eax
                            inc eax
                            cmp eax, %d
                            jne _insert_loop

                    inc esi
                    cmp edx, esi
                    jbe _len_loop

                xor eax, eax ;array pointer
                xor ebx, ebx ;nmatch
                mov ecx, %d
                _scan_loop:
                    mov dx, WORD [{last_transmit_array}+eax]
                    mov si, WORD [{last_transmit_array}+eax+2]
                    dec si
                    cmp dx,si
                    jne _nomatch
                    inc ebx
                    jmp _match
                    jmp _end_scan_iter
                    _nomatch:
                        xor ebx, ebx
                    _end_scan_iter:
                        cmp eax, %d
                        je _out_scan_loop
                        inc eax

                _out_scan_loop:
        ''' # % (self.nslot+2)

        code = '''
        cmp ecx, 0x4347c000
        jb _exit
        cmp ecx, 0x4347d000
        jae _exit
        cmp ebx, 0x1
        jne _exit
        cmp edx, 0x4 ;the idea is that even if transmit is short, eventually this will be retransmitted
        jb _exit2
        jmp 0x8047ffc
        _exit2:
        cmp edx, 0x0
        je _exit

        ; slow path begins
        pusha
        ; TODO
        popa
        _exit:
        '''
        patches.append(InsertCodePatch(victim_addr,code,name="transmit_protection",priority=200))
        patches.append(AddRWInitDataPatch("\x00\x00"+"\xff\xff"*(self.nslot+1),name="last_transmit_array"))
        return patches


    def get_patches(self):
        patches = []
        cfg = self.patcher.cfg

        transmit_wrapper = [ff for ff in cfg.functions.values() if \
                cfg_utils.detect_syscall_wrapper(self.patcher,ff) == 2] 
        if len(transmit_wrapper) != 1:
            l.warning("Found %d transmit_wrapper... better not to touch anything"%len(transmit_wrapper))
            return []
        transmit_wrapper = transmit_wrapper[0]
        victim_node = cfg.get_any_node(transmit_wrapper.addr)
        victim_addr = int(victim_node.instruction_addrs[-1])

        patches.extend(self.compute_patches(victim_addr))

        #import IPython; IPython.embed()


        return patches
