import patcherex
import angr

import patcherex.utils as utils
import patcherex.cfg_utils as cfg_utils

import capstone
import logging
from patcherex.patches import *

l = logging.getLogger("patcherex.techniques.Bitflip")


class Bitflip(object):

    def __init__(self,binary_fname,backend):
        self.binary_fname = binary_fname
        self.patcher = backend


    def get_bitflip_code(self):
        code = '''
            ; given the prereceive patch esi points to the num of received bytes
            ; int 3
            mov  edx, DWORD [esi]
            test edx, edx
            je _bitflip_end
            ; ecx = buf, edx = len
            _bitflip_not_loop:
                not BYTE [ecx]
                inc ecx
                dec edx
                jne _bitflip_not_loop
            _bitflip_end:
        '''
        # TODO this is not optimized code, the sse code seems to fail in some cases
        # and it does not seem to be that faster
        # maybe the problem is that I corrupt xmm registers (test failing is test_patch_master NRFIN_00073)
        # for reference, this is the sse code:
        '''
            ; given the prereceive patch esi points to the num of received bytes
            mov   edx, DWORD [esi]
            ; ecx = buf, edx = len
            test   edx,edx
            je     _bitflip_end
            xor    esi,esi
            mov    eax,edx
            and    eax,0xffffffe0
            je     _bitflip_final_comparison
            xor    esi,esi
            pcmpeqd xmm0,xmm0
            _xmm_loop:
                movdqu xmm1, [ecx+esi*1]
                movdqu xmm2, [ecx+esi*1+0x10]
                pxor   xmm1,xmm0
                pxor   xmm2,xmm0
                movdqu [ecx+esi*1],xmm1
                movdqu [ecx+esi*1+0x10],xmm2
                add    esi,0x20
                cmp    eax,esi
                jne    _xmm_loop
                mov    esi,eax
            _bitflip_final_comparison:
            cmp    esi,edx
            je     _bitflip_end
            add    ecx,esi
            sub    edx,esi
            _last_bitflip_loop:
                not    BYTE [ecx]
                inc    ecx
                dec    edx
                jne    _last_bitflip_loop
            _bitflip_end:
        '''
        return code


    def get_presyscall_patch(self,syscall_addr):
        code = '''
            ; if esi was NULL it will be restored to NULL by the syscall wrapper
            test esi, esi
            jne _exit_prereceive
            mov esi, {prereceive_bitflip_nbytes}
            _exit_prereceive:
        '''
        p1 = InsertCodePatch(syscall_addr,code,"prereceive_bitflip_patch",priority=300)
        p2 = AddRWDataPatch(4,"prereceive_bitflip_nbytes")
        return [p1,p2]


    def get_patches(self):
        patches = []
        cfg = self.patcher.cfg

        receive_wrapper = [ff for ff in cfg.functions.values() if \
                cfg_utils.detect_syscall_wrapper(self.patcher,ff) == 3] 
        if len(receive_wrapper) != 1:
            l.warning("Found %d receive_wrapper... better not to touch anything"%len(receive_wrapper))
            return []
        receive_wrapper = receive_wrapper[0]
        #import IPython; IPython.embed()
        # here we assume that receive_wrapper is a "sane" syscall wrapper, as checked by detect_syscall_wrapper
        last_block = [b for b in receive_wrapper.blocks if b.addr != receive_wrapper.addr][0]
        victim_addr = int(last_block.addr)
        syscall_addr = victim_addr - 2

        patches.extend(self.get_presyscall_patch(syscall_addr))
        # free registers esi, edx, ecx, ebx are free because we are in a syscall wrapper restoring them
        # ebx: fd, ecx: buf, edx: count, esi: rx_byte
        code = '''
            test eax, eax ; receive succeded
            jne _exit_bitflip

            test ebx, ebx ; test if ebx is 0 (stdin)
            je _enter_bitflip
            cmp ebx, 1
            jne _exit_bitflip
            _enter_bitflip:

            %s

            _exit_bitflip:
        ''' % (self.get_bitflip_code())

        patches.append(InsertCodePatch(victim_addr,code,"postreceive_bitflip_patch",priority=300))

        return patches
