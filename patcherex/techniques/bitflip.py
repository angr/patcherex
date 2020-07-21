import patcherex
import angr

from .. import utils
from .. import cfg_utils

import capstone
import logging
from patcherex.patches import *

l = logging.getLogger("patcherex.techniques.Bitflip")


class Bitflip(object):

    def __init__(self,binary_fname,backend):
        self.binary_fname = binary_fname
        self.patcher = backend


    @staticmethod
    def get_bitflip_code():
        code = '''
            ; given the prereceive patch esi points to the num of received bytes
            ; int 3
            xor ebx, ebx
            mov  edx, DWORD [esi]
            test edx, edx
            je _bitflip_end
            ; ecx = buf, edx = len
            _bitflip_loop:
                mov bl, BYTE [ecx]
                mov bl, BYTE [{bitflip_translation_table}+ebx]
                mov BYTE [ecx], bl
                inc ecx
                dec edx
                jne _bitflip_loop
            _bitflip_end:
        '''
        # TODO this is not optimized code, the sse code seems to fail in some cases
        # and it does not seem to be that faster
        # maybe the problem is that I corrupt xmm registers (test failing is test_patch_master NRFIN_00073)
        return code

    @staticmethod
    def get_translation_table_patch():
        translations = {b'\x00': b'\x31', b'\x43': b'\x00', b'\n': b'\x43', b'\x31': b'\n'}
        full_translation_table = {}
        tstr = b""
        for i in range(256):
            c = bytes([i])
            if c in translations:
                tstr += translations[c]
            else:
                tstr += c
        return AddRODataPatch(tstr, name="bitflip_translation_table")

    @staticmethod
    def get_presyscall_patch(syscall_addr):
        code = '''
            ; if esi was NULL it will be restored to NULL by the syscall wrapper
            test esi, esi
            jne _exit_prereceive
            mov esi, {prereceive_bitflip_nbytes}
            _exit_prereceive:
        '''
        p1 = InsertCodePatch(syscall_addr, code, "prereceive_bitflip_patch",priority=900)
        p2 = AddRWDataPatch(4, "prereceive_bitflip_nbytes")
        return [p1, p2]


    def get_patches(self):
        patches = []
        cfg = self.patcher.cfg

        receive_wrapper = [ff for ff in cfg.functions.values() if \
                cfg_utils.detect_syscall_wrapper(self.patcher,ff) == 3]
        if len(receive_wrapper) != 1:
            l.warning("Found %d receive_wrapper... better not to touch anything", len(receive_wrapper))
            return []
        receive_wrapper = receive_wrapper[0]
        # here we assume that receive_wrapper is a "sane" syscall wrapper, as checked by detect_syscall_wrapper
        last_block = [b for b in receive_wrapper.blocks if b.addr != receive_wrapper.addr][0]
        victim_addr = int(last_block.addr)
        syscall_addr = victim_addr - 2

        patches.extend(Bitflip.get_presyscall_patch(syscall_addr))
        patches.append(Bitflip.get_translation_table_patch())
        # free registers esi, edx, ecx, ebx are free because we are in a syscall wrapper restoring them
        # ebx: fd, ecx: buf, edx: count, esi: rx_byte
        code = '''
            test eax, eax ; receive succeeded
            jne _exit_bitflip

            test ebx, ebx ; test if ebx is 0 (stdin)
            je _enter_bitflip
            cmp ebx, 1
            jne _exit_bitflip
            _enter_bitflip:

            %s

            _exit_bitflip:
        ''' % (Bitflip.get_bitflip_code())

        patches.append(InsertCodePatch(victim_addr, code, "postreceive_bitflip_patch", priority=900))
        return patches

def init_technique(program_name, backend, options):
    return Bitflip(program_name, backend, **options)
