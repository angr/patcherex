import patcherex
import angr

import patcherex.utils as utils
import patcherex.cfg_utils as cfg_utils

from ..technique import Technique

import capstone
import logging
from patcherex.patches import *

l = logging.getLogger("patcherex.techniques.TrasmitProtection")


class TransmitProtection(Technique):
    def __init__(self,binary_fname,backend,allow_reg_reuse=True):
        super(TransmitProtection, self).__init__(binary_fname, backend)
        self.nslot = 16

    def get_c_patch(self):
        code = '''
        typedef char int8_t;
        typedef unsigned char uint8_t;
        typedef short int16_t;
        typedef unsigned short uint16_t;
        typedef int int32_t;
        typedef unsigned int uint32_t;
        typedef long long int64_t;
        typedef unsigned long long uint64_t;

        __attribute__((fastcall)) int sub1(uint32_t transmitted_value_32, uint16_t* mem_area){
                uint8_t nslot = %d;
                uint16_t* array_area = &(mem_area[2]);
                uint8_t index,inner_index;
                uint16_t transmitted_value = transmitted_value_32 & 0xffff;
                uint16_t ntransmitted = ((transmitted_value_32 & 0xffff0000) >> 16);
                uint16_t current_transmitted_value;
                uint8_t nconsecutive=0;
                uint16_t current_value;

                if(mem_area[0]==0){
                    array_area[-1]=0;
                    for(index=0;index<nslot;index++){
                        array_area[index]=0xffff;
                    }
                    mem_area[0]=1;
                }

                for(current_transmitted_value=transmitted_value;current_transmitted_value<transmitted_value+ntransmitted;current_transmitted_value++){
                    for(index=0;index<nslot;index++){
                        if(current_transmitted_value==array_area[index]){
                            continue;
                        }
                        if(current_transmitted_value>array_area[index-1] && current_transmitted_value<array_area[index]){
                            for(inner_index=nslot-1;inner_index>index;inner_index--){
                                array_area[inner_index] = array_area[inner_index-1];
                            }
                            array_area[inner_index] = current_transmitted_value;
                        }
                    }
                    if(current_transmitted_value>array_area[index]){
                        array_area[index] = current_transmitted_value;
                    }

                }

                current_value = 0;
                //asm("int $3");
                for(index=0;index<nslot;index++){
                    if(array_area[index]==current_value+1){
                        nconsecutive += 1;
                        if(nconsecutive == 4-1){
                            return 1;
                        }
                    }else{
                        nconsecutive = 0;
                    }
                    current_value = array_area[index];
                }
            return 0;
        }
        ''' % (self.nslot)
        return AddCodePatch(code,"transmit_protection_array_handler",is_c=True,optimization="-Oz")

    def compute_patches(self,victim_addr):
        patches = []

        code = '''
        cmp ecx, 0x4347c000
        jb _exit_tp
        cmp ecx, 0x4347d000
        jae _exit_tp
        cmp ebx, 0x1 ; check if stdin or stdout (apparently they are the same!)
        je _correct_fd
        test ebx, ebx
        je _correct_fd
        test ebx, ebx
        jne _exit_tp
        _correct_fd:
        cmp edx, 0x4 ;the idea is that even if transmit is short, eventually this will be retransmitted
        jb _exit_tp_2
        jmp 0x8047ffc
        _exit_tp_2:
        cmp edx, 0x0
        je _exit_tp

        ; slow path begins
        push ecx
        push edx
        push eax
        mov eax, edx
        shl eax, 16
        mov edx, {last_transmit_array}
        and ecx, 0x0000ffff
        or ecx, eax
        %s
        test eax,eax
        pop eax
        pop edx
        pop ecx
        je _exit_tp

        jmp 0x8047ffb
        _exit_tp:
        ''' % utils.get_nasm_c_wrapper_code("transmit_protection_array_handler",get_return=True,debug=False)
        patches.append(InsertCodePatch(victim_addr,code,name="transmit_protection",priority=300))
        patches.append(AddRWDataPatch(self.nslot+1,name="last_transmit_array"))
        return patches + [self.get_c_patch()]


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

def init_technique(program_name, backend, options):
    return TransmitProtection(program_name, backend, **options)
