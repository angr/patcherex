
#
# Some common code and data shared among all backends
#

ASM_ENTRY_POINT_PUSH_ENV = 'pusha\n'

ASM_ENTRY_POINT_RESTORE_ENV = '''
popa
; clean the stack above, preserve registers accoring to the abi
; we only clean the very bottom, if a patch touches more it has to clean by itself
; we are after_restore: edx is 0 and we need to restore eax, I don't care about eflags
mov eax,  0xbaaaafa0
_clean_stack_loop_entrypoint:
    mov [eax], edx
    add eax, 4
    cmp eax, 0xbaaab000
jne _clean_stack_loop_entrypoint
xor eax, eax
; restore flags
push 0x202
popf
mov DWORD [esp-4], eax
'''
