import patcherex
from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import *

backend = DetourBackend("./new_test_files/test")
patches = []

transmit_code = '''
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
patches.append(AddCodePatch(transmit_code,name="transmit_function"))
patches.append(AddRODataPatch("HI!\x00",name="transmitted_string"))
# the following code is going to be executed just before the original instruction at 0x8048166
injected_code = '''
mov eax, {transmitted_string} ; a patch can refer to another patch address, by putting its name between curly brackets
mov ebx, 4
call {transmit_function}
'''
patches.append(InsertCodePatch(0x0804840b,injected_code,name="injected_code_after_receive"))

backend.apply_patches(patches)
backend.save("/tmp/patched")

