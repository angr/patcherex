import os
from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import AddCodePatch, AddRODataPatch, InsertCodePatch

if __name__ == '__main__':
    bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), './new_test_files'))

    backend = DetourBackend(os.path.join(bin_location, "test"))
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
    injected_code = '''
    mov eax, {transmitted_string}
    mov ebx, 4
    call {transmit_function}
    '''
    patches.append(InsertCodePatch(0x0804840b,injected_code,name="injected_code_after_receive"))

    backend.apply_patches(patches)
    backend.save("/tmp/patched")
