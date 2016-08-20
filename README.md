# Patcherex
Patcherex is the component used to create patched binaries in our CRS.

The code has been tested on Ubuntu 16.04 64bit, using PyPy as the Python interpreter.

## Installation

```bash
apt-get install nasm clang
cd patcherex
pip install -e . # before doing this, other CRS components need to be installed (see setup.py)
```

There are three fundamental concepts in *patcherex*:
* patches
* techniques
* backends

## Usage

### patches
A patch is a single modification to a binary.

Different types of patches exist, for instance:
* **AddEntryPointPatch**: add some code that it is going to be executed before the original entry point of the binary.
* **InsertCodePatch**: add some code that it is going to be executed before an instruction at a specific address
* **AddCodePatch**: add some code that other patches can use.
* **AddRWData**: add some RW data that other patches can use.

See [patcherex/patches.py](patcherex/patches.py) for the full list of available patches.

Every patch has a name and it is possible to refer from a patch to another patch.

### backends
A backend is the compoenent responsible to "injects" a list of patches in an existing binary and produces a new binary.

There are two backends:
* **DetourBackend**: it adds patches by inserting jumps inside the original code.
* **ReassemblerBacked**: it adds code by disassembling and then reassembling the origianl code.

The DetourBackend generates bigger and slower binaries (and in some rare cases it cannot insert some patches), however it is slighlty more reliable than the ReassemblerBackend (i.e., it breaks slightly less binaries).

### techiniques
A techiniques is a component analyzing a binary and returnin a list of patches.

For instance:
* **StackRetEncryption**: it encrypts the return pointers of "unsafe" functions.
* **Backdoor**: it adds the backdoor to a binary.
* **...**

## Examples

### IPython usage

*Patcherex* can be used with IPython.

For instance, the following example, modify the binary [CADET_00003](test_bin/CADET_00003) so that it prints "HI!" everytime a new string is entered by the user.

```python
import patcherex
from patcherex.backends.detourbackend import DetourBackend
from patcherex.backends.reassembler_backend import ReassemblerBackend
from patcherex.patches import *

# the detour backend can be used as well:
# backend = DetourBackend("test_binaries/CADET_00003")
backend = ReassemblerBackend("test_binaries/CADET_00003")
patches = []

transmit_code = '''
  ; eax is the transmitted buffer
  ; ebx is the length
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
; at this code location, it is fine to clobber eax and ebx
mov eax, {transmitted_string} ; a patch can refer to another patch address, by putting its name between curly brackets
mov ebx,
call {transmit_function}
'''
patches.append(InsertCodePatch(0x8048166,injected_code,name="injected_code_after_receive"))

# now we ask to the backend to inject all our patches
backend.apply_patches(patches)
# and then we save the file
backend.save("/tmp/CADET_00003_mod1")
# at this point you can try to run /tmp/CADET_00003_mod1 inside the DECREE VM or using our modified version of Qemu
```

### Command line usage

Any function in [patch_master.py](patcherx/patch_master.py) called generate_*something*_binary inside the classs *PatchMaster* can be directly invoked by the command line.

The command syntax is the following:
```bash
./patch_master.py single <input_file> <method>  <output_file>
```

For instance, running the following command:
```bash
./patch_master.py single ../test_binaries/CADET_00003 stackretencryption  /tmp/CADET_00003_stackretencryption
```
will execute the following code:
```python
def generate_stackretencryption_binary(self, test_bin=None):
    backend = ReassemblerBackend(self.infile)
    patches = []
    patches.extend(StackRetEncryption(self.infile, backend).get_patches())
    backend.apply_patches(patches)
    final_content = backend.get_final_content()
    return (final_content, "")
 ```

patch_master.py contains also methods to patch multiple binaries in parallel and quickly test them.

