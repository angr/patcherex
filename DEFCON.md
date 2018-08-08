# DEFCON (IDA plugin)

## Preqs
* IDA 7.1
* Python 2.7
* pip
* virtualenv

## Installation

``` bash
sudo apt-get install nasm clang

mkvirtualenv <name>

git clone <this repo>

patcherex/install_deps.sh
pip install -e patcherex

ln -s $(readlink -f patcherex/ida_plugin/patcherex_ida_main.py) <IDA DIR>/ida-7.1/plugins/patcherex_ida_main.py
ln -s $(readlink -f patcherex/ida_plugin/patcherex_ida) <IDA DIR>/ida-7.1/plugins/patcherex_ida
```

## Usage

You are likely better off exploring than reading a long winded explanation, but here are the basics:

* Press Ctrl-Shift-N to add a new patch
* Press Ctrl-Shift-P to open the Patcherex window (for viewing / editing patches)
* Press Ctrl-Shift-R to run patcherex and generate a new binary
* From assembly, reference symbols as such: `{symbol_name}`. Keep in mind that this *literally pastes the address in*. If you have further questions about how this is implemented, please ping @paul.

IF YOU ARE WORKING ON A PIE BINARY, SEE FAQ #3.

## Features

### What works

* Inserting assembly where CFGFast can generate blocks (if this doesn't work, ask Fish :P)
* Adding ro/rw data
* Removing instructions
* Compiling C

### What doesn't work

* Reassembler
* ARM support

## FAQ

### 1. What's the difference between "Add code" and "Insert assembly"?

"Add code" places the code in a new segment with no jump to it, while "Insert assembly" generates a detours jumpout. This is done to support C compilation (insertion of C directly is hard (tm)).

### 2. Insert Assembly fails with a message about no blocking being present at that address. What do?

CFG didn't generate a block there. Ping @paul for help if you can't work around it.

### 3. My binary is PIE. How do I write code to support this?

Use `call {pie_thunk}`. This will clobber {rax, [rsp]} in order to return a pointer to the base of the binary
in rax. From there, you can just add other symbols to it to get real pointers.

### 4. Can you get reassembler working?

No.

### 5. Can you get ARM support working?

No.
