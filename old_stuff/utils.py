
import subprocess
import contextlib
import yaml
import tempfile
import shutil
import os
import capstone
import struct
import sys

from Exceptions import *

import IPython


ELF_HEADER = "7f45 4c46 0101 0100 0000 0000 0000 0000".replace(" ","").decode('hex')
CGC_HEADER = "7f43 4743 0101 0143 014d 6572 696e 6f00".replace(" ","").decode('hex')

#adapted from:
#http://stackoverflow.com/questions/18666816/using-python-to-dump-hexidecimals-into-yaml
def representer(dumper, data):
    return yaml.ScalarNode('tag:yaml.org,2002:int', hex(data))
def ydump(*args,**kwargs):
    kwargs['width']=1000000 #we like long lines
    res = yaml._dump(*args,**kwargs)
    return res.strip()
yaml.add_representer(int, representer)
yaml._dump = yaml.dump
yaml.dump = ydump
#the output of yaml_hex.dump() can still be loaded using the standard yaml module
yaml_hex = yaml

def str_overwrite(tstr,new,pos=None):
    if pos == None:
        pos = len(tstr)
    return tstr[:pos] + new + tstr[pos+len(new):]


def pad_str(tstr,align,pad="\x00"):
    str_len = len(tstr)
    if str_len % align == 0:
        return tstr
    else:
        return tstr + pad * (align - (str_len%align))


def elf_to_cgc(tstr):
    assert(tstr.startswith(ELF_HEADER))
    return str_overwrite(tstr,CGC_HEADER,0)


def cgc_to_elf(tstr):
    assert(tstr.startswith(CGC_HEADER))
    return str_overwrite(tstr,ELF_HEADER,0)


def exe_type(tstr):
    if tstr.startswith(ELF_HEADER):
        return "ELF"
    elif tstr.startswith(CGC_HEADER):
        return "CGC"
    else:
        return None

@contextlib.contextmanager
def tempdir(prefix='/tmp/python_tmp'):
    """A context manager for creating and then deleting a temporary directory."""
    tmpdir = tempfile.mkdtemp(prefix=prefix)
    try:
        yield tmpdir
    finally:
        #pass
        shutil.rmtree(tmpdir)


def exec_cmd(args,cwd=None,shell=False,debug=False):
    #debug = True
    if debug:
        print "EXECUTING:",repr(args),cwd,shell

    pipe = subprocess.PIPE
    p = subprocess.Popen(args,cwd=cwd,shell=shell,stdout=pipe,stderr=pipe)
    std = p.communicate()
    retcode = p.poll()
    res = (std[0],std[1],retcode)
    
    if debug:
        print "RESULT:",repr(res)

    return res


def compile_asm_template(template_name,substitution_dict):
    formatted_template_content = get_asm_template(template_name,substitution_dict)
    return compile_asm(formatted_template_content)


def get_asm_template(template_name,substitution_dict):
    project_basedir = os.path.sep.join(os.path.abspath(__file__).split(os.path.sep)[:-2])
    template_fname = os.path.join(project_basedir,"asm",template_name)
    template_content = open(template_fname).read()
    formatted_template_content = template_content.format(**substitution_dict)
    return formatted_template_content


def instruction_to_str(instruction,print_bytes=True):
    if print_bytes:
        pbytes = str(instruction.bytes).encode('hex').rjust(16)
    else:
        pbytes = ""
    return "0x%x %s:\t%s\t%s %s" %(instruction.address, pbytes, instruction.mnemonic, instruction.op_str,
            "{"+instruction.overwritten+"}" if hasattr(instruction,'overwritten') else "")

def capstone_to_nasm(instruction):
        tstr = "db "
        tstr += ",".join([hex(struct.unpack("B",b)[0]) for b in str(instruction.bytes)])
        tstr += " ;"+instruction_to_str(instruction,print_bytes=False)
        return tstr


def decompile(code,offset=0x0):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    return list(md.disasm(code, offset))


def compile_jmp(origin,target):
    jmp_str = '''
        USE32
        org {code_loaded_address}

        jmp {target}
    '''.format(**{'code_loaded_address':hex(origin),'target':hex(target)})
    return compile_asm(jmp_str)


def get_multiline_str():
    print "[press Ctrl+C to exit]"
    input_list = []
    try:
        while True:
            input_str = raw_input()
            input_list.append(input_str)
    except KeyboardInterrupt:
        pass
    print ""
    return "\n".join(input_list)


def compile_asm(code,base=None):
    with tempdir() as td:
        asm_fname = os.path.join(td,"asm.s")
        bin_fname = os.path.join(td,"bin.o")
        
        fp = open(asm_fname,'wb')
        fp.write("bits 32\n")
        if base != None:
            fp.write("org %s\n" % hex(base))
        fp.write(code)
        fp.close()
        
        res = exec_cmd("nasm -o %s %s"%(bin_fname,asm_fname),shell=True)
        if res[2] != 0:
            print "NASM error:"
            print res[0]
            print res[1]
            print open(asm_fname,'r').read()
            raise NasmException

        compiled = open(bin_fname).read()

    return compiled

@contextlib.contextmanager
def redirect_stdout(new_target1,new_target2):
    old_target1, sys.stdout = sys.stdout, new_target1 # replace sys.stdout
    old_target2, sys.stderr = sys.stderr, new_target2

    try:
        yield (new_target1,new_target2) # run some code with the replaced stdout
    finally:
        sys.stdout = old_target1 # restore to the previous value
        sys.stderr = old_target2


