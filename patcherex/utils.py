import os
import re
import sys
import shutil
import struct
import capstone
import tempfile
import contextlib
import subprocess
import fnmatch
import os


class NasmException(Exception):
    pass


class CLangException(Exception):
    pass


class ObjcopyException(Exception):
    pass


class UndefinedSymbolException(Exception):
    pass


ELF_HEADER = "7f45 4c46 0101 0100 0000 0000 0000".replace(" ", "").decode('hex')
CGC_HEADER = "7f43 4743 0101 0143 014d 6572 696e".replace(" ", "").decode('hex')


def str_overwrite(tstr, new, pos=None):
    if pos is None:
        pos = len(tstr)
    return tstr[:pos] + new + tstr[pos+len(new):]


def pad_str(tstr, align, pad="\x00"):
    str_len = len(tstr)
    if str_len % align == 0:
        return tstr
    else:
        return tstr + pad * (align - (str_len % align))


def elf_to_cgc(tstr):
    assert(tstr.startswith(ELF_HEADER))
    return str_overwrite(tstr, CGC_HEADER, 0)


def cgc_to_elf(tstr):
    assert(tstr.startswith(CGC_HEADER))
    return str_overwrite(tstr, ELF_HEADER, 0)


def exe_type(tstr):
    if tstr.startswith(ELF_HEADER):
        return "ELF"
    elif tstr.startswith(CGC_HEADER):
        return "CGC"
    else:
        return None


@contextlib.contextmanager
def tempdir(prefix='/tmp/python_tmp', delete=True):
    # A context manager for creating and then deleting a temporary directory.
    tmpdir = tempfile.mkdtemp(prefix=prefix)
    try:
        yield tmpdir
    finally:
        if delete:
            shutil.rmtree(tmpdir)


def exec_cmd(args, cwd=None, shell=False, debug=False):
    # debug = True
    if debug:
        print "EXECUTING:", repr(args), cwd, shell

    pipe = subprocess.PIPE
    p = subprocess.Popen(args, cwd=cwd, shell=shell, stdout=pipe, stderr=pipe)
    std = p.communicate()
    retcode = p.poll()
    res = (std[0], std[1], retcode)
    
    if debug:
        print "RESULT:", repr(res)

    return res


def compile_asm_template(template_name, substitution_dict):
    formatted_template_content = get_asm_template(template_name, substitution_dict)
    return compile_asm(formatted_template_content)


def get_asm_template(template_name, substitution_dict):
    project_basedir = os.path.sep.join(os.path.abspath(__file__).split(os.path.sep)[:-2])
    template_fname = os.path.join(project_basedir, "asm", template_name)
    template_content = open(template_fname).read()
    formatted_template_content = template_content.format(**substitution_dict)
    return formatted_template_content


def instruction_to_str(instruction, print_bytes=True):
    if print_bytes:
        pbytes = str(instruction.bytes).encode('hex').rjust(16)
    else:
        pbytes = ""
    return "0x%x %s:\t%s\t%s %s" % (instruction.address, pbytes, instruction.mnemonic, instruction.op_str,
                                    "<"+instruction.overwritten+">" if hasattr(instruction, 'overwritten') else "")


def capstone_to_nasm(instruction):
        tstr = "db "
        tstr += ",".join([hex(struct.unpack("B", b)[0]) for b in str(instruction.bytes)])
        tstr += " ;"+instruction_to_str(instruction, print_bytes=False)
        return tstr


def bytes_to_asm(in_str, comment=None):
        tstr = "db "
        tstr += ",".join([hex(ord(b)) for b in in_str])
        if comment != None:
            tstr += " ; "+comment
        return tstr


def decompile(code, offset=0x0):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    return list(md.disasm(code, offset))


def compile_jmp(origin, target):
    jmp_str = '''
        USE32
        org {code_loaded_address}

        jmp {target}
    '''.format(**{'code_loaded_address': hex(int(origin)), 'target': hex(int(target))})
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


def compile_asm(code, base=None, name_map=None):
    #print "=" * 10
    #print code
    #if base != None: print hex(base)
    #if name_map != None: print {k: hex(v) for k,v in name_map.iteritems()}
    try:
        if name_map is not None:
            code = code.format(**name_map)
    except KeyError as e:
        raise UndefinedSymbolException(str(e))

    with tempdir() as td:
        asm_fname = os.path.join(td, "asm.s")
        bin_fname = os.path.join(td, "bin.o")
        
        fp = open(asm_fname, 'wb')
        fp.write("bits 32\n")
        if base is not None:
            fp.write("org %s\n" % hex(base))
        fp.write(code)
        fp.close()
        
        res = exec_cmd("nasm -o %s %s" % (bin_fname, asm_fname), shell=True)
        if res[2] != 0:
            print "NASM error:"
            print res[0]
            print res[1]
            print "\n".join(["%02d\t%s"%(i+1,l) for i,l in enumerate(open(asm_fname, 'r').read().split("\n"))])
            raise NasmException

        compiled = open(bin_fname).read()

    return compiled


def compile_asm_fake_symbol(code, base=None, ):
    code = re.subn('\{.*?\}', "0x41414141", code)[0]

    with tempdir() as td:
        asm_fname = os.path.join(td, "asm.s")
        bin_fname = os.path.join(td, "bin.o")

        fp = open(asm_fname, 'wb')
        fp.write("bits 32\n")
        if base is not None:
            fp.write("org %s\n" % hex(base))
        fp.write(code)
        fp.close()

        res = exec_cmd("nasm -o %s %s" % (bin_fname, asm_fname), shell=True)
        if res[2] != 0:
            print "NASM error:"
            print res[0]
            print res[1]
            print "\n".join(["%02d\t%s"%(i+1,l) for i,l in enumerate(open(asm_fname, 'r').read().split("\n"))])
            raise NasmException

        compiled = open(bin_fname).read()

    return compiled


def get_nasm_c_wrapper_code(function_symbol, get_return=False, debug=False):
    # TODO maybe with better calling convention on llvm this can be semplified
    wcode = []
    wcode.append("pusha")
    # TODO add param list haandling, right two params in ecx/edx are supported
    '''
    assert len(param_list) <= 2 # TODO support more parameters
    if len(param_list) == 1:
        wcode.append("mov ecx, %s" % param_list[0])
    if len(param_list) == 2:
        wcode.append("mov ecx, %s" % param_list[0])
        wcode.append("mov edx, %s" % param_list[1])
    '''
    if debug:
        wcode.append("int 0x3")
    wcode.append("call {%s}" % function_symbol)
    if get_return:
        wcode.append("mov [esp+28], eax") #FIXME check
    wcode.append("popa")

    return "\n".join(wcode)


def compile_c(code, optimization='-Oz', name_map=None):
    # TODO symbol support in c code
    with tempdir() as td:
        c_fname = os.path.join(td, "code.c")
        object_fname = os.path.join(td, "code.o")
        bin_fname = os.path.join(td, "code.bin")

        fp = open(c_fname, 'wb')
        fp.write(code)
        fp.close()

        res = exec_cmd("clang -m32 -nostdlib -mno-sse -ffreestanding %s -o %s -c %s" % (optimization, object_fname, c_fname), shell=True)
        if res[2] != 0:
            print "CLang error:"
            print res[0]
            print res[1]
            print "\n".join(["%02d\t%s"%(i+1,l) for i,l in enumerate(open(c_fname, 'r').read().split("\n"))])
            raise CLangException
        res = exec_cmd("objcopy -O binary %s %s" % (object_fname, bin_fname), shell=True)
        if res[2] != 0:
            print "objcopy error:"
            print res[0]
            print res[1]
            raise ObjcopyException
        compiled = open(bin_fname).read()

    return compiled


@contextlib.contextmanager
def redirect_stdout(new_target1, new_target2):
    old_target1, sys.stdout = sys.stdout, new_target1  # replace sys.stdout
    old_target2, sys.stderr = sys.stderr, new_target2

    try:
        yield (new_target1, new_target2)  # run some code with the replaced stdout
    finally:
        sys.stdout = old_target1  # restore to the previous value
        sys.stderr = old_target2


def find_files(folder,extension,only_exec=False):
    matches = []
    for root, dirnames, filenames in os.walk(folder):
        for filename in fnmatch.filter(filenames, extension):
            full_name = os.path.join(root, filename)
            if not only_exec or os.access(full_name, os.X_OK):
                matches.append(full_name)
    return matches


def round_up_to_page(addr):
    return (addr + 0x1000 - 1) / 0x1000 * 0x1000

