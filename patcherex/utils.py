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
import string


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


class ASMConverter(object):
    size_suffix = {
        1: 'b',
        2: 'w',
        4: 'l',
    }

    @staticmethod
    def get_size(op):
        """
        Get the size from the operand
        :param str op: The operand
        :return: Size in bytes
        :rtype: int
        """

        # memory operand
        op = op.lower()
        if "dword" in op:
            return 4
        elif "word" in op:
            return 2
        elif "byte" in op:
            return 1

        # register
        if len(op) == 3 and op.startswith('e') and op[-1] in ('x', 'i', 'p'):
            return 4
        elif len(op) == 2 and any([ c in string.lowercase for c in op ]):
            if not op.endswith('h') and not op.endswith('l'):
                return 2
            else:
                return 1
        return None

    @staticmethod
    def reg_to_att(reg):
        """
        Convert a register string from intel syntax to AT&T syntax
        :param str reg: The register name
        :return: converted string
        :rtype: str
        """

        reg = reg.lower()
        is_reg = False

        if len(reg) == 3 and reg.startswith('e') and reg[-1] in ('x', 'i', 'p'):
            is_reg = True
        elif len(reg) == 2:
            if reg.endswith('h') or reg.endswith('l') or reg[-1] in ('x', 'i', 'p'):
                is_reg = True

        if not is_reg:
            return None

        return "%%%s" % reg

    @staticmethod
    def mem_to_att(mem):
        """
        Convert a memory operand string from intel syntax to AT&T syntax
        :param str mem: The memory operand string
        :return: converted string
        :rtype: str
        """

        m = re.match(r"[^\[]*\[([^\]]+)\]", mem)
        if m:
            mem_ptr = m.group(1)

            # TODO: base + index * scale + displacement
            # m = re.match(r"")

            # base + displacement
            m = re.match(r"\s*([^\s\+\-]+)\s*[\+\-]\s*([^\s\+\-]+)", mem_ptr)
            if m:
                base, disp = m.group(1), m.group(2)

                base_reg = ASMConverter.reg_to_att(base)
                if base_reg is None:
                    # some idiot wrote it in this way: displacement + base
                    # e.g. {this_is_a_label} + edi
                    # fuck anyone who wrote assembly like that...
                    base, disp = disp, base

                base_reg = ASMConverter.reg_to_att(base)

                if base_reg is None:
                    raise ValueError('Unsupported input: %s' % mem_ptr)

                if disp[0] == '{' and disp[-1] == '}':
                    disp = disp[1:-1]

                return "%s(%s)" % (disp, base_reg)

            # base or displacement
            m = re.match(r"\s*([^\s\+\-]+)", mem_ptr)
            if m:
                something = m.group(1)
                reg = ASMConverter.reg_to_att(something)
                if reg:
                    # base
                    return "(%s)" % reg
                else:
                    # displacement
                    # TODO: fix it
                    if something[0] == '{' and something[-1] == '}':
                        return something[1:-1]
                    return "%s" % something

        if mem[0] == '{' and mem[-1] == '}':
            return "$%s" % mem[1:-1]

        return None

    @staticmethod
    def imm_to_att(op):
        """
        Convert an immediate to AT&T style syntax
        :param str op: The operand
        :return: converted string
        :rtype: str
        """

        m = re.match(r"\s*([0-9a-fA-Fxh]+)$", op)
        if m:
            imm = m.group(1)
            return "$%s" % imm

    @staticmethod
    def to_att(op, mnemonic=None):
        """
        Convert an operand from intel syntax to AT&T syntax
        :param str op: the operand string
        :param str mnemonic: the mnemonic
        :return: converted string
        :rtype: str
        """

        new_op = ASMConverter.reg_to_att(op)
        if new_op is not None:
            return 'reg', new_op
        new_op = ASMConverter.mem_to_att(op)
        if new_op is not None and mnemonic[0] != 'j' and mnemonic not in ('call', ):
            return 'mem', new_op
        new_op = ASMConverter.imm_to_att(op)
        if new_op is not None:
            return 'imm', new_op

        if op[0] == '{' and op[-1] == '}':
            # it's a label
            return 'label', op[1:-1]

        # other type of label
        return 'label', op

    @staticmethod
    def mnemonic_to_att(m, size):

        if m in ('int', 'pushfd', 'popfd', ):
            return m
        if m.startswith('j'):
            return m

        m += ASMConverter.size_suffix[size]
        return m

    @staticmethod
    def intel_to_att(asm):

        # convert each line from intel syntax to AT&T syntax

        converted = []

        for l in asm.split('\n'):

            # comments
            m = re.match(r"(\s*);([\s\S]*)", l)
            if m:
                converted.append("\t#" + m.group(2))
                continue

            # inline comments
            m = re.match(r"([\s\S]+);([\s\S]+)", l)
            if m:
                inline_comments = "\t#" + m.group(2)
                l = m.group(1)
            else:
                inline_comments = ""

            l = l.strip()

            # two operands
            m = re.match(r"(\s*)([\S]+)\s+([^,]+),\s*([^,]+)\s*$", l)
            if m:
                mnemonic, op1, op2 = m.group(2), m.group(3), m.group(4)
                spaces = m.group(1)

                # switch the op
                op1, op2 = op2, op1
                size = ASMConverter.get_size(op1)
                if size is None: size = ASMConverter.get_size(op2)

                if size is None:
                    raise NotImplementedError('Not supported')

                op1 = ASMConverter.to_att(op1, mnemonic=mnemonic)[1]
                op2 = ASMConverter.to_att(op2, mnemonic=mnemonic)[1]

                # suffix the mnemonic
                mnemonic = ASMConverter.mnemonic_to_att(mnemonic, size)

                s = "%s%s\t%s, %s%s" % (spaces, mnemonic, op1, op2, inline_comments)
                converted.append(s)

                continue

            # one operand
            m = re.match(r"(\s*)([\S]+)\s+([^,]+)\s*$", l)
            if m:
                mnemonic, op = m.group(2), m.group(3)
                spaces = m.group(1)

                size = ASMConverter.get_size(op)
                if size is None:
                    # it might be a label
                    size = 4

                op_sort, op = ASMConverter.to_att(op, mnemonic=mnemonic)

                # suffix the mnemonic
                mnemonic = ASMConverter.mnemonic_to_att(mnemonic, size)

                #if mnemonic[0] == 'j' and op_sort == 'label':
                #    op = "." + op

                s = "%s%s\t%s%s" % (spaces, mnemonic, op, inline_comments)
                converted.append(s)

                continue

            # no operand
            m = re.match(r"(\s*)([^\s,:]+)\s*$", l)
            if m:
                mnemonic = m.group(2)
                spaces = m.group(1)

                mnemonic = ASMConverter.mnemonic_to_att(mnemonic, 4)

                s = "%s%s%s" % (spaces, mnemonic, inline_comments)
                converted.append(s)

                continue

            # other stuff
            converted.append(l)

        return "\n".join(converted)

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
    fp = open(template_fname)
    template_content = fp.read()
    fp.close()
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
            fp = open(asm_fname, 'r')
            fcontent = fp.read()
            fp.close()
            print "\n".join(["%02d\t%s"%(i+1,l) for i,l in enumerate(fcontent.split("\n"))])
            raise NasmException

        fp = open(bin_fname)
        compiled = fp.read()
        fp.close()

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
            fp = open(asm_fname, 'r')
            fcontent = fp.read()
            fp.close()
            print "\n".join(["%02d\t%s"%(i+1,l) for i,l in enumerate(fcontent.split("\n"))])
            raise NasmException

        fp = open(bin_fname)
        compiled = fp.read()
        fp.close()

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
            fp = open(c_fname, 'r')
            fcontent = fp.read()
            fp.close()
            print "\n".join(["%02d\t%s"%(i+1,l) for i,l in enumerate(fcontent.split("\n"))])
            raise CLangException
        res = exec_cmd("objcopy -O binary %s %s" % (object_fname, bin_fname), shell=True)
        if res[2] != 0:
            print "objcopy error:"
            print res[0]
            print res[1]
            raise ObjcopyException
        fp = open(bin_fname)
        compiled = fp.read()
        fp.close()

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

