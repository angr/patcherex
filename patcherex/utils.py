import os
import re
import sys
import shutil
import capstone
import tempfile
import contextlib
import subprocess
import fnmatch
import string

from .errors import ASMConverterError, ASMConverterNotImplementedError

class NasmException(Exception):
    pass


class CLangException(Exception):
    pass


class ObjcopyException(Exception):
    pass


class UndefinedSymbolException(Exception):
    pass


ELF_HEADER = b"\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00"
CGC_HEADER = b"\x7f\x43\x47\x43\x01\x01\x01\x43\x01\x4d\x65\x72\x69\x6e"


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
        if op.strip().startswith("{"):
            return 4
        if "dword" in op:
            return 4
        elif "word" in op:
            return 2
        elif "byte" in op:
            return 1

        # register
        if len(op) == 3 and op.startswith('e') and op[-1] in ('x', 'i', 'p'):
            return 4
        elif len(op) == 2 and any([ c in string.ascii_lowercase for c in op ]):
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

        if len(reg) == 4 and reg.startswith('xmm'):
            is_reg = True
        elif len(reg) == 3 and reg.startswith('e') and reg[-1] in ('x', 'i', 'p'):
            is_reg = True
        elif len(reg) == 2:
            if reg.endswith('h') or reg.endswith('l') or reg[-1] in ('x', 'i', 'p'):
                is_reg = True

        if not is_reg:
            return None

        return "%%%s" % reg

    @staticmethod
    def mem_to_att_base_disp(base_reg, disp, sign):
        if sign == '-':
            disp = '-' + disp
        return "%s(%s)" % (disp, base_reg)

    @staticmethod
    def mem_to_att_base_index(base_reg, index_reg, sign):
        if sign == '-':
            # scale is -1
            return "(%s, %s, -1)" % (base_reg, index_reg)
        else:
            # scale is 1
            return "(%s, %s)" % (base_reg, index_reg)

    @staticmethod
    def mem_to_att_base_index_scale(base_reg, index_reg, scale, sign):
        if sign == '-':
            return "(%s, %s, -%s)" % (base_reg, index_reg, scale)
        else:
            return "(%s, %s, %s)" % (base_reg, index_reg, scale)

    @staticmethod
    def mem_to_att_index_scale_disp(index_reg, scale, disp, sign):
        if sign == '-':
            return "%s( , %s, -%s)" % (disp, index_reg, scale)
        else:
            return "%s( , %s, %s)" % (disp, index_reg, scale)

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

            # [{this_is_a_label}]
            m = re.match(r"^\s*\{([\S]+)\}\s*$", mem_ptr)
            if m:
                label = m.group(1)
                return label

            # base + index * scale + displacement
            scale_regex = "(0x1|0x2|0x4|0x8|1|2|4|8)"
            m = re.match(r"\s*([^\s\+\-]+)\s*([\+])\s*([^\s\+\-]+)\s*\*"+ scale_regex + \
                    r"\s*([\+\-])\s*([^\s\+\-]+)\s*$", mem_ptr)
            if m:
                part_0, sign_1, part_1, scale, sign_2, part_2 = m.groups()
                if all(c in string.digits for c in part_1):
                    # part_1 is displacement
                    part_2, part_1 = part_1, part_2

                base_reg = ASMConverter.reg_to_att(part_0)
                if base_reg is None: raise ASMConverterError('Unsupported base register "%s"' % part_0)
                index_reg = ASMConverter.reg_to_att(part_1)
                if index_reg is None: raise ASMConverterError('Unsupported index register "%s"' % part_1)
                disp = part_2

                if sign_2 == '-':
                    disp = '-' + disp
                # negative scale should be invalid:
                # "error: scale factor in address must be 1, 2, 4 or 8\nmovl    -0x10(%esi, %edi, -1)"
                scale = str((int(scale,base=0)))

                tstr =  "%s(%s, %s, %s)" % (disp, base_reg, index_reg, scale)
                return tstr

            # base + index + displacement
            m = re.match(r"\s*([^\s\+\-]+)\s*([\+\-])\s*([^\s\+\-]+)\s*([\+\-])\s*([^\s\+\-]+)\s*$", mem_ptr)
            if m:
                part_0, sign_1, part_1, sign_2, part_2 = m.groups()

                if all(c in string.digits for c in part_1):
                    # part_1 is displacement
                    part_2, part_1 = part_1, part_2

                if not all(c in string.digits+"xX" for c in part_2):
                    raise ASMConverterError('Unsupported displacement string "%s"' % part_2)

                base_reg = ASMConverter.reg_to_att(part_0)
                if base_reg is None: raise ASMConverterError('Unsupported base register "%s"' % part_0)
                index_reg = ASMConverter.reg_to_att(part_1)
                if index_reg is None: raise ASMConverterError('Unsupported index register "%s"' % part_1)

                disp = str((int(part_2,base=0)))

                if sign_2 == '-':
                    disp = '-' + disp

                if sign_1 == '-':
                    return "%s(%s, %s, -1)" % (disp, base_reg, index_reg)
                else:
                    return "%s(%s, %s)" % (disp, base_reg, index_reg)

            # base + displacement, or base + index * scale, or index * scale + displacement
            m = re.match(r"\s*([^\s\+\-]+)\s*([\+\-])\s*([^\s\+\-]+)\s*$", mem_ptr)
            if m:
                part_0, sign, part_1 = m.group(1), m.group(2), m.group(3)

                # see if this is index * scale
                m0 = re.match(r"^\s*([^\s\*]+)\s*\*\s*(\d+)\s*$", part_0)
                if m0:
                    # ouch it's index * scale
                    index, scale = m0.group(1), m0.group(2)

                    index_reg = ASMConverter.reg_to_att(index)

                    if part_1[0] == '{' and part_1[-1] == '}':
                        # disp might be a label. treat it as a displacement
                        disp = part_1[1:-1]
                    else:
                        # if part is a register, it's a "base + index"
                        part_1_reg = ASMConverter.reg_to_att(part_1)
                        if part_1_reg is not None:
                            # oh it is a register!
                            base_reg = part_1_reg
                            return ASMConverter.mem_to_att_base_index_scale(base_reg, index_reg, scale, sign)

                        # otherwise it's a displacement
                        disp = part_1

                    return ASMConverter.mem_to_att_index_scale_disp(index_reg, scale, disp, sign)

                else:
                    # it's base
                    base = part_0

                    base_reg = ASMConverter.reg_to_att(base)
                    if base_reg is None:
                        # some idiot wrote it in this way: displacement + base
                        # e.g. {this_is_a_label} + edi
                        # fuck anyone who wrote assembly like that...
                        base, part_1 = part_1, base

                    base_reg = ASMConverter.reg_to_att(base)

                    if base_reg is None:
                        raise ASMConverterError('Unsupported input: %s' % mem_ptr)

                    # let's decide if the part is an index or a displacement

                    if part_1[0] == '{' and part_1[-1] == '}':
                        # disp might be a label. treat it as a displacement
                        part_1 = part_1[1:-1]
                    else:
                        # if part is a register, it's a "base + index"
                        disp_reg = ASMConverter.reg_to_att(part_1)
                        if disp_reg is not None:
                            # oh it is a register!
                            return ASMConverter.mem_to_att_base_index(base_reg, disp_reg, sign)

                    m1 = re.match(r"^\s*([^\s\*]+)\s*\*\s*(\d+)\s*$", part_1)
                    if m1:
                        # it's a base + index * scale
                        index, scale = m1.group(1), m1.group(2)
                        index_reg = ASMConverter.reg_to_att(index)
                        return ASMConverter.mem_to_att_base_index_scale(base_reg, index_reg, scale, sign)
                    else:
                        # it's a "base + displacement"
                        disp = part_1
                        return ASMConverter.mem_to_att_base_disp(base_reg, disp, sign)

            # base or displacement
            m = re.match(r"\s*([^\s\+\-]+)\s*$", mem_ptr)
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

        # raise NotImplementedError('operand "%s" is not supported by ASMConverter. Please bug Fish to fix it.' % mem)
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
        return None

    @staticmethod
    def to_att(op, mnemonic=None):
        """
        Convert an operand from intel syntax to AT&T syntax
        :param str op: the operand string
        :param str mnemonic: the mnemonic
        :return: converted string
        :rtype: str
        """

        if op[0] == '{' and op[-1] == '}':
            # it's a label
            label = op[1:-1]
            if mnemonic[0] == 'j' or mnemonic in ('call', ):
                return 'label', '%s' % label
            else:
                return 'label', '$' + label

        new_op = ASMConverter.reg_to_att(op)
        if new_op is not None:
            if mnemonic[0] == 'j' or mnemonic in ('call', ):
                return 'reg', '*%s' % new_op
            else:
                return 'reg', new_op
        new_op = ASMConverter.mem_to_att(op)
        if new_op is not None:
            if mnemonic[0] != 'j' and mnemonic not in ('call', ):
                return 'mem', new_op
            else:
                return 'mem', '*%s' % new_op

        new_op = ASMConverter.imm_to_att(op)
        if new_op is not None:
            if mnemonic[0] != 'j':
                return 'imm', new_op
            else:
                return 'imm', op

        # other type of label
        return 'label', op

    @staticmethod
    def mnemonic_to_att(m, size, op_sort=None):

        if m in ('int', 'pushfd', 'popfd', 'nop', 'call',
                 # floating point instructions
                 'addss',
                 ):
            return m
        if m.startswith('j'):
            # jumps
            return m
        if m.startswith('f'):
            # floating point instructions
            return m
        if op_sort not in ('reg', 'mem') and m.startswith('j'):
            return m

        # special case for some mnemonics
        if m == 'movsx':
            size_suffix = ASMConverter.size_suffix[size]
            m = 'movs' + size_suffix + 'l'
            return m
        elif m == 'movzx':
            size_suffix = ASMConverter.size_suffix[size]
            m = 'movz' + size_suffix + 'l'
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
                # converted.append('#CONVERTED FROM: %s\n' % l)
                converted.append("\t#" + m.group(2))
                continue

            # inline comments
            m = re.match(r"^([\s\S]+);([\s\S]*)$", l)
            if m:
                inline_comments = "\t#" + m.group(2)
                l = m.group(1)
            else:
                inline_comments = ""

            l = l.strip()

            # NASM directive: db
            m = re.match(r"^\s*db\s+([\s\S]+)$", l)
            if m:
                hex_bytes = m.group(1).strip()
                for hex_byte in hex_bytes.split(','):
                    hex_byte = hex_byte.strip()
                    s = "\t.byte\t%s" % hex_byte
                    converted.append(s)
                continue

            # three operands
            m = re.match(r"(\s*)([\S]+)\s+([^,]+),\s*([^,]+),\s*([^,]+)\s*$", l)
            if m:
                mnemonic, op1, op2, op3 = m.group(2), m.group(3), m.group(4), m.group(5)
                spaces = m.group(1)

                # swap operands
                size = ASMConverter.get_size(op1)
                if size is None:
                    size = ASMConverter.get_size(op2)
                if size is None:
                    size = ASMConverter.get_size(op3)
                if size is None:
                    raise ASMConverterNotImplementedError('Cannot determine operand size from any operand in '
                                                          'instruction "%s"' % l
                                                          )

                op1, op2, op3 = op3, op2, op1
                op1 = ASMConverter.to_att(op1, mnemonic=mnemonic)[1]
                op2 = ASMConverter.to_att(op2, mnemonic=mnemonic)[1]
                op3 = ASMConverter.to_att(op3, mnemonic=mnemonic)[1]

                mnemonic = ASMConverter.mnemonic_to_att(mnemonic, size)

                s = "%s%s\t%s, %s, %s%s" % (spaces, mnemonic, op1, op2, op3, inline_comments)
                converted.append(s)

                continue

            # two operands
            m = re.match(r"(\s*)([\S]+)\s+([^,]+),\s*([^,]+)\s*$", l)
            if m:
                mnemonic, op1, op2 = m.group(2), m.group(3), m.group(4)
                spaces = m.group(1)

                # switch the op
                op1, op2 = op2, op1
                size = ASMConverter.get_size(op1)
                if size is None:
                    size = ASMConverter.get_size(op2)
                if size is None:
                    raise ASMConverterNotImplementedError('Not supported: ' + l)

                op1 = ASMConverter.to_att(op1, mnemonic=mnemonic)[1]
                op2 = ASMConverter.to_att(op2, mnemonic=mnemonic)[1]

                # suffix the mnemonic
                mnemonic = ASMConverter.mnemonic_to_att(mnemonic, size)

                # converted.append('#CONVERTED FROM: %s\n' % l)
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
                mnemonic = ASMConverter.mnemonic_to_att(mnemonic, size, op_sort=op_sort)

                #if mnemonic[0] == 'j' and op_sort == 'label':
                #    op = "." + op

                # converted.append('#CONVERTED FROM: %s\n' % l)
                s = "%s%s\t%s%s" % (spaces, mnemonic, op, inline_comments)
                converted.append(s)

                continue

            # no operand
            m = re.match(r"(\s*)([^\s,:]+)\s*$", l)
            if m:
                mnemonic = m.group(2)
                spaces = m.group(1)

                mnemonic = ASMConverter.mnemonic_to_att(mnemonic, 4)

                # converted.append('#CONVERTED FROM: %s\n' % l)
                s = "%s%s%s" % (spaces, mnemonic, inline_comments)
                converted.append(s)

                continue

            # other stuff
            # converted.append('#CONVERTED FROM: %s\n' % l)
            converted.append(l)

        return "\n".join(converted)


def bytes_overwrite(tstr, new, pos=None):
    if pos is None:
        pos = len(tstr)
    return tstr[:pos] + new + tstr[pos+len(new):]


def pad_bytes(tstr, align, pad=b"\x00"):
    str_len = len(tstr)
    if str_len % align == 0:
        return tstr
    else:
        return tstr + pad * (align - (str_len % align))


def elf_to_cgc(tstr):
    assert(tstr.startswith(ELF_HEADER))
    return bytes_overwrite(tstr, CGC_HEADER, 0)


def cgc_to_elf(tstr):
    assert(tstr.startswith(CGC_HEADER))
    return bytes_overwrite(tstr, ELF_HEADER, 0)


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
        print("EXECUTING:", repr(args), cwd, shell)

    pipe = subprocess.PIPE
    p = subprocess.Popen(args, cwd=cwd, shell=shell, stdout=pipe, stderr=pipe)
    std = p.communicate()
    retcode = p.poll()
    res = (std[0], std[1], retcode)

    if debug:
        print("RESULT:", repr(res))

    return res


def compile_asm_template(template_name, substitution_dict, bits=32):
    formatted_template_content = get_asm_template(template_name, substitution_dict)
    return compile_asm(formatted_template_content, bits=bits)


def get_asm_template(template_name, substitution_dict):
    project_basedir = os.path.sep.join(os.path.abspath(__file__).split(os.path.sep)[:-2])
    template_fname = os.path.join(project_basedir, "asm", template_name)
    fp = open(template_fname, "r")
    template_content = fp.read()
    fp.close()
    formatted_template_content = template_content.format(**substitution_dict)
    return formatted_template_content


def instruction_to_str(instruction, print_bytes=True):
    if print_bytes:
        pbytes = instruction.bytes.hex().rjust(16)
    else:
        pbytes = ""
    return "0x%x %s:\t%s\t%s %s" % (instruction.address, pbytes, instruction.mnemonic, instruction.op_str,
                                    "<"+instruction.overwritten+">" if hasattr(instruction, 'overwritten') else "")


def capstone_to_nasm(instruction):
        tstr = "db "
        tstr += ",".join([hex(b) for b in instruction.bytes])
        tstr += " ;"+instruction_to_str(instruction, print_bytes=False)
        return tstr


def bytes_to_asm(in_str, comment=None):
        tstr = "db "
        tstr += ",".join([hex(ord(b)) for b in in_str])
        if comment != None:
            tstr += " ; "+comment
        return tstr


def disassemble(code, offset=0x0, bits=32):
    if bits == 32:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    elif bits == 64:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    else:
        raise Exception("disassemble(): Unsupported bits %d." % bits)
    md.detail = True
    if isinstance(code, str):
        code = bytes(map(ord, code))
    return list(md.disasm(code, offset))


def compile_jmp(origin, target):
    jmp_str = '''
        USE32
        org {code_loaded_address}

        jmp {target}
    '''.format(**{'code_loaded_address': hex(int(origin)), 'target': hex(int(target))})
    return compile_asm(jmp_str)


def get_multiline_str():
    print("[press Ctrl+C to exit]")
    input_list = []
    try:
        while True:
            input_str = input()
            input_list.append(input_str)
    except KeyboardInterrupt:
        pass
    print("")
    return "\n".join(input_list)


def compile_asm(code, base=None, name_map=None, bits=32):
    #print "=" * 10
    #print code
    #if base != None: print hex(base)
    #if name_map != None: print {k: hex(v) for k,v in name_map.iteritems()}
    try:
        if name_map is not None:
            code = code.format(**name_map) # compile_asm
        else:
            code = re.subn(r'{.*?}', "0x41414141", code)[0] # solve symbols
    except KeyError as e:
        raise UndefinedSymbolException(str(e))

    with tempdir() as td:
        asm_fname = os.path.join(td, "asm.s")
        bin_fname = os.path.join(td, "bin.o")

        fp = open(asm_fname, 'wb')
        fp.write(b"bits %d\n" % bits)
        if base is not None:
            fp.write(bytes("org %#x\n" % base, "utf-8"))
        fp.write(bytes(code, "utf-8"))
        fp.close()

        res = exec_cmd("nasm -o %s %s" % (bin_fname, asm_fname), shell=True)
        if res[2] != 0:
            print("NASM error:")
            print(res[0])
            print(res[1])
            fp = open(asm_fname, 'r')
            fcontent = fp.read()
            fp.close()
            print("\n".join(["%02d\t%s"%(i+1,l) for i,l in enumerate(fcontent.split("\n"))]))
            raise NasmException

        fp = open(bin_fname, "rb")
        compiled = fp.read()
        fp.close()

    return compiled


def get_nasm_c_wrapper_code(function_symbol, get_return=False, debug=False):
    # TODO maybe with better calling convention on llvm this can be semplified
    wcode = []
    wcode.append("pusha")
    # TODO add param list handling, right two params in ecx/edx are supported
    # assert len(param_list) <= 2 # TODO support more parameters
    # if len(param_list) == 1:
    #     wcode.append("mov ecx, %s" % param_list[0])
    # if len(param_list) == 2:
    #     wcode.append("mov ecx, %s" % param_list[0])
    #     wcode.append("mov edx, %s" % param_list[1])
    if debug:
        wcode.append("int 0x3")
    wcode.append("call {%s}" % function_symbol)
    if get_return:
        wcode.append("mov [esp+28], eax") #FIXME check
    wcode.append("popa")

    return "\n".join(wcode)


def compile_c(code, optimization='-Oz', compiler_flags="-m32"):
    # TODO symbol support in c code
    with tempdir() as td:
        c_fname = os.path.join(td, "code.c")
        object_fname = os.path.join(td, "code.o")
        bin_fname = os.path.join(td, "code.bin")

        fp = open(c_fname, 'w')
        fp.write(code)
        fp.close()

        res = exec_cmd("clang -nostdlib -mno-sse -ffreestanding %s -o %s -c %s %s" \
                        % (optimization, object_fname, c_fname, compiler_flags), shell=True)
        if res[2] != 0:
            print("CLang error:")
            print(res[0])
            print(res[1])
            fp = open(c_fname, 'r')
            fcontent = fp.read()
            fp.close()
            print("\n".join(["%02d\t%s"%(i+1,l) for i,l in enumerate(fcontent.split("\n"))]))
            raise CLangException
        res = exec_cmd("objcopy -B i386 -O binary -j .text %s %s" % (object_fname, bin_fname), shell=True)
        if res[2] != 0:
            print("objcopy error:")
            print(res[0])
            print(res[1])
            raise ObjcopyException
        fp = open(bin_fname, "rb")
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
    for root, _, filenames in os.walk(folder):
        for filename in fnmatch.filter(filenames, extension):
            full_name = os.path.join(root, filename)
            if not only_exec or os.access(full_name, os.X_OK):
                matches.append(full_name)
    return matches


def round_up_to_page(addr):
    return int((addr + 0x1000 - 1) / 0x1000) * 0x1000


def string_to_labels(tstr):
    labels = []
    for line in tstr.split("\n"):
        line = line.strip()
        m = re.match("^_.*:",line)
        if m != None:
            labels.append(m.group(0))
    labels = [l for l in labels if not any([c in l for c in "( )"])]
    return labels
