
import string
import random

import pyvex

from ..technique import Technique
from ..patches import InsertCodePatch

# TODO: - detect if ebp is used as base pointer in a function or not
# TODO: - support more types of VEX statements and expressions
# TODO: - use a dynamic key
# TODO: - raise proper exceptions
# TODO: - more testing
# TODO: - bug fixes
# TODO: - put all pointers to a writable section, and encrypt all pointers when binary starts


class MiniAST(object):
    def __init__(self, op, args=None):
        self.op = op
        self.args = args

    def __repr__(self):
        s = "(%s %s)" % (self.op, " ".join(repr(a) for a in self.args))
        return s


class DerefInstruction(object):
    def __init__(self, ins_addr, action, addr_regs):
        self.ins_addr = ins_addr
        self.ins_size = None
        self.action = action
        self.addr_regs = addr_regs
        self.addr_regs_used = None

    def __repr__(self):
        return "<Deref %#08x %s@%s>" % (self.ins_addr, self.action, self.addr_regs)


class RefInstruction(object):
    def __init__(self, ins_addr, addr_reg, sources):
        self.ins_addr = ins_addr
        self.ins_size = None
        self.addr_reg = addr_reg
        self.sources = sources

    def __repr__(self):
        return "<Ref %#08x %s: %s>" % (self.ins_addr, self.addr_reg, self.sources)


class SimplePointerEncryption(Technique):
    def __init__(self, filename, backend):
        """
        Constructor.

        :param str filename: File name of the binary to protect.
        :param Backend backend: The patcher backend.
        """

        super(SimplePointerEncryption, self).__init__(filename, backend)

        self._patches = self._generate_patches()

    def _generate_patches(self, debug=True):
        """
        Analyze the binary and generate a list of patches.

        :param bool debug: True if in debug mode. Debugging information will be output to stdout.
        :return: a list of patches.
        :rtype: list
        """

        patches = [ ]

        cfg = self.patcher.cfg

        # I cannot read fucking AT&T syntax
        cfg.project.arch.capstone_x86_syntax = 'intel'
        cfg.project.factory._lifter.clear_cache()

        mem_deref_instrs = self._memory_deref_instructions(cfg)
        mem_ref_instrs = self._memory_ref_instructions(cfg)

        if debug:
            print "dereferences"

            # print them out
            for deref in mem_deref_instrs:  # type: DerefInstruction
                print deref, cfg.project.factory.block(deref.ins_addr, num_inst=1).capstone

            print "references"

            for ref in mem_ref_instrs:  # type: RefInstruction
                print ref, cfg.project.factory.block(ref.ins_addr, num_inst=1).capstone

        arch = cfg.project.arch

        # insert an encryption patch after each memory referencing instruction

        for ref in mem_ref_instrs:  # type: RefInstruction
            dst_reg = arch.register_names[ref.addr_reg]
            asm_code = """
            add {dst_reg}, 5
            """.format(dst_reg=dst_reg)
            patch = InsertCodePatch(ref.ins_addr + ref.ins_size, asm_code)

            patches.append(patch)

        # insert an decryption patch *and a re-encryption patch* before each memory dereferencing instruction

        for deref in mem_deref_instrs:  # type: DerefInstruction

            # FIXME: if there are more than one registers, what sort of problems will we have?
            src_reg_offset = next(r for r in deref.addr_regs if r not in (arch.sp_offset, arch.bp_offset))
            src_reg = arch.register_names[src_reg_offset]

            # decryption patch
            asm_code = """
            sub {src_reg}, 5
            """.format(src_reg=src_reg)
            patch = InsertCodePatch(deref.ins_addr, asm_code)

            patches.append(patch)

            # we do not apply the re-encryption patch if the source register is reused immediately
            # for example: movsx eax, byte ptr [eax]
            # apparently we don't decrypt eax since it's already overwritten

            if deref.addr_regs_used is not False:
                # re-encryption patch
                asm_code = """
                pushfd
                add {src_reg}, 5
                popfd
                """.format(src_reg=src_reg)

                patch = InsertCodePatch(deref.ins_addr + deref.ins_size, asm_code)
                patches.append(patch)

        # for syscalls, make sure all pointers are decrypted before calling
        syscalls = {
            'transmit': ([1, 3], [ ]),
            'receive': ([1, 3], [ ]),
            'allocate': ([2], [2]),
            'deallocate': ([1], [ ]),
            'fdwait': ([1, 2, 3, 4], [ ]),
            'random': ([0, 2], [ ]),
        }
        for syscall_name, (argument_indices_in, argument_indices_out) in syscalls.iteritems():
            syscall_patches = self._generate_syscall_patches(cfg, syscall_name, argument_indices_in,
                                                             argument_indices_out
                                                             )
            patches.extend(syscall_patches)

        return patches

    def _generate_syscall_patches(self, cfg, syscall_name, argument_indices_in, argument_indices_out):
        """


        :param angr.analyses.CFG cfg: The control flow graph.
        :param str syscall_name: Name of the syscall to patch.
        :param list argument_indices_int: A list of input argument indices that are pointers.
        :param list argument_indices_out: A list of output argument indices that are pointers.
        :return: A list of patches.
        :rtype: list
        """

        SYSCALL_ARGUMENTS = ['ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']

        patches = [ ]

        syscall = cfg.functions.function(name=syscall_name)
        predecessors = cfg.get_any_node(syscall.addr).predecessors
        for pred in predecessors:
            # it must ends with int 80h
            last_instr_addr = pred.instruction_addrs[-1]
            last_instr = cfg.project.factory.block(last_instr_addr, num_inst=1)
            if last_instr.capstone.insns[0].mnemonic != 'int':
                # TODO: raise a proper exception
                raise Exception("unsupported syscall callers at %#08x", pred.addr)

            for index in argument_indices_in:
                reg = SYSCALL_ARGUMENTS[index]
                lbl_name = "".join([random.choice(string.lowercase) for _ in xrange(10)])

                asm = """
                    cmp {reg}, 0
                    je .{lbl}
                    sub {reg}, 5
                .{lbl}:
                """.format(reg=reg, lbl=lbl_name)
                patch = InsertCodePatch(last_instr_addr, asm)
                patches.append(patch)

            for index in argument_indices_out:
                reg = SYSCALL_ARGUMENTS[index]
                lbl_name = "".join([random.choice(string.lowercase) for _ in xrange(10)])
                asm = """
                    push eax
                    mov eax, dword ptr [{reg}]
                    cmp eax, 0
                    je .{lbl}
                    add eax, 5
                    mov dword ptr [{reg}], eax
                    pop eax
                .{lbl}:
                """.format(reg=reg, lbl=lbl_name)

                patch = InsertCodePatch(last_instr_addr + 2, asm)  # len(int 80h) == 2
                patches.append(patch)

        return patches

    def _ast_to_addr_regs(self, ast, is_addr_valid):
        """
        Pick registers that holds a valid address and return them.

        :param MiniAST ast: The AST
        :param is_addr_valid: A function that takes in an address and returns True iff the address is valid.
        :return: A list of register offsets.
        :rtype: list
        """

        # we only care about where the base comes from
        # - if there is only one register, then it must be the base
        # - if there are a register and a const, the register is the base if and only if the const
        #   is not a valid address. Otherwise the constant is the base
        # - if there are two constants, it's gonna be a little complicated... TODO

        if len(ast.args) == 2:
            # binary operations
            if ast.op == '+':
                if ast.args[1].op == 'const':
                    # something + constant
                    if is_addr_valid(ast.args[1].args[0]):
                        # base address + some offset
                        return [ ]
                    else:
                        if ast.args[0].op == 'reg':
                            # this register must be the base address
                            return [ ast.args[0].args[0] ]
                        elif ast.args[0].op == 'const' and is_addr_valid(ast.args[0].args[0]):
                            # the constant is the base address
                            return [ ]
                        else:
                            return self._ast_to_addr_regs(ast.args[0], is_addr_valid)

                elif ast.args[1].op in ('<<', ):
                    # arg1 must be used as an offset or index
                    # arg0 is the base address
                    if ast.args[0].op == 'reg':
                        return [ ast.args[0].args[0] ]
                    elif ast.args[0].op == 'const':
                        return [ ]
                elif ast.args[0].op == 'reg':
                    # let's see if we can extract a base address from other arguments
                    regs = self._ast_to_addr_regs(ast.args[1], is_addr_valid)
                    if not regs:
                        # nice! the first argument must be the base register
                        return ast.args[0].args[0]

            elif ast.op == '-':
                if ast.args[0].op == 'reg':
                    return [ ast.args[0].args[0] ]
                elif ast.args[0].op == 'const':
                    return [ ]

        elif len(ast.args) == 1:
            if ast.op == 'reg':
                # directly using the register as the address
                return ast.args
            elif ast.op == 'const':
                # using a constant as the address
                return [ ]

        print "Unresolved AST", ast
        import ipdb; ipdb.set_trace()

    def _memory_deref_instructions(self, cfg):
        """
        Iterate through all basic blocks in the CFG, and find all instructions that load data from memory

        :param angr.analyses.CFG cfg: The control flow graph.
        :return: A list of DerefInstruction objects.
        :rtype: list
        """

        instrs = [ ]

        ip_offset = self.patcher.cfg.project.arch.ip_offset
        sp_offset = self.patcher.cfg.project.arch.sp_offset
        bp_offset = self.patcher.cfg.project.arch.bp_offset

        def is_addr_valid(addr):
            if cfg._addr_belongs_to_section(addr) is not None:
                return True

            if 0x4347c000 <= addr < 0x4347c000 + 0x1000:
                return True

            return False

        OPSTR_TO_OP = {
            'Iop_Add32': '+',
            'Iop_Sub32': '-',
            'Iop_Sub8': '-',
            'Iop_Shl32': '<<',
            'Iop_And8': '&',
            'Iop_And32': '&',
            'Iop_Sar32': '>>',
            'Iop_Shr32': '>>',
            'Iop_Mul32': '*',
        }

        for function in cfg.functions.values():  # type: angr.knowledge.Function
            for block in function.blocks:

                last_instr = None  # type: DerefInstruction

                vex_block_noopt = cfg.project.factory.block(block.addr, opt_level=0, max_size=block.size).vex

                ins_addr = None
                tmps = {}

                for stmt in vex_block_noopt.statements:
                    if isinstance(stmt, pyvex.IRStmt.IMark):
                        ins_addr = stmt.addr + stmt.delta
                        # update the instruction size of the previous DerefInstruction object
                        if last_instr is not None and last_instr.ins_size is None:
                            last_instr.ins_size = ins_addr - last_instr.ins_addr

                    elif isinstance(stmt, pyvex.IRStmt.WrTmp):
                        tmp = stmt.tmp
                        data = stmt.data
                        if isinstance(data, pyvex.IRExpr.Get):
                            # read from register
                            tmps[tmp] = MiniAST('reg', [ data.offset ])
                            if last_instr is not None and last_instr.addr_regs_used is None and \
                                    data.offset in last_instr.addr_regs:
                                last_instr.addr_regs_used = True
                        elif isinstance(data, pyvex.IRExpr.Binop):
                            # some sort of arithmetic operations
                            if data.op.startswith('Iop_Cmp') or \
                                    data.op.startswith('Iop_Div') or \
                                    data.op.startswith('Iop_Or') or \
                                    data.op.startswith('Iop_Xor') or \
                                    data.op in ('Iop_32HLto64', ):
                                # ignore them.
                                continue
                            elif data.op in OPSTR_TO_OP:
                                op = OPSTR_TO_OP[data.op]
                            else:
                                op = data.op

                            args = [ ]
                            for arg in data.args:
                                if isinstance(arg, pyvex.IRExpr.RdTmp):
                                    if arg.tmp in tmps:
                                        args.append(tmps[arg.tmp])
                                    else:
                                        args.append(MiniAST('unknown'))
                                elif isinstance(arg, pyvex.IRExpr.Const):
                                    val = arg.con.value
                                    args.append(MiniAST('const', [ val ]))

                            tmps[tmp] = MiniAST(op, args)

                        elif isinstance(data, pyvex.IRExpr.Load):
                            # loading from memory!
                            addr = data.addr
                            if isinstance(addr, pyvex.IRExpr.RdTmp):
                                tmp_addr = addr.tmp
                                if tmp_addr in tmps:
                                    last_instr = DerefInstruction(ins_addr, 'load',
                                                                  self._ast_to_addr_regs(tmps[tmp_addr], is_addr_valid)
                                                                  )
                                    instrs.append(last_instr)
                        elif isinstance(data, pyvex.IRExpr.RdTmp):
                            data_tmp = data.tmp
                            if data_tmp in tmps:
                                tmps[tmp] = tmps[data_tmp]
                        elif isinstance(data, pyvex.IRExpr.Const):
                            # loading a const address
                            value = data.con.value
                            if is_addr_valid(value):
                                tmps[tmp] = MiniAST('const', [ value ])
                    elif isinstance(stmt, pyvex.IRStmt.Store):
                        # writing some stuff into memory
                        addr = stmt.addr
                        if isinstance(addr, pyvex.IRExpr.RdTmp):
                            tmp_addr = addr.tmp
                            if tmp_addr in tmps:
                                last_instr = DerefInstruction(ins_addr, 'store',
                                                              self._ast_to_addr_regs(tmps[tmp_addr], is_addr_valid)
                                                              )
                                instrs.append(last_instr)
                    elif isinstance(stmt, pyvex.IRStmt.Put):
                        # loading data into a register
                        if last_instr is not None and last_instr.addr_regs_used is None and \
                                len(last_instr.addr_regs) == 1 and \
                                stmt.offset in last_instr.addr_regs:
                            last_instr.addr_regs_used = False

                if last_instr is not None and last_instr.ins_size is None:
                    last_instr.ins_size = block.addr + vex_block_noopt.size - last_instr.ins_addr
                    last_instr = None

        # filtering
        filtered = [ ]
        for i in instrs:
            if not i.addr_regs or any(r for r in i.addr_regs if r in (sp_offset, bp_offset, ip_offset)):
                continue
            filtered.append(i)

        return filtered

    def _memory_ref_instructions(self, cfg):
        """
        Iterate through all basic blocks in the CFG, and find all instructions that load pointers from memory

        Usually there are two ways to load an effective address:
        - lea any address to a register
        - mov a literal to a register

        :param angr.analyses.CFG cfg: The control flow graph.
        :return: A list of RefInstruction objects.
        :rtype: list
        """

        instrs = [ ]

        ip_offset = self.patcher.cfg.project.arch.ip_offset
        sp_offset = self.patcher.cfg.project.arch.sp_offset
        bp_offset = self.patcher.cfg.project.arch.bp_offset

        addr_belongs_to_section = self.patcher.cfg._addr_belongs_to_section

        def is_addr_valid(addr):
            if addr_belongs_to_section(addr) is not None:
                return True

            if 0x4347c000 <= addr < 0x4347c000 + 0x1000:
                return True

            return False

        for function in cfg.functions.values():
            for block in function.blocks:
                last_instr = None  # type:RefInstruction

                vex_block_noopt = cfg.project.factory.block(block.addr, opt_level=0, max_size=block.size).vex

                ins_addr = None
                tmps = {}

                for stmt in vex_block_noopt.statements:
                    if isinstance(stmt, pyvex.IRStmt.IMark):
                        ins_addr = stmt.addr + stmt.delta

                        # update ins_size of the previous RefInstruction object
                        if last_instr is not None and last_instr.ins_size is None:
                            last_instr.ins_size = ins_addr - last_instr.ins_addr
                            last_instr = None

                    elif isinstance(stmt, pyvex.IRStmt.WrTmp):
                        tmp = stmt.tmp
                        data = stmt.data
                        if isinstance(data, pyvex.IRExpr.Get):
                            # esp, ebp
                            # TODO: identify cases where ebp is not used as base pointer in a function
                            if data.offset in (sp_offset, bp_offset):
                                tmps[tmp] = [('reg', data.offset)]
                        elif isinstance(data, pyvex.IRExpr.Const):
                            # is it using an effective address?
                            value = data.con.value
                            if is_addr_valid(value):
                                # it is... or at least very likely
                                tmps[tmp] = [('const', value)]
                        elif isinstance(data, pyvex.IRExpr.RdTmp):
                            tmp_data = data.tmp
                            if tmp_data in tmps:
                                tmps[tmp] = tmps[tmp_data]
                        elif isinstance(data, pyvex.IRExpr.Binop):
                            args = data.args
                            source = [ ]
                            for arg in args:
                                if isinstance(arg, pyvex.IRExpr.RdTmp):
                                    arg_tmp = arg.tmp
                                    if arg_tmp in tmps:
                                        source.extend(tmps[arg_tmp])
                                elif isinstance(arg, pyvex.IRExpr.Const):
                                    value = arg.con.value
                                    if is_addr_valid(value):
                                        source.extend(('const', value))
                            if source:
                                tmps[tmp] = source
                    elif isinstance(stmt, pyvex.IRStmt.Put) and stmt.offset != ip_offset:
                        data = stmt.data
                        if isinstance(data, pyvex.IRExpr.RdTmp):
                            data_tmp = data.tmp
                            if data_tmp in tmps:
                                last_instr = RefInstruction(ins_addr, stmt.offset, tmps[data_tmp])
                                instrs.append(last_instr)
                        elif isinstance(data, pyvex.IRExpr.Const):
                            value = data.con.value
                            if is_addr_valid(value):
                                last_instr = RefInstruction(ins_addr, stmt.offset, [('const', value)])
                                instrs.append(last_instr)

                if last_instr is not None and last_instr.ins_size is None:
                    last_instr.ins_size = block.addr + vex_block_noopt.size - last_instr.ins_addr
                    last_instr = None

        # filtering
        instrs = [ i for i in instrs if i.addr_reg not in (ip_offset, sp_offset, bp_offset)
                   and i.addr_reg < 40  # this is x86 only - 40 is cc_op
                   ]

        return instrs

    def get_patches(self):
        return self._patches
