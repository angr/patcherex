
import string
import random
import logging

import pyvex
from ..backends import ReassemblerBackend

from ..technique import Technique
from ..patches import InsertCodePatch, PointerArrayPatch, AddEntryPointPatch, AddRWDataPatch

l = logging.getLogger('techniques.simple_ptr_enc')

# TODO: - detect if ebp is used as base pointer in a function or not
# TODO: - support more types of VEX statements and expressions
# TODO: - use a dynamic key
# TODO: - compress the pointer storage array
# TODO: - use random strings for label names ('begin', 'end', etc.)
# TODO: - raise proper exceptions
# TODO: - more testing
# TODO: - bug fixes


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
    def __init__(self, ins_addr, addr_reg, sources, store_addr=None):
        self.ins_addr = ins_addr
        self.ins_size = None
        self.addr_reg = addr_reg
        self.sources = sources
        self.store_addr = store_addr

    def __repr__(self):
        if self.addr_reg is not None:
            return "<Ref %#08x %s: %s>" % (self.ins_addr, self.addr_reg, self.sources)
        else:
            return "<Ref %#08x %s: %s>" % (self.ins_addr, self.store_addr, self.sources)


class BlockTraverser(object):

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

    def __init__(self, cfg):
        self.cfg = cfg

        self._addr_belongs_to_section = self.cfg._addr_belongs_to_section

        # global temporary variables
        self._last_instr = None
        self.ins_addr = None
        self.instrs = [ ]

        self.ip_offset = self.cfg.project.arch.ip_offset
        self.sp_offset = self.cfg.project.arch.sp_offset
        self.bp_offset = self.cfg.project.arch.bp_offset

        self.tmps = {}
        self.regs = {}

        # begin traversal!
        self._analyze()

    def _is_addr_valid(self, addr):
        if self._addr_belongs_to_section(addr) is not None:
            return True

        if 0x4347c000 <= addr < 0x4347c000 + 0x1000:
            return True

        return False

    def _ast_to_addr_regs(self, ast):
        """
        Pick registers that holds a valid address and return them.

        :param MiniAST ast: The AST
        :return: A list of register offsets.
        :rtype: list
        """

        # we only care about where the base comes from
        # - if there is only one register, then it must be the base
        # - if there are a register and a const, the register is the base if and only if the const
        #   is not a valid address. Otherwise the constant is the base
        # - if there are two constants, it's gonna be a little complicated... TODO

        is_addr_valid = self._is_addr_valid

        if len(ast.args) == 2:
            # binary operations
            if ast.op == '+':
                if ast.args[1].op == 'const':
                    # something + constant
                    if is_addr_valid(ast.args[1].args[0]):
                        # base address + some offset
                        return []
                    else:
                        if ast.args[0].op == 'reg':
                            # this register must be the base address
                            return [ast.args[0].args[0]]
                        elif ast.args[0].op == 'const' and is_addr_valid(ast.args[0].args[0]):
                            # the constant is the base address
                            return []
                        else:
                            return self._ast_to_addr_regs(ast.args[0])

                elif ast.args[1].op in ('<<',):
                    # arg1 must be used as an offset or index
                    # arg0 is the base address
                    if ast.args[0].op == 'reg':
                        return [ast.args[0].args[0]]
                    elif ast.args[0].op == 'const':
                        return []
                elif ast.args[0].op == 'reg':
                    # let's see if we can extract a base address from other arguments
                    regs = self._ast_to_addr_regs(ast.args[1])
                    if not regs:
                        # nice! the first argument must be the base register
                        return ast.args[0].args[0]

            elif ast.op == '-':
                if ast.args[0].op == 'reg':
                    return [ast.args[0].args[0]]
                elif ast.args[0].op == 'const':
                    return []

        elif len(ast.args) == 1:
            if ast.op == 'reg':
                # directly using the register as the address
                return ast.args
            elif ast.op == 'const':
                # using a constant as the address
                return []

        print "Unresolved AST", ast
        import ipdb; ipdb.set_trace()

    def _ast_to_indir_memrefs(self, ast):
        """

        :param ast:
        :return:
        """

        if len(ast.args) == 2:
            import ipdb; ipdb.set_trace()

        elif len(ast.args) == 1:
            if ast.op == 'const':
                return 'dword ptr [%#x]' % ast.args[0]
            elif ast.op == 'reg':
                reg_offset = ast.args[0]
                return 'dword ptr [%s]' % (self.cfg.project.arch.register_names[reg_offset])
            else:
                print "Unresolved AST", ast
                import ipdb; ipdb.set_trace()

    def _filter_instrs(self):
        raise NotImplementedError()

    def _analyze(self):

        for function in self.cfg.functions.values():  # type: angr.knowledge.Function
            for block in function.blocks:

                self.last_instr = None  # type: DerefInstruction

                vex_block_noopt = self.cfg.project.factory.block(block.addr, opt_level=0, max_size=block.size).vex

                self.ins_addr = None
                self.tmps = {}
                self.regs = {}

                for stmt in vex_block_noopt.statements:

                    handler = getattr(self, '_handle_statement_%s' % (stmt.__class__.__name__), None)

                    if handler is not None:
                        handler(stmt)

                if self.last_instr is not None and self.last_instr.ins_size is None:
                    self.last_instr.ins_size = block.addr + vex_block_noopt.size - self.last_instr.ins_addr
                    self.last_instr = None

                self._handle_next(vex_block_noopt.next)

                if self.last_instr is not None and self.last_instr.ins_size is None:
                    self.last_instr.ins_size = block.addr + vex_block_noopt.size - self.last_instr.ins_addr
                    self.last_instr = None

        self._filter_instrs()

    def _handle_next(self, next_expr):
        pass

    def _handle_statement_IMark(self, stmt):
        self.ins_addr = stmt.addr + stmt.delta
        # update the instruction size of the previous DerefInstruction object
        if self.last_instr is not None and self.last_instr.ins_size is None:
            self.last_instr.ins_size = self.ins_addr - self.last_instr.ins_addr

    def _handle_statement_WrTmp(self, stmt):
        tmp = stmt.tmp
        data = stmt.data

        data = self._handle_expression(data)

        if data is not None:
            self.tmps[tmp] = data

    def _handle_statement_Put(self, stmt):
        # loading data into a register
        if self.last_instr is not None and self.last_instr.addr_regs_used is None and \
                        len(self.last_instr.addr_regs) == 1 and \
                        stmt.offset in self.last_instr.addr_regs:
            self.last_instr.addr_regs_used = False

        data = self._handle_expression(stmt.data)
        if data is not None:
            self.regs[stmt.offset] = data

        return data

    def _handle_expression(self, expr, allow_override=True):

        if allow_override:
            expr_handler = getattr(self.__class__, '_handle_expression_%s' % (expr.__class__.__name__), None)
        else:
            expr_handler = getattr(BlockTraverser, '_handle_expression_%s' % (expr.__class__.__name__), None)


        if expr_handler is not None:
            return expr_handler(self, expr)
        else:
            return None

    def _handle_expression_Get(self, expr):
        # read from register
        if expr.offset not in (self.ip_offset, self.bp_offset, self.sp_offset):
            return MiniAST('reg', [ expr.offset ])

    def _handle_expression_Binop(self, expr):
        # some sort of arithmetic operations
        if expr.op.startswith('Iop_Cmp') or \
                expr.op.startswith('Iop_Div') or \
                expr.op.startswith('Iop_Or') or \
                expr.op.startswith('Iop_Xor') or \
                expr.op in ('Iop_32HLto64',):
            # ignore them.
            return None
        elif expr.op in self.OPSTR_TO_OP:
            op = self.OPSTR_TO_OP[expr.op]
        else:
            op = expr.op

        args = []
        for arg in expr.args:
            arg_data = self._handle_expression(arg, False)
            if arg_data is None:
                return None
            args.append(arg_data)

        return MiniAST(op, args)

    def _handle_expression_RdTmp(self, expr):
        data_tmp = expr.tmp
        if data_tmp in self.tmps:
            return self.tmps[data_tmp]

    def _handle_expression_Const(self, expr):
        value = expr.con.value
        return MiniAST('const', [ value ])


class MemoryRefCollector(BlockTraverser):
    def __init__(self, cfg):
        super(MemoryRefCollector, self).__init__(cfg)

    def _has_regs(self, ast, reg_offsets):

        if not isinstance(ast, MiniAST):
            return False
        if ast.op == 'reg' and ast.args[0] in reg_offsets:
            return True
        for arg in ast.args:
            if self._has_regs(arg, reg_offsets):
                return True
        return False

    def _filter_instrs(self):

        # filtering
        self.instrs = [i for i in self.instrs if i.addr_reg not in (self.ip_offset, self.sp_offset, self.bp_offset)
                       and i.addr_reg < 40  # this is x86 only - 40 is cc_op
                       ]

    def _handle_statement_Put(self, stmt):
        data = self._handle_expression(stmt.data)

        if data is not None and stmt.offset != self.ip_offset:
            # check whether data is a memory reference or not
            if data.op == 'const' or \
                    (self._has_regs(data, (self.sp_offset, self.bp_offset)) and
                         (stmt.offset not in (self.sp_offset, self.bp_offset))
                     ):
                self.last_instr = RefInstruction(self.ins_addr, stmt.offset, data)
                self.instrs.append(self.last_instr)

    def _handle_statement_Store(self, stmt):

        data = self._handle_expression(stmt.data)
        addr = self._handle_expression(stmt.addr)

        if data is not None and addr is not None:
            # check whether data is a memory reference or not
            if data.op == 'const' and not self._has_regs(addr, (self.sp_offset, self.bp_offset)):
                self.last_instr = RefInstruction(self.ins_addr, None, data, store_addr=self._ast_to_indir_memrefs(addr))
                self.instrs.append(self.last_instr)

    def _handle_expression_Get(self, expr):
        # read from register
        if expr.offset != self.ip_offset:
            return MiniAST('reg', [ expr.offset ])

    def _handle_expression_Const(self, expr):
        value = expr.con.value
        # is it using an effective address?
        if self._is_addr_valid(value):
            # it is... or at least very likely
            return MiniAST('const', [value])
        else:
            return None

class MemoryDerefCollector(BlockTraverser):
    def __init__(self, cfg):
        super(MemoryDerefCollector, self).__init__(cfg)

    def _filter_instrs(self):
        # filtering
        instrs = []
        for i in self.instrs:
            if not i.addr_regs or any(r for r in i.addr_regs if r in (self.sp_offset, self.bp_offset, self.ip_offset)):
                continue
            instrs.append(i)
        self.instrs = instrs

    def _handle_statement_Store(self, stmt):
        # writing some stuff into memory
        addr = self._handle_expression(stmt.addr)

        if addr is not None:
            self.last_instr = DerefInstruction(self.ins_addr, 'store',
                                               self._ast_to_addr_regs(addr)
                                               )
            self.instrs.append(self.last_instr)

    def _handle_statement_Put(self, stmt):
        data = super(MemoryDerefCollector, self)._handle_statement_Put(stmt)

        if stmt.offset in (self.sp_offset, self.bp_offset) and data is not None:
            self.last_instr = DerefInstruction(self.ins_addr, 'to-sp',
                                               self._ast_to_addr_regs(data)
                                               )
            self.instrs.append(self.last_instr)

    def _handle_next(self, next_expr):
        data = self._handle_expression(next_expr)

        if data is not None:
            self.last_instr = DerefInstruction(self.ins_addr, 'jump',
                                               self._ast_to_addr_regs(data)
                                               )
            self.instrs.append(self.last_instr)

    def _handle_expression_Get(self, expr):
        if expr.offset == self.ip_offset and expr.offset in self.regs:
            return self.regs[expr.offset]
        else:
            if self.last_instr is not None and self.last_instr.addr_regs_used is None and \
                            expr.offset in self.last_instr.addr_regs:
                self.last_instr.addr_regs_used = True

            return MiniAST('reg', [expr.offset])

    def _handle_expression_Load(self, expr):
        # loading from memory!
        addr = expr.addr
        if isinstance(addr, pyvex.IRExpr.RdTmp):
            tmp_addr = addr.tmp
            if tmp_addr in self.tmps:
                self.last_instr = DerefInstruction(self.ins_addr, 'load',
                                              self._ast_to_addr_regs(self.tmps[tmp_addr])
                                              )
                self.instrs.append(self.last_instr)

    def _handle_expression_Const(self, expr):
        value = expr.con.value
        if self._is_addr_valid(value):
            return MiniAST('const', [value])


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

        pointers = self._constant_pointers(cfg)
        mem_deref_instrs = self._memory_deref_instructions(cfg)
        mem_ref_instrs = self._memory_ref_instructions(cfg)

        if debug:
            l.debug("dereferences")

            # print them out
            for deref in mem_deref_instrs:  # type: DerefInstruction
                l.debug("%s %s", deref, cfg.project.factory.block(deref.ins_addr, num_inst=1).capstone)

            l.debug("references")

            for ref in mem_ref_instrs:  # type: RefInstruction
                l.debug("%s %s", ref, cfg.project.factory.block(ref.ins_addr, num_inst=1).capstone)

        arch = cfg.project.arch

        # add a list of pointers to the binary
        patch = PointerArrayPatch(None, pointers + [ 0 ], name='all_pointers')
        patches.append(patch)

        # add the encryption key into data section
        patch = AddRWDataPatch(4, '_POINTER_KEY')
        patches.append(patch)

        # insert the pointer encryption code at the entry point
        begin_label = "".join(random.choice(string.lowercase) for _ in xrange(10))
        end_label = "".join(random.choice(string.lowercase) for _ in xrange(10))

        encrypt_pointers = """
            push eax
            push ebx
            push ecx
            push edx

            ; random
            sub esp, 4
            mov eax, 7
            mov ebx, esp
            mov ecx, 4
            xor edx, edx
            int 80h

            ; generate offset
            pop edx
            mov dword ptr [_POINTER_KEY], edx

            ; encrypt all static pointers
            xor eax, eax

        {begin_label}:
            mov ebx, dword ptr [all_pointers + eax]
            cmp ebx, 0
            je {end_label}
            mov ecx, dword ptr [ebx]
            add ecx, edx ; edx holds the encryption key
            mov dword ptr [ebx], ecx
            add eax, 4
            jmp {begin_label}

        {end_label}:
            pop edx
            pop ecx
            pop ebx
            pop eax
        """.format(
            begin_label=begin_label,
            end_label=end_label
        )
        patch = AddEntryPointPatch(asm_code=encrypt_pointers)
        patches.append(patch)

        # make all pointer-array data belong to ".data"
        for data in self.backend._binary.data:
            if data.sort == "pointer-array":
                data.section_name = ".data"

        # insert an encryption patch after each memory referencing instruction

        for ref in mem_ref_instrs:  # type: RefInstruction

            if ref.addr_reg is not None:
                dst_reg = arch.register_names[ref.addr_reg]
                asm_code = """
                add {dst_reg}, dword ptr [_POINTER_KEY]
                """.format(dst_reg=dst_reg)

            else:
                mem_dst_operand = ref.store_addr
                asm_code = """
                push esi
                mov esi, dword ptr [_POINTER_KEY]
                add {mem_dst}, esi
                pop esi
                """.format(mem_dst=mem_dst_operand)

            patch = InsertCodePatch(ref.ins_addr + ref.ins_size, asm_code)

            patches.append(patch)

        # insert an decryption patch *and a re-encryption patch* before each memory dereferencing instruction

        for deref in mem_deref_instrs:  # type: DerefInstruction

            # FIXME: if there are more than one registers, what sort of problems will we have?
            src_reg_offset = next(r for r in deref.addr_regs if r not in (arch.sp_offset, arch.bp_offset))
            src_reg = arch.register_names[src_reg_offset]

            # decryption patch
            asm_code = """
            sub {src_reg}, dword ptr [_POINTER_KEY]
            """.format(src_reg=src_reg)
            patch = InsertCodePatch(deref.ins_addr, asm_code)

            patches.append(patch)

            # we do not apply the re-encryption patch if the source register is reused immediately
            # for example: movsx eax, byte ptr [eax]
            # apparently we don't decrypt eax since it's already overwritten

            if deref.action in ('load', 'store', 'to-sp') and deref.addr_regs_used is not False:
                # re-encryption patch
                asm_code = """
                pushfd
                add {src_reg}, dword ptr [_POINTER_KEY]
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
                    sub {reg}, [_POINTER_KEY]
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
                    add eax, [_POINTER_KEY]
                    mov dword ptr [{reg}], eax
                    pop eax
                .{lbl}:
                """.format(reg=reg, lbl=lbl_name)

                patch = InsertCodePatch(last_instr_addr + 2, asm)  # len(int 80h) == 2
                patches.append(patch)

        return patches

    def _memory_deref_instructions(self, cfg):
        """
        Iterate through all basic blocks in the CFG, and find all instructions that load data from memory

        :param angr.analyses.CFG cfg: The control flow graph.
        :return: A list of DerefInstruction objects.
        :rtype: list
        """

        collector = MemoryDerefCollector(cfg)

        return collector.instrs

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

        collector = MemoryRefCollector(cfg)

        return collector.instrs

    def _constant_pointers(self, cfg):
        """
        Find all pointers that are in non-executable sections.

        :param angr.analyses.CFG cfg: The control flow graph.
        :return: A list of addresses of pointers.
        :rtype: list
        """

        pointer_addrs = [ ]

        memory_data = cfg.memory_data

        for addr, data in memory_data.iteritems():
            if data.sort == "pointer-array":
                for i in xrange(0, data.size, cfg.project.arch.bits / 8):
                    ptr_addr = addr + i
                    pointer_addrs.append(ptr_addr)

        return pointer_addrs

    def get_patches(self):
        return self._patches
