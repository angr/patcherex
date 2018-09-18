
import string
import random
import logging
from collections import defaultdict

import networkx

import pyvex
from angr.sim_variable import SimConstantVariable, SimRegisterVariable, SimMemoryVariable
from angr import KnowledgeBase
from ..backends import ReassemblerBackend
from ..errors import SimplePtrEncError

from ..technique import Technique
from ..patches import InsertCodePatch, PointerArrayPatch, AddEntryPointPatch, AddRWDataPatch

l = logging.getLogger('techniques.simple_ptr_enc')

# TODO: - detect if ebp is used as base pointer in a function or not
# TODO: - support more types of VEX statements and expressions
# TODO: - compress the pointer storage array
# TODO: - use random strings for label names ('begin', 'end', etc.)
# TODO: - more testing
# TODO: - bug fixes
# TODO: - do not re-encrypt for control-flow changing code, like jmps and calls


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
        self.addr_reg_overwritten = None
        self.skip = False
        self.decryption_addrs = None
        self.encryption_addrs = None

    def __repr__(self):
        return "<Deref %#08x %s@%s>" % (self.ins_addr, self.action, self.addr_regs)

    @property
    def should_reencrypt(self):
        if self.encryption_addrs is None:
            return True
        return len(self.encryption_addrs) > 0


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

        self._post_analysis()

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

        print("Unresolved AST", ast)
        import ipdb; ipdb.set_trace()

    def _ast_to_indir_memrefs(self, ast):
        """

        :param ast:
        :return:
        """

        if len(ast.args) == 2:
            if ast.args[0].op == 'reg' and ast.args[1].op == 'const':
                # reg +/- const
                # the original instruction might be 'push <addr>' when the const is 4
                reg_offset = ast.args[0].args[0]
                reg_name = self.cfg.project.arch.register_names[reg_offset]
                const = ast.args[1].args[0]
                op = ast.op
                return "dword ptr [{reg_name} {op} {delta}]".format(
                    reg_name=reg_name,
                    op=op,
                    delta=const,
                )

            else:
                import ipdb; ipdb.set_trace()

        elif len(ast.args) == 1:
            if ast.op == 'const':
                return 'dword ptr [%#x]' % ast.args[0]
            elif ast.op == 'reg':
                reg_offset = ast.args[0]
                return 'dword ptr [%s]' % (self.cfg.project.arch.register_names[reg_offset])
            else:
                print("Unresolved AST", ast)
                import ipdb; ipdb.set_trace()

    def _filter_instrs(self):
        raise NotImplementedError()

    def _post_analysis(self):
        raise NotImplementedError()

    def _analyze(self):

        for function in self.cfg.functions.values():  # type: angr.knowledge.Function
            for block in function.blocks:

                self.last_instr = None  # type: DerefInstruction

                vex_block_noopt = self.cfg.project.factory.block(block.addr, opt_level=0, size=block.size).vex

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
            self.last_instr = None

    def _handle_statement_WrTmp(self, stmt):
        tmp = stmt.tmp
        data = stmt.data

        data = self._handle_expression(data)

        if data is not None:
            self.tmps[tmp] = data

    def _handle_statement_Put(self, stmt):
        # loading data into a register
        if self.last_instr is not None and self.last_instr.addr_reg_overwritten is None and \
                self.last_instr.ins_addr == self.ins_addr and \
                len(self.last_instr.addr_regs) == 1 and \
                stmt.offset in self.last_instr.addr_regs:
            # the address register is overwritten in the same instruction
            self.last_instr.addr_reg_overwritten = True

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

    def _post_analysis(self):
        # do nothing
        pass

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

        # special case handling: writing data to esp
        if data is not None and stmt.offset is self.sp_offset:
            if isinstance(stmt.data, pyvex.IRExpr.RdTmp):
                tmp = stmt.data.tmp
                self.tmps[tmp] = MiniAST('reg', [ stmt.offset ])

    def _handle_statement_Store(self, stmt):

        data = self._handle_expression(stmt.data)
        addr = self._handle_expression(stmt.addr)

        if data is not None and addr is not None:
            # check whether data is a memory reference or not
            if data.op == 'const': # and not self._has_regs(addr, (self.sp_offset, self.bp_offset)):
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


class BaseNode(object):
    def __init__(self, ins_addr, end_addr, status=None):
        self.ins_addr = ins_addr
        self.end_addr = end_addr
        self.status = status


class MergePoint(BaseNode):
    def __init__(self, ins_addr, ins_size):
        super(MergePoint, self).__init__(ins_addr, ins_addr + ins_size, status=None)

    def __eq__(self, other):
        return isinstance(other, MergePoint) and other.ins_addr == self.ins_addr

    def __hash__(self):
        return hash(('MergePoint', self.ins_addr))

    def __repr__(self):
        return "<MergePoint @ %#x>" % (self.ins_addr)


class Source(BaseNode):
    def __init__(self, node, ins_size):
        super(Source, self).__init__(node.location.ins_addr, node.location.ins_addr + ins_size, status='encrypted')
        self.node = node

    def __repr__(self):
        s = "<Source @ %#x, %s>" % (self.ins_addr, self.status)
        return s


class Sink(BaseNode):
    def __init__(self, node, ins_size):
        super(Sink, self).__init__(node.location.ins_addr, node.location.ins_addr + ins_size, status='encrypted')
        self.node = node

    def __repr__(self):
        s = "<Sink @ %#x, %s>" % (self.ins_addr, self.status)
        return s


class Killer(BaseNode):
    def __init__(self, node, ins_size):
        super(Killer, self).__init__(node.location.ins_addr, node.location.ins_addr + ins_size, status=None)
        self.node = node


class Consumer(BaseNode):
    def __init__(self, node, ins_size):
        super(Consumer, self).__init__(node.location.ins_addr, node.location.ins_addr + ins_size, status='decrypted')
        self.node = node

    def __repr__(self):
        s = "<Consumer @ %#x, %s>" % (self.ins_addr, self.status)
        return s


class Transformer(BaseNode):
    def __init__(self, node, ins_size):
        super(Transformer, self).__init__(node.location.ins_addr, node.location.ins_addr + ins_size, status=None)
        self.node = node

    def __repr__(self):
        s = "<Transformer @ %#x, %s>" % (self.ins_addr, self.status)
        return s


class Cluster(BaseNode):
    def __init__(self, ins_addr, end_addr, nodes, status):
        super(Cluster, self).__init__(ins_addr, end_addr, status=status)
        self.nodes = nodes

    def __repr__(self):
        s = "<Cluster @ %#x, %s>" % (self.ins_addr, self.status)
        return s


class MemDerefDepGraph(object):
    """
    Represents a dependence graph between some registers holding encrypted/decrypted pointers.

    We define the pointer source, pointer consumer, and the pointer sink as follows:
    - A pointer source is the instruction that loads a pointer to a register from memory or an immediate
    - A pointer consumer is the instruction that dereferences the pointer
    - A pointer sink is the instruction that writes the pointer to another register, or writes the pointer into memory
      (to a stack variable or a heap variable)
    - A pointer transformer is the instruction that increments/decrements the pointer register, and its output is later
      used by a pointer consumer or a pointer sink. It does not matter what sort of operation is performed, since our
      encryption is homomorphic. The pointer at a transformer can be either encrypted or decrypted.

    A pointer is guaranteed to be encrypted coming out of the source. The encrypted pointer must be decrypted before
    reaching the pointer consumer, and re-encrypted before it reaches the pointer sink. Apparently the easiest
    solution is to decrypt the pointer right before the consumer, and re-encrypt the pointer immediately after the
    consumer. However, such a solution is suboptimal in many cases, most notably, a) when the pointer sink is empty,
    b) when there are more than one pointer consumers, and c) when there are more than one pointer sources.

    We layout all pointer sources, pointer consumers, and pointer sinks on a control flow graph. Optimal locations
    to decrypt and re-encrypt (only if a re-encryption is needed) a pointer is between pointer consumers and pointer
    sinks.
    """

    def __init__(self, function, consumers, ptr_reg, dep_graph):
        """
        Constructor.

        :param Function function: The function that the consumer locates.
        :param list consumers: All pointer consumers.
        :param int ptr_reg: Offset of the register that holds a pointer at the pointer consuming location.
        :param networkx.DiGraph dep_graph: Data dependence graph.
        """
        self._function = function
        self._consumers = consumers  # this is the initial set of consumers. we might expand this set since more
                                     # consumers that are using the same ptr_reg can be found during the optimization
                                     # procedure
        self._ptr_reg = ptr_reg
        self._dep_graph = dep_graph

        self._sources = None
        self._sinks = None
        self._transformers = None
        self._killers = None

        # find all sources, sinks, and transformers
        g = self._find_all()
        dec, enc = self._make_decision(g)

        self.decryption_addrs = dec
        self.encryption_addrs = enc

    @property
    def consumers(self):
        return self._consumers

    def _find_all(self):
        """
        Based on the consumer register, find all sources, sinks, and transformers in the data dependence graph, and
        then layout them on the function transition graph.

        :return: A transition graph of pointer sources, sinks, consumers, and transformers, where edges represent the
                control flow between those nodes.
        :rtype: networkx.DiGraph
        """

        sources = set()

        # find all sources, with transformers included
        for d in self._consumers:
            in_edges = self._dep_graph.in_edges(d, data=True)
            for s, _, data in in_edges:
                if 'type' in data and data['type'] == 'kill':
                    # skip killing edges
                    continue
                if isinstance(s.variable, SimRegisterVariable) and s.variable.reg == self._ptr_reg:
                    sources.add(s)

        transformers = set()
        # some of them are transformers
        # TODO: figure out transformer nodes that involve more than one register
        for s in sources:
            # if a register depends on itself, and writes to the very same register, then it's a transformer
            # e.g. inc esi  (esi depends on esi)
            #      add esi, eax  (esi depends on esi and eax, but it writes to itself anyways)
            in_edges = self._dep_graph.in_edges(s, data=True)
            preds = [ p for p, _, data in in_edges if 'type' not in data or data['type'] != 'kill' ]  # skip killing edges
            if any([ isinstance(v.variable, SimRegisterVariable) and v.variable.reg == self._ptr_reg for v in preds ]):
                transformers.add(s)
                continue

        if transformers:
            sources = sources - transformers

        # for each source and transformer, find all sinks and consumers
        sinks = set()
        consumers = set()
        killers = set()
        for s in sources | transformers:
            out_edges = self._dep_graph.out_edges(s, data=True)
            for _, suc, data in out_edges:
                if 'type' in data:
                    if data['type'] == 'mem_addr':
                        # this is a pointer consumer
                        consumers.add(suc)
                        continue
                    elif data['type'] == 'mem_data':
                        # this is a pointer sink
                        sinks.add(suc)
                        continue
                    elif data['type'] == 'kill':
                        killers.add(suc)
                        continue
                if isinstance(suc.variable, SimRegisterVariable):
                    if suc.variable.reg < 40:  # FIXME: this is ugly
                        if suc not in transformers:
                            # it's written to a register. sink
                            sinks.add(suc)
                    continue
                # unsupported. WTF...
                import ipdb; ipdb.set_trace()

        self._sources = sources
        self._sinks = sinks
        self._consumers = consumers
        self._transformers = transformers
        self._killers = killers

        # convert them into dicts with instruction addresses as their keys, so we can layout them on a function
        # transition graph
        sources = dict((s.location.ins_addr, Source(s, self._function.instruction_size(s.location.ins_addr)))
                       for s in sources)
        sinks = dict((s.location.ins_addr, Sink(s, self._function.instruction_size(s.location.ins_addr)))
                     for s in sinks)
        consumers = dict((s.location.ins_addr, Consumer(s, self._function.instruction_size(s.location.ins_addr)))
                         for s in consumers)
        transformers = dict((s.location.ins_addr, Transformer(s, self._function.instruction_size(s.location.ins_addr)))
                            for s in transformers)
        killers = dict((s.location.ins_addr, Killer(s, self._function.instruction_size(s.location.ins_addr)))
                       for s in killers)

        g = self._function.subgraph(set(sources.keys() + sinks.keys() + consumers.keys() + transformers.keys() +
                                        killers.keys()
                                        )
                                    )

        g_ = networkx.DiGraph()

        for src, dst in g.edges_iter():
            # TODO: create a single function that does the following crap
            src_ = sources.get(src, None)
            if src_ is None: src_ = sinks.get(src, None)
            if src_ is None: src_ = consumers.get(src, None)
            if src_ is None: src_ = transformers.get(src, None)
            if src_ is None: src_ = killers.get(src, None)
            if src_ is None: src_ = MergePoint(src, self._function.instruction_size(src))

            dst_ = sources.get(dst, None)
            if dst_ is None: dst_ = sinks.get(dst, None)
            if dst_ is None: dst_ = consumers.get(dst, None)
            if dst_ is None: dst_ = transformers.get(dst, None)
            if dst_ is None: dst_ = killers.get(dst, None)
            if dst_ is None: dst_ = MergePoint(dst, self._function.instruction_size(src))

            if not isinstance(src_, Killer) and not isinstance(dst_, Killer):
                g_.add_edge(src_, dst_)

        return g_

    def _make_decision(self, graph):
        """
        Calculate the place of performing pointer encryption and decryption. Loop in data dependencies are considered.

        An AnalysisFailureNotice exception is raised if for some reason we failed to confidently calculate the boundary,
        in which case, the patcher is supposed to decrypt the defer instruction before address register is used, and
        re-encrypt the address register immediately afterwards.

        :param networkx.DiGraph graph: A control flow graph of all pointer sources, sinks, consumers, and transformers
        :return: A 2-tuple like (list of decryption addresses, list of re-encryption addresses)
        :rtype: tuple
        """

        while graph.number_of_edges():
            nodes_merged = False
            # merge all nodes that can be merged
            for src, dst in graph.edges():
                if src.status == dst.status:
                    cluster = Cluster(src.ins_addr, dst.end_addr, (src, dst), src.status)
                    self._replace_nodes(graph, [ src, dst ], cluster)
                    nodes_merged = True
                    # we must restart immediately since we are working on an iterator...
                    break

            if nodes_merged:
                continue

            # nothing to be merged!
            # find strongly-connected components and cluster them
            # e.g.
            #    encrypted
            #       |
            #    unknown <----
            #       |        |
            #    decrypted ---
            #
            # can be transformed to
            #
            #    encrypted
            #       |
            #    decrypted <--
            #       |        |
            #    decrypted ---

            # calculate strongly connected components
            for nodes in networkx.strongly_connected_components(graph):
                all_status = set()
                for n in nodes:
                    all_status.add(n.status)

                if len(all_status) <= 2:
                    if None in all_status:
                        all_status.remove(None)
                    if not all_status:
                        continue
                    # mark all status to the same (encrypted/decrypted)
                    status = [ v for v in all_status if v is not None ][0]
                    for n in nodes:
                        n.status = status

            # phew, we finally reached here
            # we cannot do node-merging anymore - time to make a decision!
            break

        # iterate all edges, and insert a 'decryption switch' on edge E--D, and insert a 'encryption switch' on edge
        # D--E
        decryption_locations = set()
        encryption_locations = set()
        for src, dst in graph.edges():
            if src.status == 'encrypted' and dst.status == 'decrypted':
                decryption_locations.add(src.end_addr)
            elif src.status == 'decrypted' and dst.status == 'encrypted':
                encryption_locations.add(dst.ins_addr)

        return list(decryption_locations), list(encryption_locations)

    def _replace_nodes(self, graph, old_nodes, new_node):
        """
        Replace a bunch of existing nodes with a new one.

        :param networkx.DiGraph graph: The graph instnace.
        :param list old_nodes: A list of old nodes to be replaced.
        :param object new_node: The new node.
        :return: None
        """

        for n in old_nodes:
            preds = graph.predecessors(n)
            succs = graph.successors(n)

            for p in preds:
                if p not in old_nodes:
                    graph.add_edge(p, new_node)
            for s in succs:
                if s not in old_nodes:
                    graph.add_edge(new_node, s)

        graph.remove_nodes_from(old_nodes)


class MemoryDerefCollector(BlockTraverser):
    def __init__(self, cfg, optimize=False):
        self._optimize = optimize

        super(MemoryDerefCollector, self).__init__(cfg)

    def _filter_instrs(self):
        # filtering
        instrs = []
        for i in self.instrs:
            if not i.addr_regs or any(r for r in i.addr_regs if r in (self.sp_offset, self.bp_offset, self.ip_offset)):
                continue
            instrs.append(i)
        self.instrs = instrs

    def _post_analysis(self):
        # mark all instructions whose addr_regs are not used at all afterwards

        if not self._optimize:
            return

        for function in self.cfg.functions.values():
            dug = DefUseGraph(self.cfg.project, function)
            dependence_graph = dug.graph

            # create a mapping from instruction addresses to dependence nodes
            insn_addr_to_nodes = defaultdict(list)

            for n in dependence_graph.nodes_iter():
                insn_addr_to_nodes[n.location.ins_addr].append(n)

            function_insn_addrs = set()
            for b in function.blocks:
                function_insn_addrs |= set(b.instruction_addrs)

            all_covered_insns = set()

            for insn in iter(ins for ins in self.instrs if ins.ins_addr in function_insn_addrs):  # type: DerefInstruction

                if insn.ins_addr in all_covered_insns:
                    insn.skip = True
                    continue

                if insn.action == 'jump':
                    # we don't re-encrypt the target after a jump or a call
                    insn.decryption_addrs = [ insn.ins_addr ]
                    insn.encryption_addrs = [ ]
                    continue

                if insn.ins_addr in insn_addr_to_nodes:

                    all_nodes = insn_addr_to_nodes[insn.ins_addr]
                    # find source nodes for the source register - it might be a little tricky
                    # e.g. for instruction mov eax, dword ptr [ecx+12], we find the data node of ecx
                    addr_regs = insn.addr_regs
                    dests = [ ]
                    sources = set()
                    for n in all_nodes:
                        if not isinstance(n.variable, SimConstantVariable):
                            dests.append(n)

                    # dests hold all consumers

                    dep_graph = MemDerefDepGraph(function, dests, addr_regs[0], dependence_graph)

                    decryption_addrs = dep_graph.decryption_addrs
                    encryption_addrs = dep_graph.encryption_addrs

                    if not decryption_addrs:
                        # huh?
                        l.error('Optimization failed for %s. Fall back to default decryption-encryption strategy.', insn)
                        insn.decryption_addrs = [ insn.ins_addr ]
                        insn.encryption_addrs = [ insn.ins_addr + insn.ins_size ]
                        continue

                    consumers = dep_graph.consumers

                    covered_insn_addrs = set(i.location.ins_addr for i in consumers)

                    if insn.ins_addr in covered_insn_addrs:
                        covered_insn_addrs.remove(insn.ins_addr)

                    insn.encryption_addrs = encryption_addrs
                    if not encryption_addrs:
                        l.debug("%s is not used later. Don't re-encrypt it.", insn)

                    # note: those patches should be applied *before* the instruction
                    insn.decryption_addrs = decryption_addrs

                    if covered_insn_addrs:
                        # all future instructions are covered as well
                        all_covered_insns |= covered_insn_addrs
                        l.debug("%s covers %d other instructions", insn, len(covered_insn_addrs))

    #
    # statement/expression handlers
    #

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
            #if self.last_instr is not None and self.last_instr.reg_used_later is None and \
            #                expr.offset in self.last_instr.addr_regs:
            #    self.last_instr.reg_used_later = True

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


class DefUseGraph(object):
    def __init__(self, project, function):
        self.project = project
        self.function = function
        self.ddg = None

        self._analyze()

    def _analyze(self):

        # Generate a CFG of the current function with the base graph
        cfg = self.project.analyses.CFGAccurate(
            kb=KnowledgeBase(self.project, self.project.loader.main_object),
            starts=(self.function.addr,),
            keep_state=True,
            base_graph=self.function.graph,
            iropt_level=0,
        )

        self.ddg = self.project.analyses.DDG(cfg)

    @property
    def graph(self):
        return self.ddg.simplified_data_graph


class SimplePointerEncryption(Technique):
    def __init__(self, filename, backend, optimize=False):
        """
        Constructor.

        :param str filename: File name of the binary to protect.
        :param Backend backend: The patcher backend.
        :param bool optimize: Is optimization enabled or not.
        """

        super(SimplePointerEncryption, self).__init__(filename, backend)

        self._optimize = optimize
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
        mem_ref_instrs = self._memory_ref_instructions(cfg)
        mem_deref_instrs = self._memory_deref_instructions(cfg)

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
        begin_label = "".join(random.choice(string.ascii_lowercase) for _ in range(10))
        end_label = "".join(random.choice(string.ascii_lowercase) for _ in range(10))

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
            and edx, 0x0ffffff0
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

            ; encrypt ecx. ecx holds the address to flag page upon program starts.
            add ecx, dword ptr [_POINTER_KEY]
        """.format(
            begin_label=begin_label,
            end_label=end_label
        )
        patch = AddEntryPointPatch(asm_code=encrypt_pointers, after_restore=True, name="encrypt_all_pointers_entry")
        patches.append(patch)

        # make all data belong to ".data", so they are writable
        # TODO: keep the original alignment
        for data in self.backend._binary.data:
            data.section = None
            data.section_name = ".data"

        # insert an encryption patch after each memory referencing instruction
        mem_ref_patch_count = 0

        for ref in mem_ref_instrs:  # type: RefInstruction

            if ref.addr_reg is not None:
                dst_reg = arch.register_names[ref.addr_reg]
                asm_code = """
                add {dst_reg}, dword ptr [_POINTER_KEY]
                """.format(dst_reg=dst_reg)

            else:
                mem_dst_operand = ref.store_addr
                asm_code = """
                mov dword ptr [esp-4], esi
                mov esi, dword ptr [_POINTER_KEY]
                add {mem_dst}, esi
                mov esi, dword ptr [esp-4]
                """.format(mem_dst=mem_dst_operand)
            patch = InsertCodePatch(ref.ins_addr + ref.ins_size, asm_code, "encrypt_ref%#x" % ref.ins_addr)
            patches.append(patch)
            mem_ref_patch_count += 1

        # insert an decryption patch *and a re-encryption patch* before each memory dereferencing instruction
        mem_deref_decryption_patch_count = 0
        mem_deref_encryption_patch_count = 0

        for deref in mem_deref_instrs:  # type: DerefInstruction

            if deref.skip:
                continue

            # FIXME: if there are more than one registers, what sort of problems will we have?
            src_reg_offset = next(r for r in deref.addr_regs if r not in (arch.sp_offset, arch.bp_offset))
            src_reg = arch.register_names[src_reg_offset]

            # decryption patch
            asm_code = """
            sub {src_reg}, dword ptr [_POINTER_KEY]
            """.format(src_reg=src_reg)

            if deref.decryption_addrs is None:
                patch_addrs = [ deref.ins_addr ]
            else:
                patch_addrs = deref.decryption_addrs

            for patch_addr in patch_addrs:
                patch = InsertCodePatch(patch_addr, asm_code, "decrypt_ref%#x" % patch_addr)
                patches.append(patch)
                mem_deref_decryption_patch_count += 1

            # we do not apply the re-encryption patch if the source register is reused immediately
            # for example: movsx eax, byte ptr [eax]
            # apparently we don't decrypt eax since it's already overwritten

            if deref.action in ('load', 'store', 'to-sp') and not deref.addr_reg_overwritten and deref.should_reencrypt:

                # re-encryption patch
                asm_code = """
                pushfd
                add {src_reg}, dword ptr [_POINTER_KEY]
                popfd
                """.format(src_reg=src_reg)

                #if deref.reg_used_later is None:
                #    # decrypt immediately after using it
                #    decryption_addr = deref.ins_addr + deref.ins_size
                #else:
                #    decryption_addr = deref.latest_decryption_addr
                if deref.encryption_addrs is None:
                    patch_addrs = [ deref.ins_addr + deref.ins_size ]
                else:
                    patch_addrs = deref.encryption_addrs
                for encryption_addr in patch_addrs:
                    patch = InsertCodePatch(encryption_addr, asm_code, "re-ecnryption%#x" % encryption_addr)
                    patches.append(patch)

                    mem_deref_encryption_patch_count += 1

        # for syscalls, make sure all pointers are decrypted before calling
        syscalls = {
            'transmit': ([1, 3], [ ]),
            'receive': ([1, 3], [ ]),
            'allocate': ([2], [2]),
            'deallocate': ([1], [ ]),
            'fdwait': ([1, 2, 3, 4], [ ]),
            'random': ([0, 2], [ ]),
        }
        for syscall_name, (argument_indices_in, argument_indices_out) in syscalls.items():
            syscall_patches = self._generate_syscall_patches(cfg, syscall_name, argument_indices_in,
                                                             argument_indices_out
                                                             )
            patches.extend(syscall_patches)

        l.debug("Generated %d mem-ref patches, %d mem-deref decryption patches, and %d mem-deref encryption patches.",
                mem_ref_patch_count,
                mem_deref_decryption_patch_count,
                mem_deref_encryption_patch_count
                )

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
        if syscall is None:
            return patches

        predecessors = cfg.get_any_node(syscall.addr).predecessors
        for pred in predecessors:
            # it must ends with int 80h
            last_instr_addr = pred.instruction_addrs[-1]
            last_instr = cfg.project.factory.block(last_instr_addr, num_inst=1)
            if last_instr.capstone.insns[0].mnemonic != 'int':
                raise SimplePtrEncError("unsupported syscall callers at %#08x", pred.addr)

            for index in argument_indices_in:
                reg = SYSCALL_ARGUMENTS[index]
                lbl_name = "".join([random.choice(string.ascii_lowercase) for _ in range(10)])

                asm = """
                    cmp {reg}, 0
                    je .{lbl}
                    sub {reg}, [_POINTER_KEY]
                .{lbl}:
                """.format(reg=reg, lbl=lbl_name)
                patch = InsertCodePatch(last_instr_addr, asm, "syscall_decrypt_%#x" % last_instr_addr)
                patches.append(patch)

            for index in argument_indices_out:
                reg = SYSCALL_ARGUMENTS[index]
                lbl_name = "".join([random.choice(string.ascii_lowercase) for _ in range(10)])
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

                patch = InsertCodePatch(last_instr_addr + 2, asm, "syscall_encrypt_%#x" % last_instr_addr)  # len(int 80h) == 2
                patches.append(patch)

            if syscall_name == 'transmit':
                # Address of the flag page 0x4347c000 is encrypted. In rare cases where the flag page number is used as
                # constants and sent to users, we would like to find it out before transmission and decrypt it.
                # TODO: make it more flexible
                asm = """
                    push edx
                    push ecx
                    push eax
                    jmp foss_begin

                foss_loop:
                    mov eax, dword ptr [ecx]
                    sub eax, [_POINTER_KEY]
                    cmp eax, 0x4347d000
                    ja foss_next
                    cmp eax, 0x4347c000
                    jb foss_next
                    mov dword ptr [ecx], eax

                foss_next:
                    inc ecx
                    dec edx

                foss_begin:
                    cmp edx, 4
                    jl foss_done
                    jmp foss_loop

                foss_done:
                    pop eax
                    pop ecx
                    pop edx
                """
                patch = InsertCodePatch(last_instr_addr, asm)
                patches.append(patch)

        return patches

    def _memory_deref_instructions(self, cfg):
        """
        Iterate through all basic blocks in the CFG, and find all instructions that load data from memory

        :param angr.analyses.CFG cfg: The control flow graph.
        :return: A list of DerefInstruction objects.
        :rtype: list
        """

        collector = MemoryDerefCollector(cfg, optimize=self._optimize)

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

        for addr, data in memory_data.items():
            if data.sort == "pointer-array":
                for i in range(0, data.size, cfg.project.arch.bits / 8):
                    ptr_addr = addr + i
                    pointer_addrs.append(ptr_addr)

        return pointer_addrs

    def get_patches(self):
        return self._patches
