
import os
from collections import defaultdict
import logging
import tempfile

import angr
from angr import KnowledgeBase

from ..backends import ReassemblerBackend
from ..patches import RemoveInstructionPatch, InsertCodePatch
from ..technique import Technique
from ..errors import BinaryOptimizationError, BinaryOptimizationNotImplementedError

l = logging.getLogger('techniques.binary_optimization')


class BinaryOptimization(Technique):
    def __init__(self, filename, backend, techniques=None):
        super(BinaryOptimization, self).__init__(filename, backend)

        self._techniques = techniques

        # counters
        self.constant_propagations = 0
        self.redundant_stack_variable_removals = 0
        self.register_reallocations = 0
        self.dead_assignment_eliminations = 0

        self._patches = self._generate_patches()

        l.debug('Constant propagation occurred %d times', self.constant_propagations)
        l.debug('Redundant stack variable removal occurred %d times', self.redundant_stack_variable_removals)
        l.debug('Register reallocation replaced %d stack variables', self.register_reallocations)
        l.debug('Eliminated %d dead assignments.', self.dead_assignment_eliminations)

    def _generate_patches(self):
        """

        :return:
        """

        patches = [ ]

        cfg = self.backend.cfg
        bo = self.backend.project.analyses.BinaryOptimizer(cfg, self._techniques)

        patches.extend(self._patches_constant_propagation(bo))
        patches.extend(self._patches_redundant_stack_variables_removal(bo))
        patches.extend(self._patches_register_reallocation(bo))
        patches.extend(self._patches_dead_assignment_elimination(bo))

        return patches

    def _patches_constant_propagation(self, bo):
        """
        Generate patches out of constant propagation optimization.

        :param bo: The binary optimization analysis.
        :return: A list of patches.
        :rtype: list
        """

        patches = [ ]

        for cp in bo.constant_propagations:  # type: angr.analyses.binary_optimizer.ConstantPropagation
            # remove the assignment site
            patch = RemoveInstructionPatch(cp.constant_assignment_loc.ins_addr, None)
            patches.append(patch)

            # then remove the consuming site
            patch = RemoveInstructionPatch(cp.constant_consuming_loc.ins_addr, None)
            patches.append(patch)

            # Insert a new instruction there
            ins_addr = cp.constant_consuming_loc.ins_addr
            old_consumer = self.backend.project.factory.block(ins_addr, num_inst=1)

            insns = old_consumer.capstone.insns
            if not insns:
                # capstone cannot disassemble it somehow
                l.error('Capstone fails to disassemble instruction at %#x.', ins_addr)
                continue

            insn = old_consumer.capstone.insns[0]
            operands = insn.op_str.split(",")
            operands[1] = cp.constant

            # here is the tricky part: the constant might be an address
            # if it's an address, we need to convert it to a label
            if isinstance(self.backend, ReassemblerBackend):
                symbol_manager = self.backend._binary.symbol_manager  # type: angr.analyses.reassembler.SymbolManager
                if cp.constant in symbol_manager.addr_to_label:
                    # it's a label... use its label name
                    operands[1] = "{" + symbol_manager.addr_to_label[cp.constant][0].name + "}"

                # also we have to process operands[0]...
                op_0 = angr.analyses.reassembler.Operand(self.backend._binary, ins_addr, insn.size, insn.operands[0],
                                                operands[0], insn.mnemonic, syntax='intel'
                                                )
                operands[0] = op_0.assembly(insn)


            if isinstance(operands[1], (int, long)):
                new_op_str = "%s, %#x" % (operands[0], operands[1])
            else:
                new_op_str = "%s, %s" % (operands[0], operands[1])

            new_consumer_asm = "%s\t%s" % (old_consumer.capstone.insns[0].mnemonic, new_op_str)

            patch = InsertCodePatch(cp.constant_consuming_loc.ins_addr, new_consumer_asm)
            patches.append(patch)

            self.constant_propagations += 1

        return patches

    def _patches_redundant_stack_variables_removal(self, bo):
        """
        Generate patches out of redundant stack variables removal.

        :param bo: The binary optimization analysis.
        :return: A list of patches.
        :rtype: list
        """

        patches = [ ]

        for rsv in bo.redundant_stack_variables:  # type: angr.analyses.binary_optimizer.RedundantStackVariable

            if not rsv.argument_register_as_retval:
                # remove the reading-to-register instruction
                patch = RemoveInstructionPatch(rsv.argument.location.ins_addr, None)
                patches.append(patch)

            # remove the copying instruction
            patch = RemoveInstructionPatch(rsv.stack_variable.location.ins_addr, None)
            patches.append(patch)

            self.redundant_stack_variable_removals += 1

            if len(rsv.stack_variable_consuming_locs) == 0:
                l.info('We cannot find consumers for %s. It will be totally removed for good.', rsv)
                continue

            if rsv.argument.variable.size == 4:
                argument_asm = "dword ptr "
            elif rsv.argument.variable.size == 2:
                argument_asm = 'word ptr '
            elif rsv.argument.variable.size == 1:
                argument_asm = 'byte ptr '
            else:
                l.error('Unsupported argument size %s', rsv.argument.variable.size)
                continue

            argument_offset = " + %#x" % rsv.argument.variable.offset if rsv.argument.variable.offset > 0 else \
                              " - %#x" % abs(rsv.argument.variable.offset)

            if rsv.argument.variable.base == 'bp':
                argument_asm += '[ebp%s]' % argument_offset
            elif rsv.argument.variable.base == 'sp':
                argument_asm += '[esp%s]' % argument_offset
            else:
                l.error('Unsupported argument base %s', rsv.argument.variable.base)
                continue

            # for each instruction that uses the copied instruction, replace it with a reference to the original argument
            replaced_insn_addrs = set()
            for loc in rsv.stack_variable_consuming_locs:  # type: angr.analyses.code_location.CodeLocation

                if loc.ins_addr in replaced_insn_addrs:
                    continue

                replaced_insn_addrs.add(loc.ins_addr)

                # remove the consuming instruction
                patch = RemoveInstructionPatch(loc.ins_addr, None)
                patches.append(patch)

                # replace the old instruction

                old_consumer = self.backend.project.factory.block(loc.ins_addr, num_inst=1)

                operands = old_consumer.capstone.insns[0].op_str.split(",")
                if 'ptr' in operands[0]:
                    operands[0] = argument_asm
                elif len(operands) > 1 and 'ptr' in operands[1]:
                    operands[1] = argument_asm
                elif len(operands) > 2 and 'ptr' in operands[2]:
                    operands[2] = argument_asm
                else:
                    raise BinaryOptimizationError('Unexpected operand string in instruction %s.' %
                                                  str(old_consumer.capstone.insns[0])
                                                  )

                new_op_str = ", ".join(operands)

                new_consumer_asm = "%s\t%s" % (old_consumer.capstone.insns[0].mnemonic, new_op_str)

                patch = InsertCodePatch(loc.ins_addr, new_consumer_asm)
                patches.append(patch)

        return patches

    def _patches_register_reallocation(self, bo):
        """
        Generate patches out of register reallocation.

        :param bo: The binary optimization analysis.
        :return: A list of patches.
        :rtype: list
        """

        patches = [ ]

        prologue_saves = defaultdict(list)
        epilogue_restores = defaultdict(list)

        for rr in bo.register_reallocations:  # type: angr.analyses.binary_optimizer.RegisterReallocation
            try:
                patches_ = [ ]
                # which register to replace?
                reg_name = self.backend.project.arch.register_names[rr.register_variable.reg]

                # what instructions to replace?
                # sources first
                replaced_source_insn_addrs = set()
                for src in rr.stack_variable_sources:

                    if src.location.ins_addr in replaced_source_insn_addrs:
                        continue
                    replaced_source_insn_addrs.add(src.location.ins_addr)

                    insn = self.backend.project.factory.block(src.location.ins_addr, num_inst=1).capstone.insns[0]
                    operands = insn.op_str.split(',')
                    if not len(operands) == 2:
                        l.warning('Unsupported instruction %s. Skip.', str(insn))
                        raise BinaryOptimizationNotImplementedError()

                    # replace the dest
                    new_insn = "%s\t%s, %s" % (insn.mnemonic, reg_name, operands[1])

                    # patch: remove the old instruction
                    p0 = RemoveInstructionPatch(insn.address, None)
                    patches_.append(p0)

                    # patch: add the new instruction
                    p1 = InsertCodePatch(insn.address, new_insn)
                    patches_.append(p1)

                # consumers
                replaced_consumer_insn_addrs = set()
                for dst in rr.stack_variable_consumers:

                    if dst.location.ins_addr in replaced_consumer_insn_addrs:
                        continue
                    replaced_consumer_insn_addrs.add(dst.location.ins_addr)

                    insn = self.backend.project.factory.block(dst.location.ins_addr, num_inst=1).capstone.insns[0]
                    if len(insn.operands) == 1:
                        operand = insn.op_str
                        if 'ptr' in operand:
                            operand = reg_name
                        else:
                            raise BinaryOptimizationNotImplementedError('Unexpected operand found in instruction %s.'
                                                                        'Please bug Fish hard.' % insn)

                        new_insn = "%s\t%s" % (insn.mnemonic, operand)

                    elif len(insn.operands) == 2:
                        operands = insn.op_str.split(',')
                        if 'ptr' in operands[0]:
                            operands[0] = reg_name
                        elif 'ptr' in operands[1]:
                            operands[1] = reg_name
                        else:
                            raise BinaryOptimizationNotImplementedError('Unexpected operands found in instruction %s. '
                                                                        'Please bug Fish hard.' % insn)

                        new_insn = "%s\t%s, %s" % (insn.mnemonic, operands[0], operands[1])

                    elif len(insn.operands) == 3:
                        operands = insn.op_str.split(',')
                        if 'ptr' in operands[0]:
                            operands[0] = reg_name
                        elif 'ptr' in operands[1]:
                            operands[1] = reg_name
                        elif 'ptr' in operands[2]:
                            operands[2] = reg_name
                        else:
                            raise BinaryOptimizationNotImplementedError('Unexpected operands found in instruction %s. '
                                                                        'Please bug Fish hard.' % insn)

                        new_insn = "%s\t%s, %s, %s" % (insn.mnemonic, operands[0], operands[1], operands[2])

                    else:
                        # TODO:
                        raise BinaryOptimizationNotImplementedError()

                    # patch: remove the old instruction
                    p0 = RemoveInstructionPatch(insn.address, None)
                    patches_.append(p0)

                    # patch: add the new instruction
                    p1 = InsertCodePatch(insn.address, new_insn)
                    patches_.append(p1)

                # an instruction address cannot be both a source and a consumer
                if replaced_source_insn_addrs.intersection(replaced_consumer_insn_addrs):
                    l.warning('Unexpected error: %s has at least one instruction being both a producer and a consumer.'
                              'Please bug Fish really hard so that he\'ll fix it.',
                              rr
                              )
                    # don't patch it
                    continue

                patches.extend(patches_)

                # save the register after function prologue
                # prologue_saves[rr.prologue_addr + rr.prologue_size].append('push\t%s' % reg_name)
                prologue_saves[rr.prologue_addr + rr.prologue_size].append(
                    'mov\tdword ptr [ebp-%d], %s' % (abs(rr.stack_variable.offset), reg_name)
                )

                # pop the register before function epilogue
                # epilogue_restores[rr.epilogue_addr].insert(0, 'pop\t%s' % reg_name)
                epilogue_restores[rr.epilogue_addr].insert(
                    0, 'mov\t%s, dword ptr [ebp-%d]' % (reg_name, abs(rr.stack_variable.offset))
                )

                self.register_reallocations += 1

            except BinaryOptimizationNotImplementedError:
                l.error('Something is not implemented.', exc_info=True)
                raise

        for insertion_addr, insns in prologue_saves.items():
            p = InsertCodePatch(insertion_addr, "\n".join(insns))
            # those patches must go in the front of those replaced instructions
            # for example, we would expect
            #   push esi
            #   mov esi, 0
            # instead of
            #   mov esi, 0
            #   push esi  <- the order is wrong
            patches.insert(0, p)

        for insertion_addr, insns in epilogue_restores.items():
            p = InsertCodePatch(insertion_addr, "\n".join(insns))
            # those patches must go in the front of those replaced instructions
            patches.insert(0, p)

        return patches

    def _patches_dead_assignment_elimination(self, bo):
        """
        Generate patches for dead assignment elimination.

        :param bo: The binary optimization result.
        :return: A list of patches.
        :rtype: list
        """

        patches = [ ]

        register_names = self.backend.project.arch.register_names

        for dead_assignment in bo.dead_assignments:  # type: angr.analyses.binary_optimizer.DeadAssignment
            ins_addr = dead_assignment.pv.location.ins_addr
            dead_reg = dead_assignment.pv.variable.reg

            ins = self.backend.project.factory.block(ins_addr).capstone.insns[0]
            op_str = ins.op_str
            operands = op_str.split(',')
            dst_op = operands[0].strip()
            if dead_reg in register_names and dst_op == register_names[dead_reg]:
                l.debug("Eliminating %#x, register %s.", ins_addr, dst_op)

                p = RemoveInstructionPatch(ins_addr, None)
                patches.append(p)

                self.dead_assignment_eliminations += 1

        return patches

    def get_patches(self):
        """

        :return:
        """

        return self._patches

def optimize_it(input_filepath, output_filepath, debugging=False):
    """
    Take a binary as an input, apply optimization techniques, and output to the specified path. An exception is raised
    if optimization fails.

    :param str input_filepath: The binary to work on.
    :param str output_filepath: The binary to output to.
    :param bool debugging: True to enable debugging mode.
    :return: None
    """

    target_filepath = output_filepath
    rr_filepath = tempfile.mktemp()

    # register reallocation first
    b1 = ReassemblerBackend(input_filepath, debugging=debugging)
    cp = BinaryOptimization(input_filepath, b1, {'register_reallocation'})
    patches = cp.get_patches()
    b1.apply_patches(patches)
    r = b1.save(rr_filepath)

    if not r:
        raise BinaryOptimizationError('Optimization fails at stage 1.')

    # other optimization techniques
    b2 = ReassemblerBackend(rr_filepath, debugging=debugging)
    cp = BinaryOptimization(rr_filepath, b2, {'constant_propagation'})
    patches = cp.get_patches()
    b2.apply_patches(patches)
    r = b2.save(target_filepath)

    if not r:
        raise BinaryOptimizationError('Optimization fails at stage 2.')

    try:
        os.unlink(rr_filepath)
    except OSError:
        pass
