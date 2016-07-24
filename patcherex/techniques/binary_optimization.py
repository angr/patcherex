
from collections import defaultdict
import logging

import topsecret
from angr import KnowledgeBase

from ..backends import ReassemblerBackend
from ..patches import RemoveInstructionPatch, InsertCodePatch
from ..technique import Technique

l = logging.getLogger('techniques.binary_optimization')

class BinaryOptimization(Technique):
    def __init__(self, filename, backend):
        super(BinaryOptimization, self).__init__(filename, backend)

        # counters
        self.constant_propagations = 0
        self.redundant_stack_variable_removals = 0

        self._patches = self._generate_patches()

        l.debug('Constant propagation occurred %d times', self.constant_propagations)
        l.debug('Redundant stack variable removal occurred %d times', self.redundant_stack_variable_removals)

    def _generate_patches(self):
        """

        :return:
        """

        patches = [ ]

        cfg = self.backend.cfg
        bo = self.backend.project.analyses.BinaryOptimizer(cfg)

        # constant propagation

        for cp in bo.constant_propagations:  # type: topsecret.binary_optimizer.ConstantPropagation
            # remove the assignment site
            patch = RemoveInstructionPatch(cp.constant_assignment_loc.ins_addr, None)
            patches.append(patch)

            # then remove the consuming site
            patch = RemoveInstructionPatch(cp.constant_consuming_loc.ins_addr, None)
            patches.append(patch)

            # Insert a new instruction there
            old_consumer = self.backend.project.factory.block(cp.constant_consuming_loc.ins_addr, num_inst=1)

            operands = old_consumer.capstone.insns[0].op_str.split(",")
            operands[1] = cp.constant

            # here is the tricky part: the constant might be an address
            # if it's an address, we need to convert it to a label
            if isinstance(self.backend, ReassemblerBackend):
                symbol_manager = self.backend._binary.symbol_manager  # type: topsecret.binary.SymbolManager
                if cp.constant in symbol_manager.addr_to_label:
                    # it's a label... use its label name
                    operands[1] = "{" + symbol_manager.addr_to_label[cp.constant].name + "}"

            if isinstance(operands[1], (int, long)):
                new_op_str = "%s, %#x" % (operands[0], operands[1])
            else:
                new_op_str = "%s, %s" % (operands[0], operands[1])

            new_consumer_asm = "%s\t%s" % (old_consumer.capstone.insns[0].mnemonic, new_op_str)

            patch = InsertCodePatch(cp.constant_consuming_loc.ins_addr, new_consumer_asm)
            patches.append(patch)

            self.constant_propagations += 1


        # redundant stack variable removal

        for rsv in bo.redundant_stack_variables:  # type: topsecret.binary_optimizer.RedundantStackVariable

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
                elif 'ptr' in operands[1]:
                    operands[1] = argument_asm
                else:
                    raise Exception('WTF')

                new_op_str = "%s, %s" % (operands[0], operands[1])

                new_consumer_asm = "%s\t%s" % (old_consumer.capstone.insns[0].mnemonic, new_op_str)

                patch = InsertCodePatch(loc.ins_addr, new_consumer_asm)
                patches.append(patch)

        # register reallocation

        prologue_saves = defaultdict(list)
        epilogue_restores = defaultdict(list)

        for rr in bo.register_reallocations:  # type: topsecret.binary_optimizer.RegisterReallocation
            try:
                patches_ = [ ]
                # which register to replace?
                reg_name = self.backend.project.arch.register_names[rr.register_variable.reg]

                # what instructions to replace?
                # sources first
                for src in rr.stack_variable_sources:
                    insn = self.backend.project.factory.block(src.location.ins_addr, num_inst=1).capstone.insns[0]
                    operands = insn.op_str.split(',')
                    if not len(operands) == 2:
                        l.warning('Unsupported instruction %s. Skip.', str(insn))
                        raise NotImplementedError()

                    # replace the dest
                    new_insn = "%s\t%s, %s" % (insn.mnemonic, reg_name, operands[1])

                    # patch: remove the old instruction
                    p0 = RemoveInstructionPatch(insn.address, None)
                    patches_.append(p0)

                    # patch: add the new instruction
                    p1 = InsertCodePatch(insn.address, new_insn)
                    patches_.append(p1)

                # consumers
                for dst in rr.stack_variable_consumers:
                    insn = self.backend.project.factory.block(dst.location.ins_addr, num_inst=1).capstone.insns[0]
                    if len(insn.operands) == 2:
                        operands = insn.op_str.split(',')
                        new_insn = "%s\t%s, %s" % (insn.mnemonic, operands[0], reg_name)
                    else:
                        # TODO:
                        raise NotImplementedError()

                    # patch: remove the old instruction
                    p0 = RemoveInstructionPatch(insn.address, None)
                    patches_.append(p0)

                    # patch: add the new instruction
                    p1 = InsertCodePatch(insn.address, new_insn)
                    patches_.append(p1)

                patches.extend(patches_)

                # save the register after function prologue
                prologue_saves[rr.prologue_addr + rr.prologue_size].append('push\t%s' % reg_name)

                # pop the register before function epilogue
                epilogue_restores[rr.epilogue_addr].insert(0, 'pop\t%s' % reg_name)

            except NotImplementedError:
                continue

        for insertion_addr, insns in prologue_saves.iteritems():
            p = InsertCodePatch(insertion_addr, "\n".join(insns))
            patches.append(p)

        for insertion_addr, insns in epilogue_restores.iteritems():
            p = InsertCodePatch(insertion_addr, "\n".join(insns))
            patches.append(p)

        return patches

    def get_patches(self):
        """

        :return:
        """

        return self._patches