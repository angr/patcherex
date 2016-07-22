
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
            for loc in rsv.stack_variable_consuming_locs:  # type: angr.analyses.code_location.CodeLocation

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

        return patches

    def get_patches(self):
        """

        :return:
        """

        return self._patches