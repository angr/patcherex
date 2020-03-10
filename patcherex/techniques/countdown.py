import patcherex
import angr

from ..technique import Technique

import logging
from patcherex.patches import *


l = logging.getLogger("patcherex.techniques.Countdown")

class Countdown(Technique):
    """
    Technique that counts executions of code paths and switches control flow after *count* executions.
    Args:
        target_addr: Address of the code we want to monitor
        count: Countdown value
        dst_active: Jump target while countdown is active
        dst_zero: Jump target after count reached zero
    """
    # Unique identifier for countdown variable
    global_countdown_idx = 0

    def __init__(self, filename, backend, target_addr, count, dst_active, dst_zero, extra_logic_code=None, extra_is_c=True):
        super(Countdown, self).__init__(filename, backend)
        self.filename = filename
        self.backend = backend
        self.target_addr = target_addr
        self.count = count
        
        self.arch_bits = self.patcher.structs.elfclass
        self.obj = self.patcher.project.loader.main_object
        self.compiler_flags = (f"-m{self.arch_bits}",)
        l.debug("Got %d bit %s binary", self.arch_bits, "PIE" if self.obj.pic else "NO-PIE")

        self.dst_active = dst_active
        self.dst_active = self.obj.addr_to_offset(dst_active) if self.obj.pic else dst_active
        l.debug("dst_active == %s", hex(self.dst_active))
        self.dst_active_name = f"dst_active_{Countdown.global_countdown_idx}"
        self.dst_zero = self.obj.addr_to_offset(dst_zero) if self.obj.pic else dst_zero
        l.debug("dst_zero == %s", hex(self.dst_zero))
        self.dst_zero_name = f"dst_zero_{Countdown.global_countdown_idx}"

        self.extra_logic_code = extra_logic_code if extra_logic_code else self.nop_logic
        self.extra_is_c = extra_is_c

        self.count_var_name = f"countdown_var_{Countdown.global_countdown_idx}"
        self.countdown_logic_name = f"countdown_logic_{Countdown.global_countdown_idx}"
        self.extra_logic_name = self.countdown_logic_name + "_extra"

        Countdown.global_countdown_idx += 1



    @property
    def patcher(self):
        return self.backend

    @property
    def nop_logic(self):
        code = """
        void nop_logic(void) {
            return;
        }
        """
        return code

    def get_patches(self):
        """
        Get all patches in order to apply this technique on the binary.

        :return: A list of patches.
        :rtype: list
        """
        patches = []

        # 1. Insert count variable
        patches.extend(self._get_count_var())
        # 2. Label jump outs
        patches.extend(self._get_return_labels())
        # 3. Insert logic code
        patches.extend(self._get_logic())
        # 4. Insert target jumps
        patches.extend(self._get_jump())
        return patches

    def _get_count_var(self):
        """
        Adds countdown variable
        """
        p1 = AddRWInitDataPatch(struct.pack("<I", self.count), self.count_var_name)
        return [p1]

    def _get_return_labels(self):
        """
        Adds labels to the jump out targets
        """
        p1 = AddLabelPatch(self.dst_active, self.dst_active_name)
        p2 = AddLabelPatch(self.dst_zero, self.dst_zero_name)
        return [p1, p2]

    def _get_logic(self):
        """
        Adds logic to check and update the countdown
        """

        reg_a = "rax" if self.arch_bits == 64 else "eax"
        reg_b = "rbx" if self.arch_bits == 64 else "ebx"
        reg_sp = "rsp" if self.arch_bits == 64 else "esp"

        if self.patcher.project.loader.main_object.pic:
            l.debug("Using `call {pie_thunk}`. This will clobber {rax, [rsp]} in order to return a pointer to the base of the binary")
            get_counter = '''
            call {pie_thunk}
            add %s, {%s}
            ''' % (reg_a, self.count_var_name)
        else:
            get_counter = '''
            mov %s, {%s}
            ''' % (reg_a, self.count_var_name)

        code = '''
            ; update countdown
            push %s
            push %s
            push %s
            ; get address of count_var
%s
            mov %s, [%s]
            sub ebx, 1
            mov [%s], %s
            ; check if we reached zero
            test ebx, ebx
            jle _zero_case
            ; call extra logic and jump to dst_active
            call {%s}
            pop %s
            pop %s
            pop %s
            jmp %s
            _zero_case:
            ; call extra logic and jump to dst_zero
            call {%s}
            pop %s
            pop %s
            pop %s
            jmp %s
        ''' % (reg_a,
                reg_b,
                reg_sp,
                get_counter,
                reg_b, reg_a, 
                reg_a, reg_b,
                self.extra_logic_name,
                reg_sp,
                reg_b,
                reg_a,
                hex(self.dst_active),
                self.extra_logic_name,
                reg_sp,
                reg_b,
                reg_a,
                hex(self.dst_zero))
        p1 = AddCodePatch(self.extra_logic_code, name=self.extra_logic_name, is_c=self.extra_is_c, compiler_flags=self.compiler_flags)
        p2 = AddCodePatch(code, name=self.countdown_logic_name, compiler_flags=self.compiler_flags)
        return [p1, p2]

    def _get_jump(self):
        """
        Inserts jump to new countdown code
        """ 

        code = """
            jmp {%s}
        """ % (self.countdown_logic_name)
        p1 = InlinePatch(self.target_addr, code)
        return [p1]


class CountdownCallSite:
    def __init__(self):
        self.call_chain = []
        self.conditional_addr = None


def init_technique(program_name, backend, options):
    return OmitFunction(program_name, backend, **options)
