import struct
import logging

from ..technique import Technique

from patcherex.patches import AddRWInitDataPatch, AddCodePatch, AddLabelPatch, InlinePatch


l = logging.getLogger("patcherex.techniques.Countdown")

class Countdown(Technique):
    """
    Technique that counts executions of code paths and switches control flow after *count* executions.
    Args:
        patch_list: List of jumps to the code we want to monitor
            - target_addr: Address of the jump
            - num_instr: Number of instructions we can clobber
            - dst_active: Where to jump while countdown is active
            - dst_zero Where to jump when countdown reaches zero
                - ZERO_TARGET_EXIT: Call exit when countdown reaches zero
        count: Countdown value
        extra_logic_code: Additional code to execute at each iteration
            - Can use stack after rsp-8
            - Save and restore registers!
        extra_is_c: Is extra code given in C (or asm)
    """
    # Unique identifier for countdown variable
    global_countdown_idx = 0

    # Special dst_zero targets
    ZERO_TARGET_EXIT = "EXIT"

    def __init__(self, filename, backend, patch_list, count):
        super(Countdown, self).__init__(filename, backend)
        self.filename = filename
        self.backend = backend
        self.count = count
        self.has_ZERO_TARGET_EXIT = False
        self.local_countdown_idx = 0

        self.arch_bits = self.patcher.structs.elfclass
        self.obj = self.patcher.project.loader.main_object
        self.compiler_flags = f"-m{self.arch_bits}"
        l.debug("Got %d bit %s binary", self.arch_bits, "PIE" if self.obj.pic else "NO-PIE")

        self.count_var_name = f"countdown_var_{Countdown.global_countdown_idx}"
        self.ZERO_TARGET_EXIT_name = f"{self.count_var_name}zero_target_exit"

        self.patch_list = patch_list
        for patch in self.patch_list:
            # handle dst_active
            patch["dst_active"] = self.obj.addr_to_offset(patch["dst_active"]) if self.obj.pic else patch["dst_active"]
            l.debug("dst_active == %s", hex(patch["dst_active"]))
            patch["dst_active_name"] = f"dst_active_{Countdown.global_countdown_idx}_{self.local_countdown_idx}"
            # handle dst_zero
            if patch["dst_zero"] == Countdown.ZERO_TARGET_EXIT:
                self.has_ZERO_TARGET_EXIT = True
                patch["dst_zero_name"] = self.ZERO_TARGET_EXIT_name
                l.debug("Calling exit when zero is reached.")
            else:
                patch["dst_zero"] = self.obj.addr_to_offset(patch["dst_zero"]) if self.obj.pic else patch["dst_zero"]
                patch["dst_zero_name"] = f"dst_zero_{Countdown.global_countdown_idx}_{self.local_countdown_idx}"
                l.debug("dst_zero == %s", hex(patch["dst_zero"]))
            # handle extra_code
            patch["extra_code"] = self.nop_logic if not "extra_code" in patch else patch["extra_code"]
            patch["extra_is_c"] = True if not "extra_is_c" in patch else patch["extra_is_c"]
            patch["countdown_logic_name"] = f"countdown_logic_{Countdown.global_countdown_idx}_{self.local_countdown_idx}"
            patch["extra_code_name"] = f"{patch['countdown_logic_name']}_extra_code"
            self.local_countdown_idx += 1


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
        # 2. Insert special zero targets
        patches.extend(self._get_special_zero_targets())
        for patch in self.patch_list:
            # 3. Insert extra code
            patches.extend(self._get_extra_code(patch))
            # 4. Label jump outs
            patches.extend(self._get_return_labels(patch))
            # 5. Insert logic code
            patches.extend(self._get_logic(patch))
            # 6. Insert target jumps
            patches.extend(self._get_jump(patch))
        return patches

    def _get_count_var(self):
        """
        Adds countdown variable
        """
        p1 = AddRWInitDataPatch(struct.pack("<I", self.count), self.count_var_name)
        return [p1]

    def _get_special_zero_targets(self):
        """
        Adds code for special zero targets
        """
        if self.has_ZERO_TARGET_EXIT:
            reg_a = "rax" if self.arch_bits == 64 else "eax"
            param_0 = "rdi" if self.arch_bits == 64 else "ebx"
            exit_num = 60 if self.arch_bits == 64 else 1
            syscall = "syscall" if self.arch_bits == 64 else "int 0x80"
            code = """
                xor %s, %s
                mov %s, %d
                %s
            """ % (param_0, param_0,
                    reg_a, exit_num,
                    syscall)
            p1 = AddCodePatch(code, name=self.ZERO_TARGET_EXIT_name, compiler_flags=self.compiler_flags)
            return [p1]
        return []

    @staticmethod
    def _get_return_labels(patch):
        """
        Adds labels to the jump out targets
        """
        ret = []
        p1 = AddLabelPatch(patch["dst_active"], patch["dst_active_name"])
        ret.append(p1)
        if type(patch["dst_zero"]) != str:
            p2 = AddLabelPatch(patch["dst_zero"], patch["dst_zero_name"])
            ret.append(p2)
        return ret

    def _get_extra_code(self, patch):
        if not patch["extra_is_c"]:
            # We called this code so the stack is shifted by 8.
            patch["extra_code"] = """
                add rsp, 8
                %s
                sub rsp, 8
                ret
            """ % (patch['extra_code'])
        p1 = AddCodePatch(patch["extra_code"], name=patch["extra_code_name"], is_c=patch["extra_is_c"], compiler_flags=self.compiler_flags)
        return [p1]

    def _get_logic(self, patch):
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
            ; check if we reached zero
            test ebx, ebx
            jle _zero_case
            ; decrement
            sub ebx, 1
            mov [%s], %s
            ; call extra logic and jump to dst_active
            pop %s
            pop %s
            pop %s
            call {%s}
            jmp {%s}
            _zero_case:
            ; call extra logic and jump to dst_zero
            pop %s
            pop %s
            pop %s
            call {%s}
            jmp {%s}
        ''' % (reg_a,
                reg_b,
                reg_sp,
                get_counter,
                reg_b, reg_a,
                reg_a, reg_b,
                reg_sp,
                reg_b,
                reg_a,
                patch["extra_code_name"],
                patch["dst_active_name"],
                reg_sp,
                reg_b,
                reg_a,
                patch["extra_code_name"],
                patch["dst_zero_name"])
        p1 = AddCodePatch(code, name=patch["countdown_logic_name"], compiler_flags=self.compiler_flags)
        return [p1]

    @staticmethod
    def _get_jump(patch):
        """
        Inserts jump to new countdown code
        """

        code = """
            jmp {%s}
        """ % (patch["countdown_logic_name"])
        p1 = InlinePatch(patch["target_addr"], code, num_instr=patch["num_instr"])
        #p1 = InsertCodePatch(patch["target_addr"], code)
        return [p1]


class CountdownCallSite:
    def __init__(self):
        self.call_chain = []
        self.conditional_addr = None


def init_technique(program_name, backend, options):
    return Countdown(program_name, backend, **options)
