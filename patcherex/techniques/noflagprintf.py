import claripy
from patcherex.patches import AddLabelPatch, InsertCodePatch

# func name to format string arg position
PRINTF_VARIANTS = {
    'printf': 0,
    'fdprintf': 1,
    'fprintf': 1,
    'sprintf': 1,
    'snprintf': 2,
}

FLAG_PAGE = 0x4347c000


class NoFlagPrintfPatcher(object):
    def __init__(self, binary_fname, backend):
        self.binary_fname = binary_fname
        self.patcher = backend
        self.ident = self.patcher.identifier

        self._ro_segments = None

    @property
    def ro_segments(self):
        if self._ro_segments is None:
            self._ro_segments = tuple(
                seg for seg in self.patcher.project.loader.main_bin.segments if seg.is_readable and not seg.is_writable
            )

        return self._ro_segments

    def get_patches(self):
        cfg = self.patcher.cfg
        patches = []

        for func, (func_name, func_obj) in self.ident.matches.items():
            if func_name not in PRINTF_VARIANTS:
                continue

            fmt_arg_pos = PRINTF_VARIANTS[func_name]
            callers = set.union(set(), *(cfg.get_predecessors(node) for node in cfg.get_all_nodes(func.addr)))

            handled_addrs = set()
            func_to_cfg = {}
            for caller in callers:
                if caller.addr in handled_addrs:
                    continue

                try:
                    args, _ = self.ident.get_call_args(func, caller.addr)
                except KeyError:
                    continue

                fmt_str = args[fmt_arg_pos]
                if not claripy.is_true(claripy.Or(*(claripy.And(seg.min_addr <= fmt_str, fmt_str <= seg.max_addr)\
                        for seg in self.ro_segments))):
                    # we bad
                    break

                handled_addrs.add(caller.addr)
            else:
                # patch not necessary for this function
                continue

            check = """
                ; is the address not in RO memory?
                cmp dword [esp+{stack_offset}], {{max_ro_addr}}
                jbe _end

                ; is the address in the flag page?
                cmp dword [esp+{stack_offset}], {flag_page}
                jb _check_for_percent
                cmp dword [esp+{stack_offset}], {flag_page_almost_end}
                ja _check_for_percent

                ; they're trying to read from the flag page! fuck them.
                jmp 0x41414141

            _check_for_percent:
                push esi ; = pointer to string
                mov esi, [esp+{stack_offset_2}]

            _loop_printfcheck:
                cmp byte [esi], 0
                je _restore_printfcheck
                cmp byte [esi], {format_spec_char}
                ; die!!!
                je 0x41414141
                inc esi
                jmp _loop_printfcheck

            _restore_printfcheck:
                pop esi

            _end:
            """.format(
                stack_offset=(fmt_arg_pos + 1) * 4,
                stack_offset_2=(fmt_arg_pos + 2) * 4,
                flag_page=FLAG_PAGE,
                flag_page_almost_end=FLAG_PAGE + 0xffc,
                format_spec_char=ord(func_obj.format_spec_char),
            )

            patches.append(InsertCodePatch(func.addr, check, priority=250))

        if patches:
            max_ro_addr = max(seg.max_addr for seg in self.ro_segments)
            patches.append(AddLabelPatch(max_ro_addr, name="max_ro_addr"))

        return patches
