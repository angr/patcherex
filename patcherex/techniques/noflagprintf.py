import claripy
import logging
from patcherex.patches import AddLabelPatch, InsertCodePatch, AddRODataPatch

l = logging.getLogger("patcherex.techniques.NoFlagPrintfPatcher")

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
        self.all_strings = self._get_strings()
        self.hash_dict = self._generate_hash_dict()

    def _get_strings(self):
        state = self.patcher.project.factory.blank_state()
        string_references = []
        for v in self.patcher.cfg._memory_data.values():
            if v.sort == "string" and v.size > 1:
                st_bytes = state.solver.eval(state.memory.load(v.address, v.size), cast_to=bytes)
                st = "".join(chr(i) for i in st_bytes)
                string_references.append((v.address, st))
        return [] if len(string_references) == 0 else list(zip(*string_references))[1]

    def _generate_hash_dict(self):
        def hash_str(tstr):
            hash = 0
            for c in tstr:
                hash ^= ord(c)
            if hash == 0:
                hash += 1
            return bytes([hash])

        hash_dict = {}
        for func, (func_name, func_obj) in self.ident.matches.items():
            if func_name not in PRINTF_VARIANTS:
                continue
            if func_obj.format_spec_char is None:
                continue
            relevant_strings = [s for s in self.all_strings if func_obj.format_spec_char in s]
            hash_dict[func_obj.format_spec_char] = list(sorted(set(map(hash_str, relevant_strings)),
                                                               key=lambda x: ord(x)))
        return hash_dict

    @property
    def ro_segments(self):
        if self._ro_segments is None:
            self._ro_segments = tuple(
                seg for seg in self.patcher.project.loader.main_object.segments if seg.is_readable and not seg.is_writable
            )

        return self._ro_segments

    def get_patches(self):
        cfg = self.patcher.cfg
        patches = []

        pnum = 0
        used_spec_chars = []
        for func, (func_name, func_obj) in self.ident.matches.items():
            if func_name not in PRINTF_VARIANTS:
                continue
            if func_obj.format_spec_char is None:
                l.warning("func_obj.format_spec_char is None")
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

            pnum += 1 # we need this to ensure always different labels
            used_spec_chars.append(func_obj.format_spec_char)
            check = """
                ; is the address not in RO memory?
                cmp dword [esp+{stack_offset}], {{max_ro_addr}}
                jbe _end_printfcheck_%d

                ; int 3
                ; is the address in the flag page?
                cmp dword [esp+{stack_offset}], {flag_page}
                jb _check_for_percent_%d
                cmp dword [esp+{stack_offset}], {flag_page_almost_end}
                ja _check_for_percent_%d

                ; they're trying to read from the flag page! fuck them.
                jmp 0x41414141

            _check_for_percent_%d:
                push esi ; = pointer to string
                mov esi, [esp+{stack_offset_2}]
                push eax
                xor eax, eax; hash

            _loop_printfcheck_%d:
                cmp byte [esi], 0
                je _final_check_printfcheck_%d
                xor al, byte[esi]
                cmp byte[esi], {format_spec_char}
                jne _continue_printfcheck_%d
                    mov ah, 0x1
                _continue_printfcheck_%d:
                    inc esi
                    jmp _loop_printfcheck_%d

            _final_check_printfcheck_%d:
                test ah, ah
                je _restore_printfcheck_%d
                test al, al ; avoid al==0 as we do in the hash algorithm
                jne _do_not_inc_%d
                    inc al
                _do_not_inc_%d: ; the dynamic hash will always be bigger than 0, the hash list is null terminated
                    mov esi, {{hash_list_{format_spec_char}}}
                _hash_check_loop_%d:
                    cmp byte[esi], 0 ; the end of the list has been reached
                    je 0x41414141
                    cmp byte[esi], al ; esi points to the hash list
                    je _restore_printfcheck_%d
                    inc esi
                    jmp _hash_check_loop_%d

            _restore_printfcheck_%d:
                pop eax
                pop esi

            _end_printfcheck_%d:
            """.format(
                stack_offset=(fmt_arg_pos + 1) * 4,
                stack_offset_2=(fmt_arg_pos + 2) * 4,
                flag_page=FLAG_PAGE,
                flag_page_almost_end=FLAG_PAGE + 0xffc,
                format_spec_char=ord(func_obj.format_spec_char),
            ) % tuple([pnum]*18)

            patches.append(InsertCodePatch(func.addr, check, priority=250, name="noflagprintf_%d" % pnum))
            l.info("function at %#08x protected" % func.addr)

        if patches:
            max_ro_addr = max(seg.max_addr for seg in self.ro_segments)
            patches.append(AddLabelPatch(max_ro_addr, name="max_ro_addr"))

        # print repr(self.hash_dict)
        for fspec in set(used_spec_chars):
            hash_list = b"".join(self.hash_dict[fspec]) + b"\x00"
            patches.append(AddRODataPatch(hash_list,
                        name="hash_list_{format_spec_char}".format(format_spec_char=ord(fspec))))
        # print "\n".join(map(str,patches))
        return patches

def init_technique(program_name, backend, options):
    return NoFlagPrintfPatcher(program_name, backend, **options)
