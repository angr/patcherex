
import capstone


def get_function_size(ff):
    return reduce(lambda x,y: x+y.size, ff.blocks, 0)


def is_sane_function(ff):
    if not ff.is_syscall and ff.returning and not ff.has_unresolved_calls and \
            not ff.has_unresolved_jumps and ff.startpoint != None and ff.endpoints != None:
        if len(ff.ret_sites)>0:
            if get_function_size(ff) >= 10: # this is the size of two detours
                return True
    return False


def is_floatingpoint_function(backend,ff):
    if not(hasattr(backend,"mem_start") and hasattr(backend,"mem_end")):
        init_bytes = "DB 6C 24 04 EB 0A D9 44 24 04 EB 04 DD 44 24 04 D9 FE".replace(" ","").decode('hex')
        end_bytes = "D9 44 24 04 EB 04 DD 44 24 04 D9 EA DE C9 EB B7".replace(" ","").decode('hex')

        file_start = backend.ocontent.find(init_bytes)
        file_end = backend.ocontent.find(end_bytes)
        if file_start == -1 or file_end == -1:
            backend.mem_start = None
            backend.mem_end = None
        else:
            backend.mem_start = backend.project.loader.main_bin.offset_to_addr(file_start)
            backend.mem_end = backend.project.loader.main_bin.offset_to_addr(file_end)

    if backend.mem_start == None or backend.mem_end == None:
        return False
    if ff.endpoints == None:
        last_end = ff.addr
    else:
        if len(ff.endpoints) == 0:
            last_end = ff.addr
        else:
            last_end = max([e.addr for e in ff.endpoints])
    if last_end >= backend.mem_start and ff.addr < backend.mem_end:
        return True
    else:
        return False


def detect_syscall_wrapper(backend,ff):
    # see: https://github.com/CyberGrandChallenge/libcgc/blob/master/libcgc.s
    def check_first_instruction(instr):
        if instr.mnemonic == u'mov':
            if len(instr.operands) == 2:
                if instr.operands[0].reg == capstone.x86_const.X86_REG_EAX:
                    return instr.operands[1].imm
        return None

    try:
        succ = ff.startpoint.successors()
    except:
        # TODO recheck when https://git.seclab.cs.ucsb.edu/angr/angr/issues/191 is fixed
        return None
    ends = ff.endpoints
    first_instr = backend.project.factory.block(ff.startpoint.addr).capstone.insns[0]
    syscall_number = check_first_instruction(first_instr)
    if syscall_number == None:
        return None

    if syscall_number == 1:
        if len(succ) == 1:
            bb1 = succ[0]
            if hasattr(bb1,"is_syscall") and bb1.is_syscall:
                return syscall_number
        return None
    else:
        if not is_sane_function(ff):
            return None
        if len(succ) == 2:
            bb1,bb2 = succ
            if hasattr(bb1,"is_syscall") and bb1.is_syscall:
                ebb = bb2
            elif hasattr(bb2,"is_syscall") and bb2.is_syscall:
                ebb = bb1
            else:
                ebb= None
            if ebb != None:
                if len(ends) == 1:
                    end = ends[0]
                    if ebb == end:
                        return syscall_number
        return None

    # TODO check and exclude floating point functions in: https://github.com/CyberGrandChallenge/libcgc/blob/master/maths.s
