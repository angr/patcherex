
def get_function_size(ff):
    return reduce(lambda x,y: x+y.size, ff.blocks, 0)


def is_sane_function(ff):
    if not ff.is_syscall and ff.returning and not ff.has_unresolved_calls and \
            not ff.has_unresolved_jumps and ff.startpoint != None and ff.endpoints != None:
        if len(ff.endpoints)>0:
            if get_function_size(ff) >= 10: # this is the size of two detours
                return True
    return False

    # TODO check and exclude floating point functions in: https://github.com/CyberGrandChallenge/libcgc/blob/master/maths.s
    # TODO remove syscall wrapper
