#!/usr/bin/env python

import sys
import os
from patcherex import utils


def fname_unpatched_to_key(f):
    cs,ctype,cb = f.split(os.path.sep)[-3:]
    return tuple([ctype,cb])

def fname_patched_to_key(f):
    ctype,ptype,cs,cb = f.split(os.path.sep)[-4:]
    return tuple([ctype,ptype,cs,cb])

if __name__ == "__main__":
    unpatched_folder = sys.argv[1]
    patched_folder = sys.argv[2]

    unpatched_files = utils.find_files(unpatched_folder,"*",True)
    unpatched_sizes = {fname_unpatched_to_key(f): os.path.getsize(f) for f in unpatched_files}

    patched_files = utils.find_files(patched_folder,"*",True)
    patched_sizes = {fname_patched_to_key(f): os.path.getsize(f) for f in patched_files}
    size_overheads = {}
    for k, v in patched_sizes.items():
        unpatched_size = unpatched_sizes[(k[0],k[3])]
        size_overheads[k] = (unpatched_size,v,v/float(unpatched_size))

    sorted_results = sorted(size_overheads.items(),key=lambda x:x[1][2])
    for k,(o,p,ov) in sorted_results:
        print("%65s % 9d % 9d % 3.2f"%(os.path.sep.join(k),o,p,round(ov*100.0,2)))


'''
./file_sizes.py ../../binaries-private/cgc_samples_multiflags/ ../../cgc_results/tp110/
'''
