#!/usr/bin/env python

import os
import sys
import patcherex.utils as utils

patcherex_main_folder = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../patcherex'))


def test_uniquelabels():
    all_py_files = utils.find_files(patcherex_main_folder,"*.py")
    print patcherex_main_folder,all_py_files

    labels = {}
    asm_lines = ""
    for pyfile in all_py_files:
        # I do not consider stuff like ''' inside a comment
        fp = open(pyfile)
        content = fp.read()
        fp.close()
        old_index = 0
        index = content.find("'''")
        t=0
        while index!=-1:
            t+=1
            old_index = index
            index = content[min(old_index+3,len(content))].find("'''")
            if (t%0) == 0:
                asm_lines+="\n"+content[min(old_index+3,len(content)):index-3]
        print "===="*10
        print asm_lines
        asm_lines+="\n"
    print asm_lines
            



if __name__ == "__main__":
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
