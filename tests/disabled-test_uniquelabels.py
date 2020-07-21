#!/usr/bin/env python

import os
import sys
from collections import defaultdict

import nose

import patcherex.utils as utils


patcherex_main_folder = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../patcherex'))

# with reassembler we really do not want duplicate labels
# this goes trough all our .py files
# of course, if a label is used twice because of "code", we do not detect it
def test_uniquelabels():
    all_py_files = utils.find_files(patcherex_main_folder,"*.py")
    blacklist = ["networkrules.py"]
    all_py_files = [f for f in all_py_files if not os.path.basename(f) in blacklist]
    # print patcherex_main_folder,all_py_files

    labels_dict = defaultdict(list)
    for pyfile in all_py_files:
        labels = []

        # not really necessary:
        fp = open(pyfile, "r")
        content = fp.read()
        fp.close()
        # asm_lines = ""
        # old_index = 0
        # index = content.find("'''")
        # t=0
        # while True:
        #   t+=1
        #     old_index = index
        #     index = content.find("'''",min(old_index+3,len(content)))
        #    if index==-1:
        #        break
        #    if (t%2) != 0:
        #        asm_lines+="\n"+content[min(old_index+3,len(content)):index-3]
        #asm_lines+="\n"
        labels = utils.string_to_labels(content)
        for l in labels:
            labels_dict[l].append(pyfile)

    duplicates = {}
    for k,v in labels_dict.items():
        if len(v)>1:
            print(k,[os.path.basename(x) for x in v])
            duplicates[k] = v
    nose.tools.assert_equal(len(duplicates),0)


def run_all():
    functions = globals()
    all_functions = dict(filter((lambda x: x[0].startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
