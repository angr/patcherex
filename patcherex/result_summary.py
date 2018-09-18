#!/usr/bin/env python

import sys
import os
from collections import defaultdict
from functools import reduce

from patcherex import utils

timeout = 600
ptypes = ["medium_detour","medium_reassembler","medium_reassembler_optimized"]
btypes = ["original","Os","Oz","O0","O1","O2","O3","Ofast"]

def file_to_list(fname):
    with open(fname) as fp:
        content = fp.read()
    rlist = []
    for l in content.split("\n"):
        l = l.strip()
        if not l:
            continue
        rlist.append(l)
    return rlist


def fname_to_pbtype(fname):
    f = os.path.dirname(fname)
    split= f.split(os.path.sep)
    return (split[-2],split[-3])


def cblist_to_str(cblist):
    tstr = str(len(cblist))
    tstr += " " + repr(cblist)
    return tstr


def filename_to_cbname(fname):
    if fname.endswith("_log"):
        fname = fname[:-4]
    return os.path.basename(fname)


def coalesce_multi_cb(flist):
    coalesced = set()
    for f in flist:
        if f.count("_") == 2:
            coalesced.add("_".join(f.split("_")[:-1]))
        else:
            coalesced.add(f)
    return list(coalesced)


def filter_functionality(flist, blacklist):
    if blacklist == None:
        return flist
    else:
        return list(set(flist)-set(blacklist))


if __name__ == "__main__":
    res_folder = sys.argv[1]
    blacklist_folder = None
    if len(sys.argv) == 3:
        blacklist_folder = sys.argv[2]

    if blacklist_folder is not None:
        blacklist = {}
        tfiles = utils.find_files(blacklist_folder,"*.txt")
        for f in tfiles:
            blacklist[os.path.basename(f)[:-4]] = file_to_list(f)
        blacklist["original"] = []
    else:
        blacklist = None

    results = defaultdict(list)
    times = defaultdict(dict)
    log_files = utils.find_files(res_folder,"*_log")
    for lfile in log_files:
        with open(lfile) as fp:
            content = fp.read()
        ret_code = int(content.split("==== RETCODE: ")[1].split()[0])
        log_payload = content.split("==== RETCODE: ")[0].split("\n")[-3].split(":")[0]
        if ret_code != 0:
            results[fname_to_pbtype(lfile)].append((filename_to_cbname(lfile),ret_code,log_payload, \
                    content.split("==== RETCODE: ")[0][-200:]))

        if "=========== process ended at" in content:
            etime = float(content.split("=========== process ended at")[1].split("in")[1].split()[0])
            times[fname_to_pbtype(lfile)[0]][filename_to_cbname(lfile)] = etime
        if ret_code == -9:
            times[fname_to_pbtype(lfile)[0]][filename_to_cbname(lfile)] = float(timeout+1)

    tester_results_file = os.path.join(res_folder,"tester.txt")
    if os.path.exists(tester_results_file):
        with open(tester_results_file) as fp:
            content = fp.read()
        for line in content.split("\n"):
            if "FAILED: " in line:
                folder,cb_name = line.split(" ")[1:2+1]
                folder_split = folder.split(os.path.sep)
                print(folder_split)
                pname = folder_split[-1]
                bname = folder_split[-2]
                cb_name = cb_name.split("\x1b")[0]
                results[(pname,bname)].append((cb_name,999,"",""))

    for k,v in results.items():
        print(k,repr(v))

    global_results = {}
    for ptype in ptypes:
        print("=" * 30, ptype)
        for btype in btypes:
            print("-" *10, btype)
            timeouts = [b[0] for b in results[(ptype,btype)] if b[1] == -9]
            total_timeout_failures = len(timeouts)
            print("timeouts:", cblist_to_str(timeouts))
            expected_failed_generation = [(b[0],b[1],b[2]) for b in results[(ptype, btype)] if \
                    b[1] == 33 and b[2] == "ReassemblerError"]
            print("expected_failed_generation:", cblist_to_str(expected_failed_generation))
            unexpected_failed_generation = [(b[0],b[1],b[2]) for b in results[(ptype, btype)] if \
                    b[1] == 33 and b[2] != "ReassemblerError" and b[2] != "FunctionalityError"]
            print("unexpected_failed_generation:", cblist_to_str(unexpected_failed_generation))
            unexpected_undetected_failed_generation = [(b[0],b[1],b[2]) for b in results[(ptype, btype)] if \
                    b[1] != 33 and b[1] != 0 and b[1] != -9 and b[1] != 999]
            print("unexpected_undetected_failed_generation:", cblist_to_str(unexpected_undetected_failed_generation))
            total_generation_failures = len(timeouts) + len(expected_failed_generation) + \
                    len(unexpected_failed_generation) + len(unexpected_undetected_failed_generation)
            print("TOTAL GENERATION FAILURES:", total_generation_failures)

            detected_functionality_failures = [b[0] for b in results[(ptype, btype)] if \
                    b[1] == 33 and b[2] == "FunctionalityError"]
            detected_functionality_failures = coalesce_multi_cb(detected_functionality_failures)
            detected_functionality_failures = filter_functionality(detected_functionality_failures,blacklist[btype])
            total_detected_functionality_failures = len(detected_functionality_failures)
            print("detected_functionality_failures:", cblist_to_str(detected_functionality_failures))
            tester_functionality_failures = [b[0] for b in results[(ptype, btype)] if b[1] == 999]
            tester_functionality_failures = filter_functionality(tester_functionality_failures, blacklist[btype])
            print("tester_functionality_failure:", cblist_to_str(tester_functionality_failures))
            total_functionality_failures = len(detected_functionality_failures) + len(tester_functionality_failures)
            print("TOTAL FUNCTIONALITY FAILURES:", total_functionality_failures)
            global_results[(ptype,btype)] = (total_timeout_failures,total_generation_failures,\
                    total_detected_functionality_failures, total_functionality_failures)

    print("=" * 50, "GLOBAL_RESULTS")
    print("=" * 30, "original")
    for ptype in ptypes:
        tott = 0
        totg = 0
        totd = 0
        totf = 0
        print("="*10, ptype)
        btype = "original"
        tott += global_results[(ptype, btype)][0]
        totg += global_results[(ptype, btype)][1]
        totd += global_results[(ptype, btype)][2]
        totf += global_results[(ptype, btype)][3]
        print("total timeout failures:", tott)
        print("----- total generation failures:", totg)
        print("total detected functionality failures:", totd)
        print("----- total functionality failures:", totf)

    print("=" * 30, "others")
    for ptype in ptypes:
        tott = 0
        totg = 0
        totd = 0
        totf = 0
        print("="*10, ptype)
        for btype in btypes:
            if btype == "original":
                continue
            tott += global_results[(ptype, btype)][0]
            totg += global_results[(ptype, btype)][1]
            totd += global_results[(ptype, btype)][2]
            totf += global_results[(ptype, btype)][3]
        print("total timeout failures:", tott)
        print("----- total generation failures:", totg)
        print("total detected functionality failures:", totd)
        print("----- total functionality failures:", totf)

    intervals = list(range(50,70+1,10)) + list(range(75,95,5)) + list(range(95,100+1,1))
    print("=" * 50, "TIME")
    for ptype in ptypes:
        tt = times[ptype]
        tstr = "%30s " % ptype
        per = 0
        vlist = list(sorted(tt.values()))
        slist = []
        slist.append("avg:%3s" % str(int(round((reduce(lambda x, y:x+y, tt.values())/float(len(tt.values()))),0))))
        for i in intervals:
            slist.append(str(i) + "%:" + "%3s"%str(int(vlist[min(int(len(vlist)/100.0*i),len(vlist)-1)])))
        print(tstr+"-".join(slist))
