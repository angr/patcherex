#!/usr/bin/env python

import os.path
import random
import argparse
import logging
import time
import queue as Queue
from multiprocessing import Pool, Manager
from functools import partial

from patcherex.backends import ReassemblerBackend
from patcherex.patches import *
from patcherex.techniques import ShadowStack, ShiftStack, Adversarial, BinaryOptimization
from patcherex.techniques.binary_optimization import optimize_it
from patcherex.errors import BinaryOptimizationError

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../test_binaries'))

#
# Utils
#

def set_proc_name(procname):
    # for the ease of debugging...
    # you can see the new name via "ps -A"
    from ctypes import cdll, byref, create_string_buffer
    libc = cdll.LoadLibrary('libc.so.6')
    buff = create_string_buffer(len(procname) + 1)
    buff.value = procname
    libc.prctl(15, byref(buff), 0, 0, 0)

def enable_logging():
    logging.getLogger('patcherex.backends.reassembler_backend').setLevel(logging.DEBUG)
    logging.getLogger('binary').setLevel(logging.DEBUG)
    logging.getLogger('angr.analyses.binary_optimizer').setLevel(logging.DEBUG)
    logging.getLogger('techniques.binary_optimization').setLevel(logging.DEBUG)

#
# Functionality tests
#

def run_functionality(filename, save_as=None, optimize=False):

    filepath = os.path.join(bin_location, filename)
    if save_as is None:
        save_as = os.path.join('/', 'tmp', 'functionality', os.path.basename(filename))

    intermediate = None
    if optimize:
        intermediate = save_as + ".intermediate"
        try:
            optimize_it(filepath, intermediate, debugging=True)
        except BinaryOptimizationError:
            print("Optimization failed on file %s" % filepath)
            raise

        # update filepath
        filepath = intermediate

    p = ReassemblerBackend(filepath, debugging=True)
    r = p.save(save_as)

    if intermediate:
        try:
            os.unlink(intermediate)
        except OSError:
            pass

    if not r:
        print("Compiler says:")
        print(p._compiler_stdout)
        print(p._compiler_stderr)

    assert r, 'Reassembler fails on binary %s' % filename

def test_functionality():
    binaries = [
        'CADET_00003',
        'CROMU_00070',
        'CROMU_00071',
        'EAGLE_00005',
    ]

    for b in binaries:
        run_functionality(b)

def manual_run_functionality_all(threads=8, optimize=False):

    # Grab all binaries under binaries-private/cgc_samples_multiflags, and reassemble them

    binaries = []

    for dirname, _, filelist in os.walk(os.path.join(bin_location, 'cgc_samples_multiflags')):
        for b in filelist:
            if '.' in b:
                continue
            p = os.path.normpath(os.path.join('cgc_samples_multiflags', dirname, b))
            binaries.append(p)

    random.shuffle(binaries)

    if threads > 1:
        manager = Manager()
        queue = manager.Queue()
        results = [ ]

        pool = Pool(threads, maxtasksperchild=40)

        pool.map_async(partial(manual_run_functionality_core, optimize=optimize, queue=queue), binaries, chunksize=1)
        pool.close()

        while len(results) != len(binaries):
            time.sleep(0.5)

            # read result from queue
            try:
                data = queue.get_nowait()
            except Queue.Empty:
                continue

            results.append(data)


        # statistics
        for b, r, exc in results:
            if not r:
                print("Fail to process %s: %s" % (b, str(exc)))

    else:
        for b in binaries:
            manual_run_functionality_core(b, optimize=optimize)

def manual_run_functionality_core(b, optimize=False, queue=None):
    #s = "Reassembling %s..." % (b)
    #print s

    filename = os.path.basename(b)
    set_proc_name(filename)

    save_as = os.path.join("/",
                            "tmp",
                            "reassembled_binaries",
                            os.path.basename(b),
                            os.path.basename(os.path.dirname(b)),
                            os.path.basename(b)
                            )
    try:
        run_functionality(b, save_as=save_as, optimize=optimize)

        queue.put((b, True, ''))
        return True
        #print s, "succeeded"

    except AssertionError as ex:
        #print s, "failed"

        queue.put((b, False, str(ex)))
        return False

    except Exception as ex:
        #print s, "failed miserably with an exception: %s" % str(ex)
        #import logging
        #logging.getLogger('a').setLevel(logging.DEBUG)
        #logging.getLogger('a').error('failed miserably...', exc_info=True)

        queue.put((b, False, str(ex)))

        return False

#
# Patching tests
#

def run_shadowstack(filename):
    filepath = os.path.join(bin_location, filename)

    p = ReassemblerBackend(filepath, debugging=True)

    cp = ShadowStack(filepath, p)
    patches = cp.get_patches()

    p.apply_patches(patches)

    r = p.save(os.path.join('/', 'tmp', 'shadowstack', os.path.basename(filename)))

    if not r:
        print("Compiler says:")
        print(p._compiler_stdout)
        print(p._compiler_stderr)

    assert r, 'Shadowstack patching with reassembler fails on binary %s' % filename

def test_shadowstack():
    binaries = [
        'CADET_00003',
        'CROMU_00070',
        'CROMU_00071',
        'EAGLE_00005',
    ]


    for b in binaries:
        run_shadowstack(b)


def run_shiftstack(filename):
    filepath = os.path.join(bin_location, filename)

    p = ReassemblerBackend(filepath, debugging=True)

    patch = ShiftStack(filepath, p)
    patches = patch.get_patches()

    p.apply_patches(patches)

    r = p.save(os.path.join('/', 'tmp', 'shiftstack', os.path.basename(filename)))

    if not r:
        print("Compiler says:")
        print(p._compiler_stdout)
        print(p._compiler_stderr)

    assert r, 'ShiftStack patching with reassembler fails on binary %s' % filename

def test_shiftstack():
    binaries = [
        'CADET_00003',
    ]

    for b in binaries:
        run_shiftstack(b)

def run_adversarial(filename):
    filepath = os.path.join(bin_location, filename)

    p = ReassemblerBackend(filepath, debugging=True)

    patch = Adversarial(filepath, p)
    patches = patch.get_patches()

    p.apply_patches(patches)

    r = p.save(os.path.join('/', 'tmp', 'adversarial', os.path.basename(filename)))

    if not r:
        print("Compiler says:")
        print(p._compiler_stdout)
        print(p._compiler_stderr)

    assert r, 'Adversarial patching with reassembler fails on binary %s' % filename

def disabled_adversarial():
    binaries = [
        'CADET_00003',
    ]

    for b in binaries:
        run_adversarial(b)

def run_optimization(filename):
    filepath = os.path.join(bin_location, filename)

    target_filepath = os.path.join('/', 'tmp', 'optimized_binaries', os.path.basename(filename))
    rr_filepath = target_filepath + ".rr"

    # register reallocation first
    b1 = ReassemblerBackend(filepath, debugging=True)
    cp = BinaryOptimization(filepath, b1, {'register_reallocation'})
    #cp = BinaryOptimization(filepath, b1, {'redundant_stack_variable_removal'})
    patches = cp.get_patches()
    b1.apply_patches(patches)
    r = b1.save(rr_filepath)

    if not r:
        print("Compiler says:")
        print(b1._compiler_stdout)
        print(b1._compiler_stderr)

    # other optimization techniques
    b2 = ReassemblerBackend(rr_filepath, debugging=True)
    #cp = BinaryOptimization(rr_filepath, b2, {'constant_propagation', 'redundant_stack_variable_removal'})
    cp = BinaryOptimization(rr_filepath, b2, {'constant_propagation'})
    patches = cp.get_patches()
    b2.apply_patches(patches)
    r = b2.save(target_filepath)

    if not r:
        print("Compiler says:")
        print(b2._compiler_stdout)
        print(b2._compiler_stderr)

    assert r, 'Optimization fails on binary %s' % filename

def test_optimization():
    binaries = [
        os.path.join('original', 'CROMU_00002'),
    ]

    for b in binaries:
        run_optimization(b)

#
# Tracing
#

def trace():
    import tracer

    b = "/tmp/KPRCA_00025"
    pov = "/home/fish/cgc/benign_traffic/KPRCA_00025/for-testing__GEN_00001.xml"

    tracer = tracer.Tracer(b, pov_file=pov)

#
# MAIN
#

def run_all():
    functions = globals()
    all_functions = dict(filter((lambda x: x[0].startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("-l", "--log", action="store_true",
                        help="Enable logging output from a predefined set of loggers."
                        )
    parser.add_argument("-t", "--test", type=str,
                        help="Specify which test to run.\n"
                        "'--test all' will run all tests."
                        )
    parser.add_argument("-o", "--optimize", action="store_true", default=None,
                        help="Enable binary optimization. Some test cases may not support it."
                        )
    parser.add_argument("--threads", type=int, default=1,
                        help="Number of threads to run tests. Some test cases may not support it."
                        )

    # parse arguments
    args = parser.parse_args()

    if args.log:
        enable_logging()

    optimize = args.optimize
    threads = args.threads
    test = args.test

    if test == 'functionality_all':
        manual_run_functionality_all(threads=threads, optimize=optimize)
    elif test == 'all':
        run_all()
    elif test:
        globals()['test_%s' % test]()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
