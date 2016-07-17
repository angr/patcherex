#!/usr/bin/env python

import os.path
import random
from multiprocessing import Pool

import nose.tools

from patcherex.backends import ReassemblerBackend
from patcherex.patches import *
from patcherex.techniques import ShadowStack, SimplePointerEncryption, ShiftStack, Adversarial

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries-private'))

#
# Functionality tests
#

def run_functionality(filename, save_as=None):

    filepath = os.path.join(bin_location, filename)
    if save_as is None:
        save_as = os.path.join('/', 'tmp', os.path.basename(filename))

    p = ReassemblerBackend(filepath, debugging=True)
    r = p.save(save_as)

    if not r:
        print "Compiler says:"
        print p._compiler_stdout
        print p._compiler_stderr

    nose.tools.assert_true(r, 'Reassembler fails on binary %s' % filename)

def test_functionality():
    binaries = [
        os.path.join('cgc_trials', 'CADET_00003'),
        os.path.join('cgc_trials', 'CROMU_00070'),
        os.path.join('cgc_trials', 'CROMU_00071'),
        os.path.join('cgc_trials', 'EAGLE_00005'),
    ]

    for b in binaries:
        run_functionality(b)

def manual_run_functionality_all(threads=8):

    # Grab all binaries under binaries-private/cgc_samples_multiflags, and reassemble them

    binaries = []

    for dirname, dirlist, filelist in os.walk(os.path.join(bin_location, 'cgc_samples_multiflags')):
        for b in filelist:
            if '.' in b:
                continue
            p = os.path.normpath(os.path.join('cgc_samples_multiflags', dirname, b))
            binaries.append(p)

    random.shuffle(binaries)

    if threads > 1:
        pool = Pool(threads, maxtasksperchild=10)
        pool.map(manual_run_functionality_core, binaries, chunksize=1)
        pool.close()
        pool.join()

    else:
        manual_run_functionality_core(binaries)

def set_proc_name(procname):

    # for the ease of debugging...
    # you can see the new name via "ps -A"

    from ctypes import cdll, byref, create_string_buffer
    libc = cdll.LoadLibrary('libc.so.6')
    buff = create_string_buffer(len(procname) + 1)
    buff.value = procname
    libc.prctl(15, byref(buff), 0, 0, 0)

def manual_run_functionality_core(b):
    s = "Reassembling %s..." % (b)
    print s

    filename = os.path.basename(s)
    set_proc_name(filename)


    save_as = os.path.join("/",
                            "tmp",
                            "reassembled_binaries",
                            os.path.basename(b),
                            os.path.basename(os.path.dirname(b)),
                            os.path.basename(b)
                            )
    try:
        run_functionality(b, save_as=save_as)
        print s, "succeeded"
    except AssertionError:
        print s, "failed"
    except Exception as ex:
        print s, "failed miserably with an exception: %s" % str(ex)

#
# Patching tests
#

def run_shadowstack(filename):
    filepath = os.path.join(bin_location, filename)

    p = ReassemblerBackend(filepath, debugging=True)

    cp = ShadowStack(filepath, p)
    patches = cp.get_patches()

    p.apply_patches(patches)

    r = p.save(os.path.join('/', 'tmp', os.path.basename(filename)))

    if not r:
        print "Compiler says:"
        print p._compiler_stdout
        print p._compiler_stderr

    nose.tools.assert_true(r, 'Shadowstack patching with reassembler fails on binary %s' % filename)

def test_shadowstack():
    binaries = [
        os.path.join('cgc_trials', 'CADET_00003'),
        os.path.join('cgc_trials', 'CROMU_00070'),
        os.path.join('cgc_trials', 'CROMU_00071'),
        os.path.join('cgc_trials', 'EAGLE_00005'),
    ]

    for b in binaries:
        run_shadowstack(b)

def run_simple_pointer_encryption(filename):
    filepath = os.path.join(bin_location, filename)

    p = ReassemblerBackend(filepath, debugging=True)

    cp = SimplePointerEncryption(filepath, p, optimize=True)
    patches = cp.get_patches()

    p.apply_patches(patches)

    r = p.save(os.path.join('/', 'tmp', os.path.basename(filename)))

    if not r:
        print "Compiler says:"
        print p._compiler_stdout
        print p._compiler_stderr

    nose.tools.assert_true(r, 'SimplePointerEncryption patching with reassembler fails on binary %s' % filename)

def test_simple_pointer_encryption():
    binaries = [
        os.path.join('cgc_trials', 'CADET_00003'),
        os.path.join('cgc_trials', 'CROMU_00070'),
        os.path.join('cgc_trials', 'CROMU_00071'),
        # os.path.join('cgc_trials', 'EAGLE_00005'),
        #  os.path.join('cgc_samples_multiflags', 'CROMU_00001', 'original', 'CROMU_00001'),
    ]

    for b in binaries:
        run_simple_pointer_encryption(b)

def run_shiftstack(filename):
    filepath = os.path.join(bin_location, filename)

    p = ReassemblerBackend(filepath, debugging=True)

    patch = ShiftStack(filepath, p)
    patches = patch.get_patches()

    p.apply_patches(patches)

    r = p.save(os.path.join('/', 'tmp', os.path.basename(filename)))

    if not r:
        print "Compiler says:"
        print p._compiler_stdout
        print p._compiler_stderr

    nose.tools.assert_true(r, 'ShiftStack patching with reassembler fails on binary %s' % filename)

def test_shiftstack():
    binaries = [
        os.path.join('cgc_trials', 'CADET_00003'),
    ]

    for b in binaries:
        run_shiftstack(b)

def run_adversarial(filename):
    filepath = os.path.join(bin_location, filename)

    p = ReassemblerBackend(filepath, debugging=True)

    patch = Adversarial(filepath, p)
    patches = patch.get_patches()

    p.apply_patches(patches)

    r = p.save(os.path.join('/', 'tmp', os.path.basename(filename)))

    if not r:
        print "Compiler says:"
        print p._compiler_stdout
        print p._compiler_stderr

    nose.tools.assert_true(r, 'Adversarial patching with reassembler fails on binary %s' % filename)

def disabled_adversarial():
    binaries = [
        os.path.join('cgc_trials', 'CADET_00003'),
    ]

    for b in binaries:
        run_adversarial(b)

#
# Tracing
#

def trace():
    import tracer

    b = "/tmp/KPRCA_00025"
    pov = "/home/fish/cgc/benign_traffic/KPRCA_00025/for-testing__GEN_00001.xml"

    tracer = tracer.Tracer(b, pov_file=pov)

if __name__ == "__main__":
    import logging
    logging.getLogger('reassembler').setLevel(logging.DEBUG)

    # trace()
    # manual_run_functionality_all(threads=8)
    test_simple_pointer_encryption()
    test_functionality()
    test_shadowstack()
    test_shiftstack()
    # test_adversarial()
    pass
