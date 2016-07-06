
import os.path
import multiprocessing

import nose.tools

from patcherex.backends import ReassemblerBackend
from patcherex.patches import *
from patcherex.techniques import ShadowStack, SimplePointerEncryption

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

    if threads > 1:

        process_objects = [ ]
        for thread_id in xrange(threads):
            p = multiprocessing.Process(target=manual_run_functionality_core, args=(binaries, thread_id, threads))
            process_objects.append(p)

            p.start()

        for p in process_objects:
            p.join()

    else:
        manual_run_functionality_core(binaries, 0, 1)

def manual_run_functionality_core(binaries, thread_id, all_threads):
    for i, b in enumerate(binaries):
        if (i + thread_id) % all_threads != 0:
            continue

        s = "[%02d] Reassembling %s..." % (thread_id, b)
        print s

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

    cp = SimplePointerEncryption(filepath, p)
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
        os.path.join('cgc_trials', 'EAGLE_00005'),
    ]

    for b in binaries:
        run_simple_pointer_encryption(b)

if __name__ == "__main__":
    import logging
    logging.getLogger('reassembler').setLevel(logging.DEBUG)

    test_simple_pointer_encryption()
    # manual_run_functionality_all()
    #test_functionality()
    #test_shadowstack()
