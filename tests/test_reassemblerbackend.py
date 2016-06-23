
import os.path

from patcherex.backends import ReassemblerBackend

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries-private'))

#
# Functionality tests
#

def test_CADET_00003():

    filepath = os.path.join(bin_location, 'cgc_trials', 'CADET_00003')

    p = ReassemblerBackend(filepath)
    p.save('/tmp/CADET_00003')

def test_CROMU_00070():

    filepath = os.path.join(bin_location, 'cgc_trials', 'CROMU_00070')

    p = ReassemblerBackend(filepath)
    p.save('/tmp/CADET_00070')

def test_CROMU_00071():

    filepath = os.path.join(bin_location, 'cgc_trials', 'CROMU_00071')

    p = ReassemblerBackend(filepath)
    p.save('/tmp/CADET_00071')

if __name__ == "__main__":
    #test_CADET_00003()
    test_CROMU_00070()
    #test_CROMU_00071()
