
import os
import tempfile

import compilerex
from topsecret import Binary

from ..backend import Backend

class ReassemblerBackend(Backend):
    def __init__(self, filename):

        super(ReassemblerBackend, self).__init__(filename)

        self._binary = None

        self._load()

    #
    # Overriding public methods
    #

    def apply_patches(self, patches):
        pass

    def save(self, filename=None):

        # Get the assembly
        assembly = self._binary.assembly(comments=True, symbolized=True)

        # Save the assembly onto a temporary path
        fd, tmp_file_path = tempfile.mkstemp(suffix=".s")
        os.write(fd, assembly)
        os.close(fd)

        print tmp_file_path

        # compile it
        res = compilerex.compile([ tmp_file_path, '-mllvm', '--x86-asm-syntax=intel', '-o', filename ])

        print res[0]
        print res[1]

        # Remove the temporary file
        # os.remove(tmp_file_path)

    def get_final_content(self):
        return ""

    #
    # Private methods
    #

    def _load(self):
        """
        Load and disassemble the binary.
        """

        self._binary = self.project.analyses.Binary()
        self._binary.symbolize()
