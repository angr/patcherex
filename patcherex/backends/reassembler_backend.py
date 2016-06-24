
import logging
import os
import tempfile

import compilerex
from topsecret import Binary

from ..backend import Backend

l = logging.getLogger('reassembler')

class ReassemblerBackend(Backend):
    def __init__(self, filename, debugging=False):

        super(ReassemblerBackend, self).__init__(filename)

        self._debugging = debugging
        self._binary = None

        self._compiler_stdout = None
        self._compiler_stderr = None

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

        l.info("Generating assembly manifest at %s", tmp_file_path)

        # compile it
        #res = compilerex.assemble([ tmp_file_path, '-mllvm', '--x86-asm-syntax=intel', '-o', filename ])
        retcode, res = compilerex.assemble([ tmp_file_path, '-o', filename ])

        self._compiler_stdout, self._compiler_stderr = res

        # Remove the temporary file
        if not self._debugging:
            os.remove(tmp_file_path)

        if retcode == 0:
            return True
        else:
            return False

    def get_final_content(self):
        return ""

    #
    # Private methods
    #

    def _load(self):
        """
        Load and disassemble the binary.
        """

        self._binary = self.project.analyses.Binary(syntax='at&t')
        self._binary.symbolize()
