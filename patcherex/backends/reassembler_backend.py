
import logging
import os
import tempfile

import compilerex
from topsecret import Binary

from ..patches import *
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
    # Properties
    #

    @property
    def cfg(self):
        return self._binary.cfg

    #
    # Overriding public methods
    #

    def apply_patches(self, patches):
        for p in patches:
            if isinstance(p, InsertCodePatch):
                self._binary.insert_asm(p.addr, p.att_asm())
#
            elif isinstance(p, AddCodePatch):
                self._binary.append_procedure(p.name, p.att_asm())
#
            elif isinstance(p, AddRODataPatch):
                self._binary.append_data(p.name, p.data, len(p.data), readonly=True)
#
            elif isinstance(p, AddRWDataPatch):
                self._binary.append_data(p.name, None, p.len, readonly=False)

            elif isinstance(p, AddEntryPointPatch):
                self._binary.insert_asm(self.project.entry, p.att_asm())

            else:
                raise NotImplementedError()

    def save(self, filename=None):

        # Get the assembly
        assembly = self._binary.assembly(comments=True, symbolized=True)

        # Save the assembly onto a temporary path
        fd, tmp_file_path = tempfile.mkstemp(suffix=".s")
        os.write(fd, assembly)
        os.close(fd)

        l.info("Generating assembly manifest at %s", tmp_file_path)

        dirpath = os.path.dirname(filename)
        try:
            os.makedirs(dirpath, 0755)
        except OSError:
            pass

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
