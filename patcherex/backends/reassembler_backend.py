
import logging
import os
import tempfile
import subprocess

import compilerex
from topsecret import Binary

from ..patches import *
from ..backend import Backend

l = logging.getLogger('reassembler')

class ReassemblerBackend(Backend):
    def __init__(self, filename, debugging=False):

        super(ReassemblerBackend, self).__init__(filename)

        l.info("Reassembling %s...", os.path.basename(filename))
        filesize = os.stat(filename).st_size
        l.info('Original binary: %d bytes', filesize)

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

            elif isinstance(p, PointerArrayPatch):
                self._binary.append_data(p.name, p.data, len(p.data), readonly=False, sort='pointer-array')

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

        # strip the binary
        self._strip(filename)

        if retcode == 0:
            return True
        else:
            return False

    def _strip(self, path):
        """
        Strip the generated CGC binary.

        :param str path: Path to the CGC binary.
        :return: None
        """

        tmp_path = path + ".tmp"

        elf_header = "\177ELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00"

        with open(path, "rb") as f:
            data = f.read()

        l.info("Before stripping: %d bytes", len(data))

        cgc_header = data[ : len(elf_header) ]

        data = elf_header + data[ len(elf_header) : ]

        with open(tmp_path, "wb") as f:
            f.write(data)

        r = subprocess.call(['strip', tmp_path])

        if r != 0:
            l.error("Stripping failed with exit code %d", r)
            return

        with open(tmp_path, "rb") as f1:
            with open(path, "wb") as f2:
                data = f1.read()

                l.info("After stripping: %d bytes", len(data))

                data = cgc_header + data[ len(cgc_header) : ]
                f2.write(data)

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
