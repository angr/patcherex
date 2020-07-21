
import logging
import os
import tempfile
import subprocess

l = logging.getLogger('patcherex.backends.reassembler_backend')

try:
    import compilerex
except ImportError:
    l.warning('Cannot import compilerex. Reassembler backend will not be able to recompile assembly files.')

from angr.analyses.reassembler import BinaryError

from ..patches import *
from ..backend import Backend
from ..errors import ReassemblerError, CompilationError, ReassemblerNotImplementedError
from ..utils import bytes_overwrite
from .misc import ASM_ENTRY_POINT_PUSH_ENV, ASM_ENTRY_POINT_RESTORE_ENV

class ReassemblerBackend(Backend):
    def __init__(self, filename, debugging=False, try_pdf_removal=True, extra_compiler_options=None):

        super(ReassemblerBackend, self).__init__(filename, try_pdf_removal=try_pdf_removal)

        l.info("Reassembling %s...", os.path.basename(filename))
        filesize = os.stat(filename).st_size
        l.info('Original binary: %d bytes', filesize)

        self._debugging = debugging
        self._binary = None

        self._compiler_stdout = None
        self._compiler_stderr = None
        self.extra_compile_options = extra_compiler_options

        self._raw_file_patches = [ ]
        self._add_segment_patches = [ ]

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

        entry_point_asm_before_restore = [ ]
        entry_point_asm_after_restore = [ ]

        syntax = compilerex.get_preferred_syntax(self.filename)
        for p in patches:
            if isinstance(p, InsertCodePatch):
                code = p.att_asm(c_as_asm=True) if syntax == "at&t" else p.intel_asm(c_as_asm=True)
                self._binary.insert_asm(p.addr, code)
#
            elif isinstance(p, AddCodePatch):
                code = p.att_asm(c_as_asm=True) if syntax == "at&t" else p.intel_asm(c_as_asm=True)
                self._binary.append_procedure(p.name, code)
#
            elif isinstance(p, AddRODataPatch):
                self._binary.append_data(p.name, p.data, len(p.data), readonly=True)
#
            elif isinstance(p, AddRWDataPatch):
                self._binary.append_data(p.name, None, p.len, readonly=False)

            elif isinstance(p, AddEntryPointPatch):
                code = p.att_asm(c_as_asm=True) if syntax == "at&t" else p.intel_asm(c_as_asm=True)
                if p.after_restore:
                    entry_point_asm_after_restore.append(code)
                else:
                    entry_point_asm_before_restore.append(code)

            elif isinstance(p, PointerArrayPatch):
                self._binary.append_data(p.name, p.data, len(p.data), readonly=False, sort='pointer-array')

            elif isinstance(p, RawFilePatch):
                self._raw_file_patches.append(p)

            elif isinstance(p, AddSegmentHeaderPatch):
                self._add_segment_patches.append(p)

            elif isinstance(p, AddLabelPatch):
                self._binary.add_label(p.name, p.addr, is_global=p.is_global)

            elif isinstance(p, RemoveInstructionPatch):
                self._binary.remove_instruction(p.ins_addr)

            else:
                raise ReassemblerNotImplementedError('ReassemblerBackend does not support patch %s. '
                                                     'Please bug Fish to implement it.' % type(p)
                                                     )

        if entry_point_asm_before_restore:
            entry_point_asm_before_restore = [ ASMConverter.intel_to_att(ASM_ENTRY_POINT_PUSH_ENV) ] + \
                                             entry_point_asm_before_restore + \
                                             [ ASMConverter.intel_to_att(ASM_ENTRY_POINT_RESTORE_ENV) ]
        entry_point_asm = entry_point_asm_before_restore + entry_point_asm_after_restore
        if entry_point_asm:
            self._binary.insert_asm(self.project.entry, "\n".join(entry_point_asm))

    def save(self, filename=None):

        # Get the assembly
        try:
            assembly = self._binary.assembly(comments=True, symbolized=True)  # type: str
        except BinaryError as ex:
            raise ReassemblerError('Reassembler failed to reassemble the binary. Here is the exception we '
                                   'caught: %s' %
                                   str(ex)
                                   )

        # Save the assembly onto a temporary path
        fd, tmp_file_path = tempfile.mkstemp(prefix=os.path.basename(self.project.filename), suffix=".s")
        os.write(fd, assembly.encode("utf-8"))
        os.close(fd)

        l.info("Generating assembly file at %s", tmp_file_path)

        dirpath = os.path.dirname(filename)
        try:
            os.makedirs(dirpath, 0o755)
        except OSError:
            pass

        # compile it
        #res = compilerex.assemble([ tmp_file_path, '-mllvm', '--x86-asm-syntax=intel', '-o', filename ])
        #base_args = compilerex.get_clang_args(self.filename)
        #retcode, res = compilerex.assemble(base_args + [ tmp_file_path, '-o', filename ])
        retcode, res = compilerex.auto_assemble(self.filename, tmp_file_path, filename,
                                                self.extra_compile_options)

        self._compiler_stdout, self._compiler_stderr = res

        if retcode != 0:
            raise CompilationError("File: %s Error: %s" % (tmp_file_path,res))

        # Remove the temporary file
        if not self._debugging:
            os.remove(tmp_file_path)

        # strip the binary
        self._strip(filename)

        # apply raw file patches
        self._apply_raw_file_patches(filename)

        # add segments
        if self._add_segment_patches:
            self._add_segments(filename,self._add_segment_patches)

        return True

    def _add_segments(self, filename, patches):
        fp = open(filename, "rb")
        content = fp.read()
        fp.close()

        # dump the original segments
        old_segments = []
        header_size = 16 + 2*2 + 4*5 + 2*6
        buf = content[0:header_size]
        (cgcef_type, cgcef_machine, cgcef_version, cgcef_entry, cgcef_phoff,
            cgcef_shoff, cgcef_flags, cgcef_ehsize, cgcef_phentsize, cgcef_phnum,
            cgcef_shentsize, cgcef_shnum, cgcef_shstrndx) = struct.unpack("<xxxxxxxxxxxxxxxxHHLLLLLHHHHHH", buf)
        phent_size = 8 * 4
        assert cgcef_phnum != 0
        assert cgcef_phentsize == phent_size
        pt_types = {0: "NULL", 1: "LOAD", 6: "PHDR", 0x60000000+0x474e551: "GNU_STACK", 0x6ccccccc: "CGCPOV2"}
        segments = []
        for i in range(0, cgcef_phnum):
            hdr = content[cgcef_phoff + phent_size * i:cgcef_phoff + phent_size * i + phent_size]
            (p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align) = struct.unpack("<IIIIIIII", hdr)
            assert p_type in pt_types
            old_segments.append((p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align))

        # align size of the entire ELF
        content = utils.pad_bytes(content, 0x10)
        # change pointer to program headers to point at the end of the elf
        content = utils.bytes_overwrite(content, struct.pack("<I", len(content)), 0x1C)

        new_segments = [p.new_segment for p in patches]
        all_segments = old_segments + new_segments

        # add all segments at the end of the file
        for segment in all_segments:
            content = utils.bytes_overwrite(content, struct.pack("<IIIIIIII", *segment))

        # we overwrite the first original program header,
        # we do not need it anymore since we have moved original program headers at the bottom of the file
        content = utils.bytes_overwrite(content, b"SHELLPHISH\x00", 0x34)

        # set the total number of segment headers
        content = utils.bytes_overwrite(content, struct.pack("<H", len(all_segments)), 0x2c)

        # update the file
        fp = open(filename,"wb")
        fp.write(content)
        fp.close()

    def _strip(self, path):
        """
        Strip the generated CGC binary.

        :param str path: Path to the CGC binary.
        :return: None
        """

        tmp_path = path + ".tmp"

        elf_header = b"\177ELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00"

        with open(path, "rb") as f:
            data = f.read()

        l.info("Before stripping: %d bytes", len(data))

        if data.startswith(b"\x7fCGC"):
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

            os.remove(tmp_path)
        else:
            r = subprocess.call(["strip", path])
            if r != 0:
                l.error("Stripping failed with exit code %d", r)
                return


    def _apply_raw_file_patches(self, filename):
        """
        Apply raw file patches on the patched binary.

        :param str filename: File path of the patched binary.
        :return: None
        """

        if not self._raw_file_patches:
            return

        with open(filename, "rb") as f:
            data = f.read()

        for p in self._raw_file_patches:  # type: RawFilePatch
            data = bytes_overwrite(data, p.data, p.file_addr)

        with open(filename, "wb") as f:
            f.write(data)

    def get_final_content(self):
        """
        Get the content of the patched binary.

        :return: Content of the patched binary.
        :rtype: str
        """

        # Save the binary at a temporary path
        fd, tmp_file_path = tempfile.mkstemp(prefix='reassembler_')
        os.close(fd)

        r = self.save(tmp_file_path)

        if not r:
            raise ReassemblerError('Reassembler fails. '
                                   'The compiler says: %s\n%s' % (self._compiler_stdout, self._compiler_stderr)
                                   )

        with open(tmp_file_path, "rb") as f:
            return f.read()

    #
    # Private methods
    #

    def _load(self):
        """
        Load and disassemble the binary.
        """
        syntax = compilerex.get_preferred_syntax(self.filename)
        try:
            self._binary = self.project.analyses.Reassembler(syntax=syntax, remove_cgc_attachments=self.try_pdf_removal)
            self._binary.symbolize()
            self._binary.remove_unnecessary_stuff()
        except BinaryError as ex:
            raise ReassemblerError('Reassembler failed to load the binary. Here is the exception we caught: %s' %
                                   str(ex)
                                   )


def init_backend(program_name, options):
    return ReassemblerBackend(program_name, **options)
