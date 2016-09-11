import patcherex

import logging
import struct
from patcherex.patches import *

l = logging.getLogger("patcherex.techniques.Packer")

#TODO this should be a subclass of a generic patcher class
class Packer(object):

    def __init__(self,binary_fname,backend):
        self.binary_fname = binary_fname
        self.patcher = backend
        self.oep = self.patcher.get_oep()
        self.original_segments = self.patcher.modded_segments
        self.plen = 0x1000

    def compute_new_segments_layout(self):
        # TODO we could have very weird situations with overlapping segment headers
        # maybe we should at least detect them and do nothing
        def restructure_segment(segment,oep_page):
            # TODO for now we just set the entire segment as "W"
            # the proper way is to split the segment
            # making the entire code writable weakens security only if we make the stack not executable/randomly placed
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = segment
            p_flags |= 0x2
            restructure_segment = p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align
            return [restructure_segment]

        start = size = None
        oep_page = self.oep & 0xfffff000
        found = False
        new_segments = []
        for s in self.original_segments:
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = s
            #only consider LOAD headers
            if p_type == 1 and (self.oep >= p_vaddr and self.oep < (p_vaddr+p_memsz)):
                if found == True:
                    l.error("oep (%08x) is inside multiple segments" % self.oep)
                    return None,start,size
                found = True
                # we have two problems to deal with:
                # we must not xor the elf header and we must not xor past this segment
                elf_header_vaddr = self.patcher.project.loader.main_object.offset_to_addr(0x40)
                start = max(oep_page,elf_header_vaddr)
                pend = oep_page+self.plen
                oend = p_vaddr + p_memsz
                rend = (min(pend,oend)>>2)<<2
                size = rend - start
                new_segments += restructure_segment(s,oep_page)
            else:
                new_segments.append(s)

        if not found:
            l.error("oep (%08x) is outside any segment" % self.oep)
            return None,start,size

        return SegmentHeaderPatch(segment_headers=new_segments,name="packer_segments"),start,size

    def get_patches(self):
        patches = []
        new_segments_patch, start, size = self.compute_new_segments_layout()
        if new_segments_patch == None:
            return []
        patches.append(new_segments_patch)

        key = 0x8ec94134 #mecphish
        original_mem = self.patcher.read_mem_from_file(start, size)
        new_mem = b""
        for i in range(0,len(original_mem),4):
            dw = struct.unpack("<I", original_mem[i:i+4])[0]
            dw ^= key
            new_mem += struct.pack("<I", dw)
        patches.append(RawMemPatch(start, new_mem, name="packer_xored_data"))
        added_code = '''
            mov eax, 0x%08x
            mov ebx, 0x%08x
            mov esi, ebx
            add esi, 0x%08x
            _loop:
                cmp ebx,esi
                jge _exit
                mov edx, DWORD [ebx]
                xor edx, eax
                mov DWORD [ebx], edx
                add ebx, 0x4
                jmp _loop
            _exit:
                ;
        ''' % (key,start,size)

        patches.append(AddEntryPointPatch(added_code, name="packer_unpack_code"))

        return patches


def init_technique(program_name, backend, options):
    return Packer(program_name, backend, **options)
