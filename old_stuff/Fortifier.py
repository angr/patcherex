
import utils
import struct
import os

import IPython


import logging
l = logging.getLogger('cgrex.Fortifier')


class InvalidVAddrException(Exception):
    pass


class FortifierException(Exception):
    pass


class DetourException(Exception):
    pass


class Fortifier:

    fortify_segment1_base = 0x09000000
    fortify_segment2_base = 0x09100000
    fortified_tag = "FORTIFIED\x00"  # should not be longer than 0x20

    def __init__(self, fname, base_code=""):
        self.fname = fname
        self.ocontent = open(fname, "rb").read()
        etype = utils.exe_type(self.ocontent)
        assert etype is not None
        if etype == "ELF":
            self.ocontent = utils.elf_to_cgc(self.ocontent)
        self.ncontent = self.ocontent
        self.segments = None
        if self.has_fortify_segment():
            self.injected_code = self.get_injected_code()
            self.first_patch = False
        else:
            self.setup_headers()
            self.injected_code = base_code
            self.first_patch = True

    def save(self, nname, both_formats=False):
        if self.first_patch:
            self.set_fortify_segment(self.injected_code)
        else:
            self.update_fortify_segment(self.injected_code)
        if both_formats:
            self.ncontent = utils.cgc_to_elf(self.ncontent)
            open(nname,"wb").write(self.ncontent)
            os.chmod(nname+"_cgc",0755)
            self.ncontent = utils.elf_to_cgc(self.ncontent)
            open(nname,"wb").write(self.ncontent)
            os.chmod(nname+"_elf",0755)
        else:
            open(nname,"wb").write(self.ncontent)
            os.chmod(nname,0755) #rwxr-xr-x


    def pflags_to_perms(self,p_flags):
        PF_X = (1 << 0)
        PF_W = (1 << 1)
        PF_R = (1 << 2)

        perms = ""
        if p_flags & PF_R:
            perms = perms + "R"
        if p_flags & PF_W:
            perms = perms + "W"
        if p_flags & PF_X:
            perms = perms + "X"
        return perms


    def dump_segments(self,tprint=False):
        #from: https://github.com/CyberGrandChallenge/readcgcef/blob/master/readcgcef-minimal.py
        header_size = 16 + 2*2 + 4*5 + 2*6
        buf = self.ncontent[0:header_size]
        (cgcef_type, cgcef_machine, cgcef_version, cgcef_entry, cgcef_phoff,
                cgcef_shoff, cgcef_flags, cgcef_ehsize, cgcef_phentsize, cgcef_phnum,
                cgcef_shentsize, cgcef_shnum, cgcef_shstrndx) = struct.unpack("<xxxxxxxxxxxxxxxxHHLLLLLHHHHHH", buf)
        phent_size = 8 * 4
        assert cgcef_phnum != 0
        assert cgcef_phentsize == phent_size

        pt_types = {0:"NULL",1:"LOAD",6:"PHDR",0x60000000+0x474e551:"GNU_STACK",0x6ccccccc:"CGCPOV2"}
        segments = []
        for i in xrange(0, cgcef_phnum):
            hdr = self.ncontent[cgcef_phoff + phent_size * i:cgcef_phoff + phent_size * i + phent_size]
            (p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags,p_align) = struct.unpack("<IIIIIIII", hdr)
            if tprint:
                print (p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align)

            assert p_type in pt_types
            ptype_str = pt_types[p_type]

            strp = self.pflags_to_perms(p_flags)
            if "W" == strp or "WX" == strp or "XW" == strp:
                raise FortifierException("This binary has weird permissions on a segment, I cannot safely touch it: %s"%strp)
            segments.append((p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align))

            if tprint:
                print "---"
                print "Type: %s"%ptype_str
                print "Permissions: %s" % self.pflags_to_perms(p_flags)
                print "Memory: 0x%x + 0x%x" % (p_vaddr, p_memsz)
                print "File: 0x%x + 0x%x" % (p_offset, p_filesz)

        self.segments = segments
        return segments


    def get_memory_permissions(self,address):
        address = address & 0xfffff000
        load_segments = [s for s in reversed(self.segments) if s[0]==1] #LOAD    
        for s in load_segments:
            vaddr_start_page = s[2] & 0xfffffff000
            vaddr_end_page = ((s[2] + s[5] - 1) & 0xfffffff000) + 0x1000
            if address >= vaddr_start_page and address < vaddr_end_page:
                return self.pflags_to_perms(s[6])
        return ""


    def has_fortify_segment(self):
        segments = self.dump_segments()
        segment_vaddrs = [s[2] for s in segments]
        if Fortifier.fortify_segment1_base in segment_vaddrs:
            return True
        else:
            return False


    def setup_headers(self):
        if self.has_fortify_segment():
            return

        segments = self.dump_segments()

        # align size of the entire ELF
        self.ncontent = utils.pad_str(self.ncontent, 0x10)
        # change pointer to program headers to point at the end of the elf
        self.ncontent = utils.str_overwrite(self.ncontent,struct.pack("<I", len(self.ncontent)), 0x1C)

        # copying original program headers in the new place (at the end of the file)
        for segment in segments:
            self.ncontent = utils.str_overwrite(self.ncontent,struct.pack("<IIIIIIII",*segment))

        # we overwrite the first original program header,
        # we do not need it anymore since we have moved original program headers at the bottom of the file
        self.ncontent = utils.str_overwrite(self.ncontent, self.fortified_tag, 0x34)


    def set_oep(self, new_oep):
        self.ncontent = utils.str_overwrite(self.ncontent,struct.pack("<I", new_oep), 0x18)


    def get_oep(self):
        return struct.unpack("<I",self.ncontent[0x18:0x18+4])[0]


    def maddress_to_baddress(self,maddress):
        assert self.segments != None

        load_segments = [s for s in reversed(self.segments) if s[0]==1] #LOAD    
        for s in load_segments:
            paddr_page = s[1] & 0xfffffff000
            vaddr_start_page = s[2] & 0xfffffff000
            vaddr_end_page = ((s[2] + s[5] - 1) & 0xfffffff000) + 0x1000
            #TODO double check these formulas with tricky non-aligned cases
            if maddress >= vaddr_start_page and maddress < vaddr_end_page:
                #regardless to what is written in the header, everything is page aligned (for mmap reasons)
                #print hex(paddr_page),hex(vaddr_start_page),hex(vaddr_end_page)
                return (maddress - vaddr_start_page) + paddr_page
        raise(InvalidVAddrException(hex(maddress)))


    def get_memory_translation_list(self,address,size,permissive=False):
        start = address
        end = address+size-1 #we will take the byte at end
        #print hex(start),hex(end)
        start_p = address & 0xfffffff000
        end_p = end & 0xfffffff000
        if start_p==end_p:
            return [(self.maddress_to_baddress(start),self.maddress_to_baddress(end)+1)]
        else:
            first_page_baddress = self.maddress_to_baddress(start)
            mlist = []
            mlist.append((first_page_baddress,(first_page_baddress & 0xfffffff000)+0x1000))
            nstart = (start & 0xfffffff000)+0x1000
            try:
                while nstart != end_p:
                    mlist.append((self.maddress_to_baddress(nstart),self.maddress_to_baddress(nstart)+0x1000))
                    nstart += 0x1000
                mlist.append((self.maddress_to_baddress(nstart),self.maddress_to_baddress(end)+1))
            except InvalidVAddrException, e:
                if permissive:
                    return mlist
                else:
                    raise e
            return mlist


    def get_maddress(self,address,size,permissive=False):
        mem = ""
        for start,end in self.get_memory_translation_list(address,size):
            #print "-",hex(start),hex(end)
            mem += self.ncontent[start:end]
        return mem


    def patch_bin(self,address,new_content):
        ndata_pos = 0
        for start,end in self.get_memory_translation_list(address,len(new_content)):
            #print "-",hex(start),hex(end)
            ndata = new_content[ndata_pos:ndata_pos+(end-start)]
            self.ncontent = utils.str_overwrite(self.ncontent,ndata,start)
            ndata_pos += len(ndata)
        

    def insert_detour(self,target,patch):
        def check_if_movable(instruction):
            #the idea here is an instruction is movable if and only if
            #it has the same string representation when moved at different offsets is "movable"
            def bytes_to_comparable_str(ibytes,offset):
                return " ".join(utils.instruction_to_str(utils.decompile(ibytes,offset)[0]).split()[2:])

            instruction_bytes = str(instruction.bytes)
            pos1 = bytes_to_comparable_str(instruction_bytes,0x0)
            pos2 = bytes_to_comparable_str(instruction_bytes,0x07f00000)
            pos3 = bytes_to_comparable_str(instruction_bytes,0xfe000000)
            print pos1,pos2,pos3
            if pos1 == pos2 and pos2 == pos3:
                return True
            else:
                return False

        #IPython.embed()
        culprit_address = patch['culprit_address']
        bbstart = patch['bbstart']
        bbsize = patch['bbsize']
        patch_code = patch['code']

        l.debug("inserting detour for patch: %s"%(map(hex,(bbstart,bbsize,culprit_address))))

        detour_size = 5
        detour_attempts = range(-1*detour_size,0+1)
        one_byte_nop = '\x90'

        #get movable_instructions in the bb
        original_bbcode = self.get_maddress(bbstart,bbsize)
        instructions = utils.decompile(original_bbcode,bbstart)
        assert any([culprit_address == i.address for i in instructions])

        #the last instruction may be not movable (a direct call or jmp)
        #given the definition of bb, only the last instruction may be non-movable
        #TODO moving an indirect call or a ret is still scary and should be tested,
        #because performing a call not from the origianl position changes what is going on the stack
        if check_if_movable(instructions[-1]):
            movable_instructions = instructions
        else:
            movable_instructions = instructions[:-1]

        if len(movable_instructions)==0:
            raise DetourException("No movable instructions found")
        movable_bb_start = movable_instructions[0].address
        movable_bb_size = reduce(lambda t,n:t+len(str(n.bytes)),movable_instructions,0)
        print "movable_bb_size:",movable_bb_size
        print "movable bb instructions:"
        print "\n".join([utils.instruction_to_str(i) for i in movable_instructions])

        #find a spot for the detour
        detour_pos = None
        for pos in detour_attempts:
            detour_start = culprit_address + pos
            detour_end = detour_start + detour_size - 1
            if detour_start >= movable_bb_start and detour_end < (movable_bb_start + movable_bb_size):
                detour_pos = detour_start
                break
        if detour_pos == None:
            raise DetourException("No space in bb",hex(bbstart),hex(bbsize),hex(movable_bb_start),hex(movable_bb_size))
        else:
            print "detour fits at",hex(detour_pos)
        detour_overwritten_bytes = range(detour_pos,detour_pos+detour_size)
        #print "ob"," ".join(map(hex,detour_overwritten_bytes))

        #detect overwritten instruction
        for i in movable_instructions:
            if len(set(detour_overwritten_bytes).intersection(set(range(i.address,i.address+len(i.bytes)))))>0:
                if i.address < culprit_address:
                    i.overwritten = "pre"
                elif i.address == culprit_address:
                    i.overwritten = "culprit"
                else:
                    i.overwritten = "post"
            else:
                i.overwritten = "out"                    
        print "\n".join([utils.instruction_to_str(i) for i in movable_instructions])
        assert any([i.overwritten!="out" for i in movable_instructions])

        #patch bb code
        for i in movable_instructions:
            if i.overwritten != "out":
                self.patch_bin(i.address,one_byte_nop*len(i.bytes))
        detour_jmp_code = utils.compile_jmp(detour_pos,target)
        self.patch_bin(detour_pos,detour_jmp_code)
        patched_bbcode = self.get_maddress(bbstart,bbsize)
        patched_bbinstructions = utils.decompile(patched_bbcode,bbstart)
        print "patched bb instructions:"
        print "\n".join([utils.instruction_to_str(i) for i in patched_bbinstructions])

        #create injected_code (pre, injected, culprit, post, jmp_back)
        injected_code = ""
        injected_code += "\n"+"nop\n"*5+"\n"
        injected_code += "\n".join([utils.capstone_to_nasm(i) for i in movable_instructions if i.overwritten=='pre'])+"\n"
        injected_code += "; --- custom code start\n"+patch['code']+"\n"+"; --- custom code end\n"+"\n"
        injected_code += "\n".join([utils.capstone_to_nasm(i) for i in movable_instructions if i.overwritten=='culprit'])+"\n"
        injected_code += "\n".join([utils.capstone_to_nasm(i) for i in movable_instructions if i.overwritten=='post'])+"\n"
        jmp_back_target = None
        for i in reversed(movable_instructions): #jmp back to the one after the last byte of the last non-out
            if i.overwritten != "out":
                jmp_back_target = i.address+len(str(i.bytes))
                break
        assert jmp_back_target != None
        injected_code += "jmp %s"%hex(int(jmp_back_target))+"\n"
        injected_code = "\n".join([line for line in injected_code.split("\n") if line!= ""]) #removing blank lines as a pro
        print "injected code:"
        print injected_code

        self.injected_code += utils.compile_asm(injected_code,base=Fortifier.fortify_segment1_base+len(self.injected_code))


    def get_injected_code(self):
        assert self.has_fortify_segment()
        segments = self.dump_segments()
        fortify_segment_info = [s for s in segments if s[2] == Fortifier.fortify_segment1_base][0]
        return self.ncontent[fortify_segment_info[1]:]


    def set_fortify_segment(self,code_segment):

        assert self.ncontent[0x34:0x34+len(self.fortified_tag)] == self.fortified_tag

        code_segment = utils.pad_str(code_segment,0x10)
        start_new_segment = len(utils.pad_str(self.ncontent + " "*0x20,0x1000))
        code_segment_header = (1, start_new_segment, self.fortify_segment1_base, self.fortify_segment1_base, \
                len(code_segment), len(code_segment), 0x7, 0x0) #RWX
        data_segment_header = (1, 0, self.fortify_segment2_base, self.fortify_segment2_base, \
                0, 0x1000, 0x6, 0x0) #RW
        self.ncontent = utils.str_overwrite(self.ncontent,struct.pack("<IIIIIIII",*code_segment_header))
        self.ncontent = utils.str_overwrite(self.ncontent,struct.pack("<IIIIIIII",*data_segment_header))
        original_nsegments = struct.unpack("<H",self.ncontent[0x2c:0x2c+2])[0]
        self.ncontent = utils.str_overwrite(self.ncontent,struct.pack("<H",original_nsegments + 2),0x2c)

        #In theory you can have segment not 0x1000 aligned, however elf to mem translation gets complicated
        self.ncontent = utils.pad_str(self.ncontent,0x1000)
        self.ncontent = utils.str_overwrite(self.ncontent,code_segment)

        #print self.dump_segments(tprint=True)


    def update_fortify_segment(self,code_segment):

        assert self.ncontent[0x34:0x34+len(self.fortified_tag)] == self.fortified_tag

        segments = self.dump_segments()
        fortify_segment_info = [s for s in segments if s[2] == Fortifier.fortify_segment1_base][0]
        injected_code_start = fortify_segment_info[1]

        start_new_segment = injected_code_start
        code_segment_header = (1, start_new_segment, self.fortify_segment1_base, self.fortify_segment1_base, \
                len(code_segment), len(code_segment), 0x7, 0x0) #RWX

        header_size = 16 + 2*2 + 4*5 + 2*6
        buf = self.ncontent[0:header_size]
        (cgcef_type, cgcef_machine, cgcef_version, cgcef_entry, cgcef_phoff,
                cgcef_shoff, cgcef_flags, cgcef_ehsize, cgcef_phentsize, cgcef_phnum,
                cgcef_shentsize, cgcef_shnum, cgcef_shstrndx) = struct.unpack("<xxxxxxxxxxxxxxxxHHLLLLLHHHHHH", buf)
        phent_size = 8 * 4
        for i in xrange(0, cgcef_phnum):
            pos = cgcef_phoff + phent_size * i
            hdr = self.ncontent[pos:pos+phent_size]
            (p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags,p_align) = struct.unpack("<IIIIIIII", hdr)
            if p_vaddr == Fortifier.fortify_segment1_base:
                break
        self.ncontent = utils.str_overwrite(self.ncontent,struct.pack("<IIIIIIII",*code_segment_header),pos)

        self.ncontent = utils.pad_str(self.ncontent,0x1000)
        self.ncontent = self.ncontent[:start_new_segment]+code_segment

        #print self.dump_segments(tprint=True)




