from pwn import *
import keystone
import ctypes
import shutil
import struct

class Patcher:
    def __init__(self,path):
        self.path = path
        self.save_path = path + "_patch"
        self.binary = ELF(self.path)
        self.bits = self.binary.bits
        self.pie = self.binary.pie
        self.endian = self.binary.endian
        self.arch = self.binary.arch
        context.arch = self.arch
        if self.bits != 32 and self.bits != 64:
            print("Sorry, the architecture of program is neither 32-bit or 64-bit.")
            quit()
        if self.arch == "arm":
            self.ks_arch = keystone.KS_ARCH_ARM
            self.ks_mode = keystone.KS_MODE_ARM
        elif self.arch == "aarch64":
            self.ks_arch = keystone.KS_ARCH_ARM64
            self.ks_mode = 0
        elif self.arch == "i386" or self.arch == "amd64":
            self.ks_arch = keystone.KS_ARCH_X86
            self.ks_mode = keystone.KS_MODE_32 if self.bits == 32 else keystone.KS_MODE_64
        elif self.arch == "mips" or self.arch == "mips64":
            self.ks_arch = keystone.KS_ARCH_MIPS
            self.ks_mode = keystone.KS_MODE_MIPS32 if self.bits == 32 else keystone.KS_MODE_MIPS64
        if self.endian == "little":
            self.ks_mode |= keystone.KS_MODE_LITTLE_ENDIAN
        else:
            self.ks_mode |= keystone.KS_MODE_BIG_ENDIAN
        self.ks = keystone.Ks(self.ks_arch, self.ks_mode)
        self.eh_frame_section = self.binary.get_section_by_name(".eh_frame")
        self.eh_frame_addr = self.eh_frame_section.header.sh_addr
        self.eh_frame_size = self.eh_frame_section.header.sh_size
        self.offset = 0
        self.inject_addr = self.eh_frame_addr
        self.adjust_eh_frame_size()
        self.fix_eh_frame_flags()
    def adjust_eh_frame_size(self):
        if self.arch == "arm" or self.arch == "aarch64" or self.arch == "mips" or self.arch == "mips64":
            PAGE_SIZE = 0x1000
            for i in range(self.binary.num_sections()):
                section = self.binary.get_section(i)
                if self.binary._get_section_name(section) == ".eh_frame":
                    break
            if self.arch == "mips64":
                self.note_section = self.binary.get_section(i+1)
                self.ctors_section = self.binary.get_section(i+2)
                self.offset = self.eh_frame_size + self.note_section.header.sh_size
                self.eh_frame_next_section = self.ctors_section
            else:
                self.eh_frame_next_section = self.binary.get_section(i+1)
            self.eh_frame_section_header_offset = self.binary._section_offset(i)
            actual_size = self.eh_frame_next_section.header.sh_offset - self.eh_frame_section.header.sh_offset
            self.eh_frame_end_addr = self.eh_frame_addr + self.eh_frame_size
            if (self.eh_frame_end_addr % PAGE_SIZE) != 0:
                self.eh_frame_end_addr_align = (self.eh_frame_end_addr + PAGE_SIZE) & ctypes.c_uint32(~PAGE_SIZE + 1).value
            self.old_eh_frame_size = self.eh_frame_size
            if self.eh_frame_addr + actual_size > self.eh_frame_end_addr_align:
                self.eh_frame_size = self.eh_frame_end_addr_align - self.eh_frame_addr
            else:
                self.eh_frame_size = actual_size
            load_segment = self.binary.get_segment_for_address(self.eh_frame_addr)
            for i in range(self.binary.num_segments()):
                segment = self.binary.get_segment(i)
                if segment.header.p_vaddr == load_segment.header.p_vaddr:
                    break
            self.load_segment_header_offset = self.binary._segment_offset(i)
            if self.endian == "little":
                endian_fmt = "<"
            else:
                endian_fmt = ">"
            new_size = self.eh_frame_size - self.old_eh_frame_size + load_segment.header.p_filesz
            shutil.copy2(self.path, self.save_path)
            self.bin_file = open(self.save_path, "rb+")
            if self.bits == 32:
                self.bin_file.seek(self.load_segment_header_offset+16)
                self.bin_file.write(struct.pack(endian_fmt+"I", new_size))
                self.bin_file.write(struct.pack(endian_fmt+"I", new_size))
            else:
                self.bin_file.seek(self.load_segment_header_offset+32)
                self.bin_file.write(struct.pack(endian_fmt+"Q", new_size))
                self.bin_file.write(struct.pack(endian_fmt+"Q", new_size))
            self.bin_file.close()
            self.binary = ELF(self.save_path)

            print("old eh_frame_size: %#x" % self.old_eh_frame_size)
        print("eh_frame_size: %#x" % self.eh_frame_size)


    def fix_eh_frame_flags(self):
        e_phnum = self.binary.header.e_phnum
        e_phoff = self.binary.header.e_phoff
        phdr_size = 32 if self.bits == 32 else 56
        p_flags_offset = 24 if self.bits == 32 else 4
        for i in range(0, e_phnum):
            phdr = self.binary.get_segment(i).header
            page_start = (phdr.p_vaddr // 0x1000) * 0x1000
            page_end = phdr.p_vaddr + phdr.p_memsz
            if page_end % 0x1000 != 0:
                page_end = (page_end // 0x1000) * 0x1000 + 0x1000
            if phdr.p_type == "PT_LOAD" and page_start <= self.eh_frame_addr and page_end >= self.eh_frame_addr + self.eh_frame_size:
                print("fix_eh_frame_flags:\npage_start: {} page_end: {} eh_frame_addr: {} eh_frame_size: {} origin phdr.p_flags: {}"
                      .format(hex(page_start), hex(page_end), hex(self.eh_frame_addr), hex(self.eh_frame_size), str(phdr.p_flags)))
                self.binary.write(e_phoff + phdr_size * i + p_flags_offset, p8(5))


    def jmpoffset(self,start,end):
        offset = end - (start + 5)
        if(offset < 0):
            offset += (1<<32)
        print(hex(offset))
        return b'\xe9' + p32(offset)

    def setinjectaddr(self,addr):
        self.inject_addr = addr
    

    def hook(self,hook_addr,hook_len,content):
        assert(hook_len >= 5)
        # backup = self.bin[hook_addr:hook_addr+hook_len]
        backup = self.binary.read(hook_addr,hook_len)
        target = self.inject_addr
        self.binary.write(hook_addr,self.jmpoffset(hook_addr,target))
        payload = backup + content
        self.binary.write(target,payload)
        self.inject_addr += len(payload)
        target = self.inject_addr
        self.binary.write(target,self.jmpoffset(target,hook_addr+hook_len))
        self.inject_addr += 5
    
    def edit(self,addr,content):
        self.binary.write(addr,content)
    
    def save(self,path):
        self.binary.save(path)
    
    def 