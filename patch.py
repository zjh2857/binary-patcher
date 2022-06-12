from pwn import *


class Patcher:
    def __init__(self,dir):
        fd = open(dir,'rb')
        self.bin = fd.read()
        self.bin = bytearray(self.bin)
        self.elf = ELF(dir)
        fd.close()
        if(self.bin[4] == 2):
            context.arch = "amd64"
            self.arch = 64
        elif(self.bin[4] == 1):
            self.arch = 32
            context.arch = "i386"
        else:
            raise RuntimeError('arch')
    
    def get_enframe(self):
        eh_frame_entry = self.bin.find(b'\x50\xe5\x74\x64')
        self.bin[eh_frame_entry:eh_frame_entry+4] = p32(1)
        print(hex(eh_frame_entry))
        if(self.arch == 32):
            self.bin[eh_frame_entry+0x18] = 7
            self.inject_addr = u32(self.bin[eh_frame_entry+4:eh_frame_entry+8])
        if(self.arch == 64):
            self.bin[eh_frame_entry+4] = 7
            self.inject_addr = u64(self.bin[eh_frame_entry+8:eh_frame_entry+16])
        print(ej)
    def jmpoffset(self,start,end):
        offset = end - (start + 5)
        if(offset < 0):
            offset += (1<<32)
        print(hex(offset))
        return b'\xe9' + p32(offset)

    def setinjectaddr(self,addr):
        self.inject_addr = addr
    
    def hook(self,hook_addr,hook_len,content):
        backup = self.bin[hook_addr:hook_addr+hook_len]
        target = self.inject_addr
        self.bin[hook_addr:hook_addr+5] = self.jmpoffset(hook_addr,target)
        payload = backup + content
        self.bin[target:target+len(payload)] = payload
        self.inject_addr += len(payload)
        target = self.inject_addr
        self.bin[target:target+5] = self.jmpoffset(target,hook_addr+hook_len)
        self.inject_addr += 5

    def save(self,dir):
        fp = open(dir,'wb')
        fp.write(self.bin)
        fp.close()
        

        
