
from patch1 import *

shellcode = ''' 
	mov r15,6 
	push r15 
	mov r15,0x7FFF000000000006 
	push r15 	
	mov r15,0x3B00010015 
	push r15 
	mov r15 , 0x3800020015 
	push r15 
	mov r15 , 0x3200030015 
	push r15 
	mov r15 , 0x3100040015 
	push r15 
	mov r15 , 0x2A00050015 
	push r15 
	mov r15 , 0x2900060015
	push r15 
	mov r15 , 0x4000000000070035 
	push r15 
	mov r15 , 0x20
	push r15 
	mov r15 , 0xC000003E09000015
	push r15 
	mov r15 , 0x400000020
	push r15 
	mov r15,rsp 
	push r15 
	mov r15 , 0xc
	push r15 
	mov r15,rsp 	
	push r15 
	mov rdi,38 
	mov rsi,1 
	mov rdx,0 
	mov rcx,0 
	mov r10,0 
	mov rax,157 
	syscall 
	mov rdi,22 
	mov rsi,2 
	mov rdx,r15 
	mov rax,157 
	syscall
	add rsp, 120
'''
patcher = Patcher('target')
# patcher.setinjectaddr(0xDDFE)
patcher.fmt_patch(0x11BE,0x11CA-0x11BE)
# patcher.hook(0x11CD,0x11d5-0x11CD,asm(shellcode))
patcher.save("./target.patch")

