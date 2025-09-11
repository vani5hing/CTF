#!/usr/bin/env python3

from pwn import *

exe = ELF('./vuln_patched')
libc = ELF('./libc.so.6')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def snum(data):
	sla(b"Choice: ", b"s " + data)

def book():
	sla(b"Choice: ", b"book")


script = '''
# printf(s+2)
brva 0x16D9
'''

p = process('./vuln_patched')
#p = gdb.debug('./vuln_patched', gdbscript = script)

snum(b"2")
debug()

p.interactive()
