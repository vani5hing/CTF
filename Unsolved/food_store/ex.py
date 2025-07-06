#!/usr/bin/env python3

from pwn import *

exe = ELF('./food_store_patched')
libc = ELF('./libc-4e5dfd832191073e18a09728f68666b6465eeacd.so')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
recvut = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

script = '''
'''

p = process('./food_store_patched')
#p = gdb.debug('./food_store_patched', gdbscript = script)
debug()

p.interactive()
