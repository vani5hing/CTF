#!/usr/bin/env python3

from pwn import *

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

def f_read(filename):
	sla(b"Choice: ", b"1")
	sla(b"Filename: ", filename)

def f_create(filename, data):
	sla(b"Choice: ", b"2")
	sla(b"Filename: ", filename)
	sla(b"Input: ", data)

script = '''
# fread inside read
brva 0x14DF
# fwrite inside fcreate
brva 0x1489
# fread inside fopen
brva 0x13D9
# fgets in choice 1
brva 0x163B
'''

p = process('./chall')
#p = gdb.debug('./chall', gdbscript = script)

f_read(b"./flag.txt")
# cat /proc/137/fd/3\n

debug()

p.interactive()
