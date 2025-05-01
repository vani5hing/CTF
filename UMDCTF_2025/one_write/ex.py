from pwn import *

e = ELF("./one_write")
context.binary = e

p_s = lambda data: p.send(data)
p_sa = lambda msg, data: p.sendafter(msg, data)
p_sl = lambda data: p.sendline(data)
p_sla = lambda msg, data: p.sendlineafter(msg, data)
p_recvut = lambda msg: p.recvuntil(msg)
debug = lambda : gdb.attach(p, gdbscript = script)

def alloc(idx, size):
	p_sa(b"> ", b"1")
	p_sa(b"idx: ", f"{idx}".encode())
	p_sa(b"size: ", f"{size}".encode())

def free(idx):
	p_sa(b"> ", b"2")
	p_sa(b"idx: ", f"{idx}".encode())

def write(data):
	p_sa(b"> ", b"3")
	p_sa(b"data: ", data)

def show():
	p_sa(b"> ", b"4")

'''
prompt in main
malloc
'''

script = '''
brva 0x13F6
brva 0x12F4
'''

p = process("./one_write")
debug()

alloc(0, 0x38)
show()


p.interactive()