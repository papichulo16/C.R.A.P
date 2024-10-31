import subprocess
from pwn import *
from sys import argv
import ropper as r
import rzpipe as rz
from capstone import *

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
        
        # initialize ropper & ropper service
        rs = r.RopperService()
        rs.addFile(binary)

        self.ropper = r.Ropper(rs)

        # analyze, put anything that depends on self.pipe after this line
        self.pipe.cmd("aaa")
        self.elf = self.pipe.cmd("aflj")

        self.find_overflow(binary) 

        
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

    # ======================= STATIC SECTION ==========================
    
    # driver for anything needing disassembly
    def handle_disassembly(self, binary):
        pass

    # find given leaks and return the libc function that is leaked
    def find_given_leaks(self, function):
        # find where printf is called in a given function
         
        # find value of rsi, if there is one
        
        # return the function used in rsi from the plt table
        pass

    # ======================== DYNAMIC SECTION ========================
    
    # find printf vuln
    def detect_printf_vuln(self, binary):
        io = process(binary)

        io.sendline(b"%p")
        out = io.recv()

        return b"0x" in out
    
    # using a universal function did not work :(
    # creating gdb script on the fly instead
    def find_overflow2(self, binary):
        pass

    # self explanatory, returns the string to overflow
    def find_overflow(self, binary):
        pattern = cyclic(0x500)

        # call gdb with the script I made (which is awesome, by the way)
        # gdb scripts are cool as hell
        # i have no clue why subprocess is being like this :(
        io = subprocess.run(["gdb", "-q", "-x", "./gdb-scripts/inspect_registers.gdb", "-ex", f"\"run_binary {binary} {pattern.decode('utf-8')}\"", "-batch"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout

        print("===========================")
        print(io)

    # ================= ROP SECTION ======================
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

if __name__ == "__main__":
    app = App(argv[1])

