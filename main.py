import subprocess
from pwn import *
from sys import argv
import ropper
import rzpipe
from capstone import *

'''

    solver will try to go statically (capstone) => dynamically (gdb) => symbolically (angr) 

'''
# Might change Capstone to r2pipe
# hello world
# Gadget object to make things easier
class Gadget:
    def __init__(self, a, g):
        self.address = a
        self.gadget = g

    def split_gadget(self):
        try:
            self.gadget = self.gadget.split(b" ; ")

        except:
            pass

    def join_gadget(self):
        try:
            self.gadget = " ; ".join(self.gadget)

        except:
            pass


class App:
    # constructor
    def __init__(self, binary):
        self.protections = self.get_protections(binary)
        self.disassembly = {}
        self.elf = {}

        self.handle_disassembly(binary)
       
        
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
    
    # VERY IMPORTANT: I HAVE TO FIX CAPSTONE TO RZ
    # driver for anything needing disassembly
    def handle_disassembly(self, binary):
        self.elf = ELF(binary)
        
        # find available functions and the function with the lowest address
        possibilities = ["main", "vuln", "pwnme", "win"]
        found = None 
        tmp = 0xffffffffffffffff

        for (k,v) in self.elf.sym.items():
            if k in possibilities and v < tmp:
               found = k
               tmp = v
        
        # disassemble binary starting at the address of the first function
        file = open(binary, "rb") 
        asm = file.read()
        asm = asm[self.elf.sym[found] - self.protections["offset"]:]

        md = Cs(CS_ARCH_X86, CS_MODE_64 + CS_MODE_LITTLE_ENDIAN)
        self.disassembly = md.disasm(asm, self.elf.sym[found]) 

        for i in self.disassembly:
            print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

    # call instructions will just have the address, so compare those addresses to `self.elf`
    # returns an array of instructions that have the call you are looking for
    def locate_call(self, function, call): 
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

    # self explanatory, returns the string to overflow
    # ===== COME BACK TO THIS, COREDUMPS ARE UNRELIABLE =====
    def find_overflow(self, binary):
        try:
            io = process(binary)

            io.sendline(cyclic(0x200))
            io.wait()

            core = io.corefile
            stack = core.rsp

            pattern = core.read(stack, 4)
            rip_offset = cyclic_find(pattern)
       
            self.remove_corefiles()
            return b"A" * rip_offset

        except:
            return None
    
    # ============== SYMBOLIC SECTION ====================

    # ================= ROP SECTION ======================
    # rewriting the get_gadgets() function
    def get_gadgets2(self, file):
        pass

    # call ROPgadget and return an array of Gadget objects
    def get_gadgets(self, file):
        io = subprocess.Popen(["ROPgadget", "--binary", file], stdout=subprocess.PIPE)
        out, err = io.communicate()

        if err:
            return "Something went wrong getting ROP gadgets"

        temp = out.split(b"\n")
        all_gadgets = []

        for i in range(2, len(temp) - 3):
            cur = temp[i].split(b" : ")
            all_gadgets.append(Gadget(cur[0], cur[1]))

        return all_gadgets

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

    # this is just a cleanup function thanks to find_overflow()
    def remove_corefiles(self):
        io = subprocess.Popen(["ls", "-l"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = io.communicate()

        if err:
            return err

        lines = out.split(b"\n")

        for line in lines:
            alice = line.split(b" ")

            if b"core" in alice[-1]:
                subprocess.Popen([b"rm", alice[-1]])

        return None


       
if __name__ == "__main__":
    print(argv[1]) 
    app = App(argv[1])

