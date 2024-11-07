from pwn import *
import subprocess
import os

class Dynamic:
    # ======================== DYNAMIC SECTION ========================

    # find printf vuln
    def detect_printf_vuln(self, binary):
        io = process(binary)

        out = io.recvuntil(b">>>")
    
        if b"would you like to edit" in out:
            return "array"

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


