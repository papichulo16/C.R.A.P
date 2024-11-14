class Static:
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

    def get_cmps(self, function):
        bob = []

        for alice in function["ops"]:
            if "cmp" in alice["disasm"]:
                bob.append(alice)

        return bob

    def cmp_params(self, function):
        arr = self.get_cmps(function)
        values = {}
        try:
            for instruction in arr:
                asm = instruction["disasm"].split(",")
                values[asm[0][asm[0].index("var_") + 4:asm[0].index("]") - 1]] = int(asm[1], 16)

        except:
            pass

        print(values)
         
    
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


