import subprocess

io = subprocess.Popen(["ls", "-l"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
out, err = io.communicate()

if err:
    exit(-1)

list_items = out.split(b"\n")
list_items = list_items[1:]
list_items = [ line.split(b" ") for line in list_items ]

for item in list_items:
    if b"bin" in item[-1] and b"_patched" not in item[-1]:
        subprocess.Popen([b"pwninit", b"--bin", item[-1], b"--libc", b"/usr/lib/libc.so.6", b"--ld", b"/usr/lib64/ld-linux-x86-64.so.2"])
        time.sleep(5) 
        subprocess.Popen([b"rm", item[-1]])
        subprocess.Popen([b"mv", item[-1] + b"_patched", item[-1]])
        print(b"Done " + item[-1])

