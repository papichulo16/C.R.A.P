import gdb

binary = None

with open("./cur_bin", "r") as file:
    lines = file.readlines()
    binary = lines[-1]

gdb.execute(f"file {binary}")

pattern = cyclic(0x200)
gdb.execute(f"run <<< {pattern}")

regs = gdb.execute("info registers", to_string=True)
print(regs)

