import subprocess
import json
from pwn import *
from sys import argv
import ropper as r
import rzpipe as rz
from capstone import *
import os
import random

from rop import ROP

'''

    solver will try to go statically (rizin) => dynamically (gdb) => symbolically (angr) 

'''

class App:
    # constructor
    def __init__(self, binary):
        # initialize useful variables
        self.binary = binary
        #self.protections = self.get_protections(binary)
        self.disassembly = {}
        self.pipe = rz.open(binary)
        self.elf = {}
        self.pwnelf = ELF(binary, False)
        self.pwnlibc = None

        # if there is a libc version then yay
        try:
            self.pwnlibc = ELF((b"./ace-student/libc.so.6").decode(), False)
            #self.pwnlibc = ELF((self.pwnelf.runpath + b"/libc.so.6").decode(), False)

        except:
            pass
        
        # initialize ropper & ropper service
        self.rs = r.RopperService()
        self.rs.addFile(binary)
        
        self.rs.loadGadgetsFor()

        # analyze, put anything that depends on self.pipe after this line
        self.pipe.cmd("aaa")
        self.elf = self.pipe.cmd("aflj")
        
    
   
