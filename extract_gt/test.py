"""
test for the elf format of the arm64 file
"""

from deps import *
from reorderInfo import *
import optparse
import blocks_pb2
import constants as C
import reconstructInfo 
import logging
from capstone import x86 ## Change capstone from x86 to arm
from capstone import arm64 
from elftools.elf.elffile import ELFFile
import ctypes
from BlockUtil import *

parser = optparse.OptionParser()
parser.add_option("-b", "--binary", dest = "binary", action="store", type="string", help="input elf binary path", default=None)

(options, args) = parser.parse_args()
if options.binary == None:
    print('Please input the elf file')
    exit(-1)

# arm64 return 64 the same as x86_64
# need some other flag
ELF_CLASS = readElfClass(options.binary)
ELF_ARCH = readElfArch(options.binary)
# print(ELF_CLASS)
# print(ELF_ARCH)



