import logging
from os import terminal_size
from deps import *
from reorderInfo import *
import optparse
import blocks_pb2
import constants as C
import reconstructInfo 
import capstone as cs
from capstone import x86 ## Change capstone from x86 to arm
from capstone import arm64 
from elftools.elf.elffile import ELFFile
import ctypes
from BlockUtil import *

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-b", "--binary", dest = "binary", action="store", type="string", help="input elf binary path", default=None)
    parser.add_option("-m", "--metadata", dest = "metadata", action="store", type="string", help="metadata file path", default=None)
    parser.add_option("-l", "--log", dest = "log", action="store", type="string", help="log file of the program", default="/tmp/ccr_basicblocks.log")

    (options, args) = parser.parse_args()
    if options.binary == None:
        print('Please input the elf file')
        exit(-1)

    shuffleInfoBin = None
    if options.metadata == None:
        shuffleInfoBin = options.binary + C.METADATA_POSTFIX
    else:
        shuffleInfoBin = options.metadata

    rData = None
    raw_protobuf_buffer = None
    if os.path.exists(shuffleInfoBin):
        rData = reconstructInfo.read(shuffleInfoBin, False, options.binary)
        raw_protobuf_buffer = reconstructInfo.readRawBufferInfo(shuffleInfoBin, False)
    elif os.path.exists(C.METADATA_PATH):
        rData = reconstructInfo.read(C.METADATA_PATH, True, options.binary)
        raw_protobuf_buffer = reconstructInfo.readRawBufferInfo(C.METADATA_PATH, True)
    else:
        print("Error: No metadata file\n")
        exit(-1)

    outFile = options.log
    module = blocks_pb2.module()
    
    ELF_CLASS = readElfClass(options.binary)
    ELF_ARCH = readElfArch(options.binary)
    readElfRelocation(options.binary)
    
    LOAD_RANGE= getLoadAddressRange(options.binary)
    (GOT_PLT_ADDR, _) = readSectionRange(options.binary, '.got.plt')
    TEXT_RANGE = readSectionRange(options.binary, '.text')
    print(TEXT_RANGE)
    rData['bin_info']['bin_path'] = options.binary
    essInfo = EssentialInfo(rData)

    for fixup in RelocationList:
        flag = True
        if flag and essInfo.getFixupsText() is not None:
            for fi in essInfo.getFixupsText():
                if fi.VA == fixup:
                    flag = False
                    break
        if flag and essInfo.getFixupsSpecial() is not None:
            for fi in essInfo.getFixupsSpecial():
                if fi.VA == fixup:
                    flag = False
                    break
        if flag and essInfo.getFixupsOrphan() is not None:
            for fi in essInfo.getFixupsOrphan():
                if fi.VA == fixup:
                    flag = False
                    break
        if flag and essInfo.getFixupsRodata() is not None:
            for fi in essInfo.getFixupsRodata():
                if fi.VA == fixup:
                    flag = False
                    break
        if flag and essInfo.getFixupsData() is not None:
            for fi in essInfo.getFixupsData():
                if fi.VA == fixup:
                    flag = False
                    break
        if flag and essInfo.getFixupsDataRel() is not None:
            for fi in essInfo.getFixupsDataRel():
                if fi.VA == fixup:
                    flag = False
                    break
        if flag and essInfo.getFixupsInitArray() is not None:
            for fi in essInfo.getFixupsInitArray():
                if fi.VA == fixup:
                    flag = False
                    break
        if flag and fixup in TEXT_RANGE:
            print("Not find fixup of the addr 0x%x, Symbol name is %s" %(fixup,RelocationName[fixup]))

            

