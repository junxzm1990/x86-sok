from deps import *
import optparse
import logging
import capstone as cs

import blocks_pb2
from elftools.elf.elffile import ELFFile
from capstone import x86
from BlockUtil import *


logging.basicConfig(format = "%(asctime)-15s %(levelname)s:%(message)s", level=logging.INFO)

textAddr = 0
textSize = 0
textOffset = 0
MD = None

notIncludedLinkerFunc = set()

# FIXME: sometimes, ccr(clang) version can't linke our compiled gcc libraries to its executable, 
# so we exclude below functions which is added by linker. 
linker_libc_func = {
               "__x86.get_pc_thunk.bx", # glibc in i386 function
               "__libc_csu_init",
               "__libc_csu_fini",
               "deregister_tm_clones",
               "register_tm_clones",
               "__do_global_dtors_aux",
               "frame_dummy",
               "_start",
               "atexit",
               "_dl_relocate_static_pie",
               "__stat",
               "stat64",
               "fstat64",
               "lstat64",
               "fstatat64",
               "__fstat"
               }
def getLinkerFunctionAddr(binary):
    global notIncludedLinkerFunc
    with open(binary, 'rb') as openFile:
        elffile = ELFFile(openFile)
        symsec = elffile.get_section_by_name('.symtab')
        get_pc_thunk_bx = 0x0
        global linkerFuncAddr
        if symsec == None:
            return
        for sym in symsec.iter_symbols():
            name = sym.name
            if 'STT_FUNC' != sym.entry['st_info']['type']:
                continue
            if name in linker_libc_func:
                logging.debug("linker: %s: %x" % (name, sym['st_value']))
                notIncludedLinkerFunc.add(sym['st_value'])

groundTruthFuncRange = dict()

linkerFuncAddr = set()
# pie/pic base address
# angr base address is 0x400000
# ghidra base address is 0x100000
# others are 0x0
BASE_ADDR_MAP = {"angr": 0x400000, "ghidra": 0x100000}
disassembler_base_addr = 0x0
PIE = False

def compareFuncs(groundTruth, compared):
    """
    compare the jump tables
    """
    logging.info("Compare Funcs Start:")
    falsePositive = 0 # false positive number
    falseNegative = 0 # false negative number
    truePositive = 0

    ## compute the false positive number
    for func in compared:
        if func not in groundTruth:
            logging.error("[Func Start False Positive #{0}]:Function Start 0x{1:x} not in Ground Truth.".format(falsePositive, func))
            falsePositive += 1
        else:
            truePositive += 1

    ## compute the false negative number
    for func in groundTruth:
        if func not in compared:
            logging.error("[Func Start False Negative #{0}]:Function Start 0x{1:x} not in compared.".format(falseNegative, func))
            falseNegative += 1

    precision = truePositive / len(compared)
    recall = truePositive / len(groundTruth)

    print("[Result]:The total Functions in ground truth is %d" % (len(groundTruth)))
    print("[Result]:The total Functions in compared is %d" % (len(compared)))
    print("[Result]:False positive number is %d" % (falsePositive))
    print("[Result]:False negative number is %d" % (falseNegative))
    print("[Result]:Precision %f" % precision)
    print("[Result]:Recall %f" % recall)


def readFuncs(mModule, groundTruth):
    """
    read Funcs from protobufs
    params:
        mModule: protobuf module
    returns:
        Funcs start: store the result of function start
    """
    global groundTruthFuncRange
    tmpFuncSet = set()
    for func in mModule.fuc:
        logging.debug("current function address is 0x%x" % func.va)
        # this is the dummy function
        if func.va == 0x0:
            continue
        funcAddr = func.va
        if PIE and not groundTruth:
            funcAddr = funcAddr - disassembler_base_addr
        if not isInTextSection(funcAddr):
            continue
        if funcAddr not in tmpFuncSet:
            tmpFuncSet.add(funcAddr)
        else:
            logging.warning("repeated handle the function in address %x" % func.va)
            continue

    if groundTruth:
        for func in linkerFuncAddr:
            if func not in tmpFuncSet:
                logging.debug("add linker add function that 0x%x" % func)
                tmpFuncSet.add(func)

        for func in mModule.fuc:
            for bb in func.bb:
            # collect the range of padding bytes
                for inst in bb.instructions:
                    groundTruthFuncRange[inst.va] = inst.size

    return tmpFuncSet

def readTextSection(binary):
    with open(binary, 'rb') as openFile:
        elffile = ELFFile(openFile)
        for sec in elffile.iter_sections():
            if sec.name == '.text':
                global textSize 
                global textAddr
                global textOffset
                pltSec = sec
                textSize = pltSec['sh_size']
                textAddr = pltSec['sh_addr']
                textOffset = pltSec['sh_offset']
                logging.info(".text section addr: 0x%x, size: 0x%x, offset: 0x%x" % (textSize, textAddr, textOffset))

def isInTextSection(addr):
    if addr >= textAddr and addr < textAddr + textSize:
        return True
    return False

"""
get pie base offset according to the compared file name.
"""
def getPIEBaseOffset(comparedFile):
    for (tool, base_offset) in BASE_ADDR_MAP.items():
        if tool in comparedFile:
            return base_offset
    # default offset is 0
    return 0

def doubleCheckGhidraBase(compared):
    '''
    sometimes, ghidra do not set pie/pic object base address as 0x100000, we double check it!
    '''
    invalid_count = 0x0
    global disassembler_base_addr
    for func in compared.fuc:
        # emmm, func.va - disassembler_base_addr is not the valid address in .text section
        if not isInTextSection(func.va - disassembler_base_addr):
            invalid_count += 1
    # need python3
    if invalid_count / len(compared.fuc) > 0.8:
        logging.warning("Change ghidra base address to 0x10000!")
        disassembler_base_addr = 0x10000

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-g", "--groundtruth", dest = "groundtruth", action = "store", \
            type = "string", help = "ground truth file path", default = None)
    parser.add_option("-c", "--comparedfile", dest = "comparedfile", action = "store", \
            type = "string", help = "compared file path", default = None)
    parser.add_option("-b", "--binaryFile", dest = "binaryFile", action = "store", \
            type = "string", help = "binary file path", default = None)

    (options, args) = parser.parse_args()

    assert options.groundtruth != None, "Please input the ground truth file!"
    assert options.comparedfile != None, "Please input the compared file!"
    assert options.binaryFile != None, "Please input the binary file!"

    readTextSection(options.binaryFile)
    PIE = isPIE(options.binaryFile)
    logging.debug("compared file is %s" % options.binaryFile)
    if PIE:
        disassembler_base_addr = getPIEBaseOffset(options.comparedfile)
    getLinkerFunctionAddr(options.binaryFile)
    mModule1 = blocks_pb2.module()
    mModule2 = blocks_pb2.module()
    try:
        f1 = open(options.groundtruth, 'rb')
        mModule1.ParseFromString(f1.read())
        f1.close()
        f2 = open(options.comparedfile, 'rb')
        mModule2.ParseFromString(f2.read())
        f2.close()
    except IOError:
        print("Could not open the file\n")
        exit(-1)

    if "ghidra" in options.comparedfile and PIE:
        doubleCheckGhidraBase(mModule2)

    truthFuncs = readFuncs(mModule1, True)
    not_included = checkGroundTruthFuncNotIncluded(groundTruthFuncRange, options.binaryFile)
    if not_included != None:
        logging.debug("Append the not included functions! {0}".format(not_included))
        truthFuncs |= not_included
        truthFuncs |= notIncludedLinkerFunc
    comparedFuncs = readFuncs(mModule2, False)
    compareFuncs(truthFuncs, comparedFuncs)
