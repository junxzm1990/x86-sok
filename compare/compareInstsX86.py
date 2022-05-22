from deps import *
import optparse
import logging
import blocks_pb2
from elftools.elf.elffile import ELFFile
from BlockUtil import *

logging.basicConfig(level=logging.DEBUG)

# some decompiler decompile padding as instructions
paddingMap = dict()
paddingAddrList = set()

# plt range
pltAddr = 0
pltSize = 0

linkerExcludeFunction = dict()
groundTruthFuncRange = dict()

# default _init and _fini function size
default_x86_get_pc_thunk_bx = 0x10

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
linkerFuncAddr = set()
notIncludedLinkerFunc = set()

# pie/pic base address
# angr base address is 0x400000
# ghidra base address is 0x100000
# others are 0x0
BASE_ADDR_MAP = {"angr": 0x400000, "ghidra": 0x100000}
disassembler_base_addr = 0x0
PIE = False

textAddr = 0
textSize = 0
FuncRanges = dict()
GroundTruthFunc = set()
GroundTruthRange = list()


def f1_scores(pre, rcl):
    return 2*pre*rcl / (pre + rcl)

# in order to increase the speed, we expand the range list
def expandPadding():
    global paddingAddrList
    for (start, end) in paddingMap.items():
        [paddingAddrList.add(addr) for addr in range(start, start + end)]

# if the instruction address in padding bytes
def isInPaddingRange(addr):
    for (start, end) in paddingMap.items():
        if addr >= start and addr < (start + end):
            return True
    return False

def isInPltSection(addr):
    if addr >= pltAddr and addr < pltAddr + pltSize:
        return True
    return False

def isInTextSection(addr):
    if addr >= textAddr and addr < textAddr + textSize:
        return True
    return False

def isInExcludeRange(addr):
    for (start, end) in linkerExcludeFunction.items():
        if addr >= start and addr < (start + end):
            return True
    return False

def compareInsts(groundTruth, compared):
    """
    compare the basic blocks with their address, size, and successors
    """
    logging.info("Compare the basic blocks:")
    falsePositive = 0 # false positive number
    falseNegative = 0 # false negative number
    truePositive = 0
    nopInstructions = 0 # tools that identify padding bytes as instructions
    excludeInstrs = 0x0
    skip_fn = 0
    ## compute the false positive number
    for inst in compared:
        if inst not in groundTruth:
            if inst in paddingAddrList:
                #logging.warning("[padding bytes %x is deemd as a instruction]" % (inst))
                nopInstructions += 1
            elif isInExcludeRange(inst):
                logging.debug("[Index 0x%x]: It seems that we don't have the instruction's 0x%x ground truth, let's skip it!" 
                        % (excludeInstrs, inst))
                excludeInstrs += 1
            else:
                logging.error("[Instruction False Positive #%d]Instruction address %x not in ground truth" % 
                        (falsePositive, inst))
                falsePositive += 1
        else:
            truePositive += 1

    compared_num = len(compared) - excludeInstrs - nopInstructions

    ## compute the false negative number
    for inst in groundTruth:
        if inst not in compared:
            logging.error("[Instruction False Negative #%d]Instruction address %x not in compared" % 
                    (falseNegative, inst))
            falseNegative += 1

    print("[Result]:The total instruction number is %d" % (len(groundTruth)))
    print("[Result]:Instruction false positive number is %d, rate is %f" % 
            (falsePositive, falsePositive/len(groundTruth)))
    print("[Result]:Instruction false negative number is %d, rate is %f" %
            (falseNegative, falseNegative/len(groundTruth)))
    if len(compared) == 0:
        print("[Result]:Padding byte instructions number is 0, rate is 0")
    else:
        print("[Result]:Padding byte instructions number is %d, rate is %f" % 
                (nopInstructions, nopInstructions/(len(compared) - excludeInstrs)))
    pre = truePositive / compared_num
    rcl = truePositive / len(groundTruth)
    print("[Result]:Precision %f" % (pre))
    print("[Result]:Recall %f" % (rcl))
    print("[Result]:F1 Score %f" % (f1_scores(pre, rcl)))

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

def readInstructions(mModule, groundTruth):
    """
    read the instructions from protobuf

    params:
        mModule: protobuf module
        groundTruth: if this is the groundTruth file
    returns:
        instructions address: store the result of functions list
    """
    tmpInstSet = set()
    tmpFuncSet = set()
    checkDouble = False
    global groundTruthFuncRange
    for func in mModule.fuc:
        range_start = -1
        range_end = -1
        funcAddr = func.va
        if funcAddr not in tmpFuncSet:
            tmpFuncSet.add(funcAddr)
        else:
            logging.warning("repeated handle the function in address %x" % func.va)
            continue
        for bb in func.bb:
            # collect the range of padding bytes
            if True == groundTruth:
                # logging.info("bb: 0x%x, size: 0x%x, padding size: 0x%x" % (bb.va, bb.size, bb.padding))
                global paddingMap
                paddingMap[bb.va+bb.size] = bb.padding
            for inst in bb.instructions:
                inst_va = inst.va
                if groundTruth:
                    groundTruthFuncRange[inst_va] = inst.size
                if not groundTruth and PIE:
                    inst_va = inst.va - disassembler_base_addr
                if not isInTextSection(inst_va):
                    continue
                if isInPltSection(inst_va) == True:
                    continue
                if inst_va not in tmpInstSet:
                    tmpInstSet.add(inst_va)

    # check if we include all linker function
    global notIncludedLinkerFunc
    global linkerFuncAddr
    
    if groundTruth:
        for func in linkerFuncAddr:
            if func not in tmpFuncSet:
                notIncludedLinkerFunc.add(func)

    return tmpInstSet

def pltRange(binary):
    with open(binary, 'rb') as openFile:
        elffile = ELFFile(openFile)
        for sec in elffile.iter_sections():
            if sec.name == '.plt':
                global pltSize
                global pltAddr
                pltSec = sec
                pltSize= pltSec['sh_size']
                pltAddr = pltSec['sh_addr']
                logging.info(".plt section addr: 0x%x, size: 0x%x" % (pltAddr, pltSize))

def readTextSection(binary):
    with open(binary, 'rb') as openFile:
        elffile = ELFFile(openFile)
        for sec in elffile.iter_sections():
            if sec.name == '.text':
                global textSize 
                global textAddr
                pltSec = sec
                textSize = pltSec['sh_size']
                textAddr = pltSec['sh_addr']
                logging.info(".text section addr: 0x%x, size: 0x%x" % (textSize, textAddr))

# we record the linker function address, and then check which function we have omited
def getLinkerFunctionAddr(binary):
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
                linkerFuncAddr.add(sym['st_value'])

def getLinkerFunctionRange(binary):
    with open(binary, 'rb') as openFile:
        elffile = ELFFile(openFile)
        symsec = elffile.get_section_by_name('.symtab')
        funcSet = set()
        global linkerExcludeFunction 
        get_pc_thunk_bx = 0x0
        if symsec == None:
            return
        for sym in symsec.iter_symbols():
            if 'STT_FUNC' != sym.entry['st_info']['type']:
                continue
            funcSet.add(sym['st_value'])
            if sym['st_value'] in notIncludedLinkerFunc:
                size = sym['st_size']
                linkerExcludeFunction[sym['st_value']] = size


        prev_func = None
        for func in sorted(funcSet):
            if prev_func != None and prev_func in linkerExcludeFunction:
                if not isInTextSection(prev_func):
                    continue
                logging.info("current func is 0x%x, prev is 0x%x" % (func, prev_func))
                if linkerExcludeFunction[prev_func] != 0:
                    # update the linker function paddings
                    end_addr = prev_func + linkerExcludeFunction[prev_func]
                    padding_size = func - prev_func - linkerExcludeFunction[prev_func]
                    assert padding_size >= 0, "[getLinkerFunctionRange]: padding size < 0"
                    if padding_size < 0x30:
                        paddingMap[end_addr] = padding_size
                else:
                    linker_func_size = func - prev_func
                    # check the function size.
                    # if the size is too large, we need to comfirm it manually!
                    assert linker_func_size > 0 and linker_func_size < 0x80, '[getLinkerFunctionRange]: linker function size seems unnormal, please check it manually!'
                    linkerExcludeFunction[prev_func] = func - prev_func
            prev_func = func

        init_fini = ['.init', '.fini']

        for sec in elffile.iter_sections():
            if sec.name in init_fini:
                linkerExcludeFunction[sec['sh_addr']] = sec['sh_size']
        for (func, size) in linkerExcludeFunction.items():
            logging.info("[linker function]: 0x%x - 0x%x" % (func, func + size))

"""
get pie base offset according to the compared file name.
"""
def getPIEBaseOffset(comparedFile):
    for (tool, base_offset) in BASE_ADDR_MAP.items():
        if tool in comparedFile.lower():
            return base_offset
    # default offset is 0
    return 0

def checkGroundTruthFuncNotIncludedLocal(groundTruthRange, binary):
    result = set()
    with open(binary, 'rb') as openFile:
        elffile = ELFFile(openFile)
        symsec = elffile.get_section_by_name('.symtab')
        if symsec == None:
            logging.error("binary %s does not contain .symtab section!" % binary)
            return None
        for sym in symsec.iter_symbols():
            if 'STT_FUNC' != sym.entry['st_info']['type']:
                continue
            func_addr = sym['st_value']
            func_name = sym.name
            if func_addr != 0 and sym['st_size'] != 0 and func_addr not in groundTruthRange:
                logging.warning("[check ground truth function:] function %s in address 0x%x not in ground truth" % 
                        (func_name, func_addr))
                result.add(func_addr)
    return result

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-g", "--groundtruth", dest = "groundtruth", action = "store", \
            type = "string", help = "ground truth file path", default = None)
    parser.add_option("-c", "--comparedfile", dest = "comparedfile", action = "store", \
            type = "string", help = "compared file path", default = None)
    parser.add_option("-b", "--binaryFile", dest = "binaryFile", action = "store", \
            type = "string", help = "binary file path", default = None)

    (options, args) = parser.parse_args()
    if options.groundtruth == None:
        print("Please input the ground truth file")
        exit(-1)
    if options.comparedfile == None:
        print("Please input the compared file")
        exit(-1)
    
    if options.binaryFile == None:
        print("Please input the binary file")
        exit(-1)

    pltRange(options.binaryFile)
    PIE = isPIE(options.binaryFile)
    if PIE:
        disassembler_base_addr = getPIEBaseOffset(options.comparedfile)
    readTextSection(options.binaryFile)
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

    ## Store the protobuf results
    truthInsts = dict() # {instruction address}
    comparedInsts = dict() # (instruction address}
    #FuncRanges = getFuncRanges(options.binaryFile)

    if "ghidra" in options.comparedfile.lower() and PIE:
        doubleCheckGhidraBase(mModule2)

    truthInsts = readInstructions(mModule1, True)
    comparedInsts = readInstructions(mModule2, False)
    not_included = checkGroundTruthFuncNotIncludedLocal(groundTruthFuncRange, options.binaryFile)
    #not_included = checkGroundTruthFuncNotIncluded(GroundTruthFunc, options.binaryFile)
    if not_included != None:
        logging.debug("Append the not included functions! {0}".format(not_included))
        notIncludedLinkerFunc |= not_included 

    getLinkerFunctionRange(options.binaryFile)
    expandPadding()
    compareInsts(truthInsts, comparedInsts)
