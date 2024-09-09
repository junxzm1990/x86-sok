from .deps import *
import optparse
import logging
import blocks_pb2
from elftools.elf.elffile import ELFFile
from BlockUtil import *
from util import *

logging.basicConfig(level=logging.DEBUG)

# some decompiler decompile padding as instructions
paddingMap = dict()
paddingAddrList = set()

# plt range
pltAddr = 0
pltSize = 0

linkerExcludeFunction = dict()
groundTruthFuncRange = dict()

arm = False

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
               "__fstat",
               "call_weak_fn",
               "__udivsi3",
               "__aeabi_uidivmod",
               "__divsi3",
               ".divsi3_skip_div0_test",
               "__aeabi_idivmod",
               "__aeabi_idiv0",
               "__aeabi_ldivmod",
               "__udivmoddi4",
               "__aeabi_drsub",
               "__aeabi_dsub",
               "__adddf3",
               "__aeabi_ui2d",
               "__aeabi_i2f",
               "__aeabi_ul2f",
               "__aeabi_l2f",
               "__aeabi_i2d",
               "__aeabi_f2d",
               "__arm_set_fast_math",
               "__divsc3",
               "__mulsc3",
               "__aeabi_ul2d",
               "__aeabi_l2d",
               "__aeabi_frsub",
               "__aeabi_fsub",
               "__addsf3",
               "__aeabi_ui2f",
               "__aeabi_uldivmod",
               "hlt",
               "__start",
               "__addtf3",
               "__divtf3",
               "__multf3",
               "__floatunditf",
               # libc static
               "ns_name_pton",
               "__cxa_rethrow",
               "_Znwm",
               "__cxa_guard_abort",
               "__cxa_guard_release",
               "__cxa_throw_bad_array_new_length",
               "_ZSt7getlineIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RNSt7__cxx1112basic_stringIS4_S5_T1_EE",
               "_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC1Ev",
               "_ZNSt14basic_ifstreamIcSt11char_traitsIcEE4openEPKcSt13_Ios_Openmode",
               "_ZNSt14basic_ifstreamIcSt11char_traitsIcEED1Ev",
               "_Unwind_Resume",
               "_ZNKSt8__detail20_Prime_rehash_policy11_M_next_bktEm",
               "_ZSt24__throw_out_of_range_fmtPKcz",
               "_ZSt20__throw_length_errorPKc",
               "_ZSt17__throw_bad_allocv",
               "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6substrEmm",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructIPKcEEvT_S8_St20forward_iterator_tag",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructIPcEEvT_S7_St20forward_iterator_tag",
               "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7compareEmmPKc",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_appendEPKcm",
               "__subtf3",
               "__aeabi_d2ulz",
               "__aeabi_d2lz",
               "lstat64",
               "fstat64",
               "stat64",
               "__fixtfdi",
               "__cxx_global_var_init.8",
               "__mknod",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructEmc",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEaSERKS4_",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7reserveEm",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEpLEc",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5eraseEmm",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE14_M_replace_auxEmmmc",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE10_M_replaceEmmPKcm",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6assignEPKc",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEaSEPKc",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6appendERKS4_mm",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6appendEPKcm",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEpLEPKc"
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
textRegion = None

FuncRanges = dict()
GroundTruthFunc = set()
GroundTruthRange = list()

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

def filter_fp_arm(pos):
    if not isInTextSection(pos):
        return True

    if textRegion is None or not arm:
        return False

    offset = pos - textAddr
    # e7ffdefe
    data = textRegion[offset: offset + 4]
    if data == b'\xfe\xde\xff\xe7' or data == b'\x1f\x20\x03\xd5':
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
            elif not filter_fp_arm(inst):
                logging.error("[Instruction False Positive #%d]Instruction address %x not in ground truth" %
                        (falsePositive, inst))
                falsePositive += 1
            else:
                excludeInstrs += 1
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

    if compared_num > 0:
        print("[Result]:Precision %f" % (truePositive / compared_num))
    print("[Result]:Recall %f" % (truePositive / len(groundTruth)))

def doubleCheckGhidraBase(compared):
    '''
    sometimes, ghidra do not set pie/pic object base address as 0x100000, we double check it!
    '''
    invalid_count = 0x0
    global disassembler_base_addr
    logging.info("HELLO, disassembler base addr is 0x%x" % disassembler_base_addr)
    for func in compared.fuc:
        # emmm, func.va - disassembler_base_addr is not the valid address in .text section
        if not isInTextSection(func.va - disassembler_base_addr):
            invalid_count += 1
    # need python3
    if invalid_count / len(compared.fuc) > 0.9:
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
            notIncludedLinkerFunc.add(func)
            # if func not in tmpFuncSet:

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
                logging.info(".text section addr: 0x%x, size: 0x%x" % (textAddr, textSize))

def readTextContent(binary):
    if not arm:
        return

    with open(binary, 'rb') as openFile:
        elffile = ELFFile(openFile)
        for sec in elffile.iter_sections():
            if sec.name == '.text':
                content = open(binary, 'rb').read()
                global textRegion
                text_size = sec['sh_size']
                text_off = sec['sh_offset']
                textRegion = content[text_off: text_size + text_off]



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
                v_addr = sym['st_value']
                if v_addr % 4 == 1 and arm:
                    v_addr = v_addr - 1
                logging.info("linker: %s: %x" % (name, v_addr))
                linkerFuncAddr.add(v_addr)

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
            v_addr = sym['st_value']
            if v_addr % 4 == 1 and arm:
                v_addr = v_addr - 1

            funcSet.add(v_addr)
            if v_addr in notIncludedLinkerFunc:
                size = sym['st_size']
                linkerExcludeFunction[v_addr] = size

        logging.info("linker exclude function is {}".format(linkerExcludeFunction))
        prev_func = None
        for func in sorted(funcSet):
            if prev_func != None and prev_func in linkerExcludeFunction:
                if not isInTextSection(prev_func):
                    # logging.info("function 0x%x not in text section!" % prev_func)
                    prev_func = func
                    continue
                if linkerExcludeFunction[prev_func] != 0:
                    # update the linker function paddings
                    end_addr = prev_func + linkerExcludeFunction[prev_func]
                    padding_size = func - prev_func - linkerExcludeFunction[prev_func]
                    # logging.info("padding size of function 0x%x is 0x%x" % (prev_func, padding_size))
                    # assert padding_size >= 0, "[getLinkerFunctionRange]: padding size < 0"
                    # if padding_size < 0x30 and padding_size > 0x0:
                    #     paddingMap[end_addr] = padding_size
                    if padding_size > 0x0:
                        linkerExcludeFunction[prev_func] += padding_size
                else:
                    linker_func_size = func - prev_func
                    # check the function size.
                    # if the size is too large, we need to comfirm it manually!
                    # assert linker_func_size > 0 and linker_func_size < 0x80, '[getLinkerFunctionRange]: linker function at 0x%x size seems unnormal, please check it manually!' % (prev_func)
                    linkerExcludeFunction[prev_func] = linker_func_size
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

    arm = is_arm(options.binaryFile)

    pltRange(options.binaryFile)
    PIE = isPIE(options.binaryFile)
    if PIE:
        disassembler_base_addr = getPIEBaseOffset(options.comparedfile)
    readTextSection(options.binaryFile)
    readTextContent(options.binaryFile)
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
    not_included = checkGroundTruthFuncNotIncluded(groundTruthFuncRange, options.binaryFile)
    #not_included = checkGroundTruthFuncNotIncluded(GroundTruthFunc, options.binaryFile)
    if not_included != None:
        logging.debug("Append the not included functions! {0}".format(not_included))
        notIncludedLinkerFunc |= not_included

    getLinkerFunctionRange(options.binaryFile)
    expandPadding()
    compareInsts(truthInsts, comparedInsts)
