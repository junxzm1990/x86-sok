from telnetlib import EL
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

angr_flag = False

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
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEpLEPKc",
               ### other libs, libc
               "ns_name_rollback",
               "ns_name_skip",
               "__ns_get16",
               "__ns_get32",
               "ns_put16",
               "ns_put32",
               "binary_hnok",
               "__dn_expand",
               "__dn_comp",
               "__dn_skipname",
               "__res_hnok",
               "__res_ownok",
               "__res_mailok",
               "__res_dnok",
               "__putlong",
               "__putshort",
               "_getlong",
               "_getshort",
               "__res_context_mkquery",
               "__res_nmkquery",
               "__res_mkquery",
               "__res_nopt",
               "ns_msg_getflag",
               "ns_skiprr",
               "ns_initparse",
               "ns_parserr",
               "ns_parserr",
               "__ns_name_ntop",
               "ns_name_ntol",
               "__ns_name_unpack",
               "ns_name_pack",
               "ns_name_uncompress",
               "ns_name_compress",
               "__fixunstfdi",
               "__eqtf2",
               "set_fast_math",
               "__letf2",
               "__getf2",
               "__sfp_handle_exceptions",
               "__lstat",
               "__fstat",
               "fstatat",
               "__floatunsitf",
               "__extenddftf2",
               "__floatsitf",
               "__floatditf",
               "__unordtf2",
               "__trunctfsf2",
               "__trunctfdf2",
               "__cxx_global_var_init.9",
               "_GLOBAL__sub_I_step_14.cc"
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
        if func % 2 == 1 and angr_flag:
            func = func - 1
        if func not in groundTruth:
            logging.error("[Func Start False Positive #{0}]:Function Start 0x{1:x} not in Ground Truth.".format(falsePositive, func))
            falsePositive += 1
        else:
            truePositive += 1

    ## compute the false negative number
    for func in groundTruth:
        if func not in compared:
            if angr_flag and func + 1 in compared:
                continue
            logging.error("[Func Start False Negative #{0}]:Function Start 0x{1:x} not in compared.".format(falseNegative, func))
            falseNegative += 1
    precision = None
    if len(compared) > 0:
        precision = truePositive / len(compared)
    recall = truePositive / len(groundTruth)

    print("[Result]:The total Functions in ground truth is %d" % (len(groundTruth)))
    print("[Result]:The total Functions in compared is %d" % (len(compared)))
    print("[Result]:False positive number is %d" % (falsePositive))
    print("[Result]:False negative number is %d" % (falseNegative))
    if precision is not None:
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
    if groundTruth:
        logging.debug("GT:")
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
        if tool in comparedFile.lower():
            return base_offset
    # default offset is 0
    return 0

def doubleCheckGhidraBase(compared):
    '''
    sometimes, ghidra do not set pie/pic object base address as 0x100000, we double check it!
    '''
    invalid_count = 0x0
    logging.info("PIE")
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

    if "ghidra" in options.comparedfile.lower() and PIE:
        doubleCheckGhidraBase(mModule2)

    ELF_ARCH = readElfArch(options.binaryFile)
    #if ELF_ARCH == 'MIPS':
    if "angr" in options.comparedfile.lower() or "nucleus" in options.comparedfile.lower():
        logging.info("Angr!")
        angr_flag = True

    truthFuncs = readFuncs(mModule1, True)
    not_included = checkGroundTruthFuncNotIncluded(groundTruthFuncRange, options.binaryFile)
    if not_included != None:
        logging.debug("Append the not included functions! {0}".format(not_included))
        truthFuncs |= not_included
        truthFuncs |= notIncludedLinkerFunc
    comparedFuncs = readFuncs(mModule2, False)
    compareFuncs(truthFuncs, comparedFuncs)
