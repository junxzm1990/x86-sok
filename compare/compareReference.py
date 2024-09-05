from deps import *
import optparse
import logging

import refInf_pb2
import blocks_pb2
from elftools.elf.elffile import ELFFile
from BlockUtil import *

logging.basicConfig(level=logging.DEBUG)

SegRange = list()
InstsInfo = list() # (start_addr, inst_size)
InstsInfoSet = dict()
InstsInfoCompared = list()
InstsInfoComparedSet = dict()

CurrentInstIndex = 0
CurrentInstIndexCompared = 0
JTEntries = list()
DIRECT_FLOW_REFS = set()
MD = None
load_range = list()

#IncludedSec = ['.text', '.data', '.rodata', '.data.rel.ro', '.init_array']
IncludedSec = ['.text', '.data', '.rodata']
groundTruthFuncRange = dict()
groundTruthInstructionsRange = list()
loadedSegs = list()

# pie/pic base address
# angr base address is 0x400000
# ghidra base address is 0x100000
# others are 0x0
BASE_ADDR_MAP = {"angr": 0x400000, "ghidra": 0x100000}
disassembler_base_addr = 0x0
PIE = False
textAddr = 0x0
textOffset = 0x0
textSize = 0x0

groundTruthFuncRange = dict()

def isInTextSection(addr):
    if addr >= textAddr and addr < textAddr + textSize:
        return True
    return False

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

linkerExcludeFunction = dict()
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

def readSecRange(binary):
    global SegRange
    with open(binary, 'rb') as binaryFile:
        elf = ELFFile(binaryFile)
        for sec in elf.iter_sections():
            if sec.name not in IncludedSec:
                continue
            start_addr = sec['sh_addr']
            end_addr = sec['sh_addr'] + sec['sh_size']
            logging.debug("Section %s: 0x%x -> 0x%x" % (sec.name, start_addr, end_addr))
            SegRange.append((start_addr, end_addr))
            if sec.name == ".text":
                global textSize
                global textAddr
                global textOffset
                textSize = sec['sh_size']
                textAddr = sec['sh_addr']
                textOffset = sec['sh_offset']
                logging.info(".text section addr: 0x%x, size: 0x%x, offset: 0x%x" % (textSize, textAddr, textOffset))

def compare(groundTruth, compared, accurate, binary):
    cntFalseNeg = 0
    cntFalsePos = 0
    cntFalsePosCode = 0
    cntFalsePosData = 0
    cntFalseNegCode = 0
    cntFalseNegData = 0
    TruePositiveNum = 0
    open_binary = open(binary, 'rb')
    content = open_binary.read()
    # compare instructions
    instructions_false_negitive = dict()
    instructions_false_positive = dict()
    for (addr, size) in InstsInfo:
        if addr not in InstsInfoComparedSet:
            instructions_false_negitive[addr] = size

    exclude_num = 0
    exclude_neg = 0
    for (addr, target) in groundTruth.items():
        if addr not in compared:
            if isInTextSection(addr): 
                if checkInRange(addr, instructions_false_negitive, accurate):
                    exclude_neg += 1
                else:
                    logging.error("[False Negitive#%d]: Reference %x to %x that compared cant't find" % (cntFalseNeg, addr, target))
                    cntFalseNeg += 1
            else:
                region = "Data"
                if isInTextSection(target):
                    region = "Code"
                    cntFalseNegCode += 1
                else:
                    cntFalseNegData += 1
                logging.error("[False Negitive#%d]: Reference %x to %x[%s] that compared cant't find" % (cntFalseNeg, addr, target, region))
                cntFalseNeg += 1
                

    for (addr, target) in compared.items():
        if addr not in groundTruth:
            if isInTextSection(addr): 
                if not isInRange(addr, groundTruthInstructionsRange):
                    exclude_num += 1
                else:
                    logging.error("[False Positive#%d]: Reference %x to %x that compared find wrong" % (cntFalsePos, addr, target))
                    cntFalsePos += 1
            else:
                region = "Data"
                if isInTextSection(target):
                    region = "Code"
                    cntFalsePosCode += 1
                else:
                    cntFalsePosData += 1
                logging.error("[False Positive#%d]: Reference %x to %x[%s] that compared find wrong" % (cntFalsePos, addr, target, region))
                cntFalsePos += 1
        else:
            TruePositiveNum += 1

    logging.info("GroundTruth references total number: %d" % (len(groundTruth) - exclude_neg))
    logging.info("Compared references total number: %d" % (len(compared) - exclude_num))
    logging.info("False positive number: %d" % (cntFalsePos))
    logging.info("False negitive number: %d" % (cntFalseNeg))
    if cntFalseNeg > 0:
        logging.info("False negitive number to data: %d, rate is %f" % (cntFalseNegData, (cntFalseNegData / cntFalseNeg)))
        logging.info("False negitive number to code: %d, rate is %f" % (cntFalseNegCode, (cntFalseNegCode / cntFalseNeg)))
    if cntFalsePos > 0:
        logging.info("False positive number to data: %d, rate is %f" % (cntFalsePosData, (cntFalsePosData / cntFalsePos)))
        logging.info("False positive number to code: %d, rate is %f" % (cntFalsePosCode, (cntFalsePosCode / cntFalsePos)))
    logging.info("Precision: %f" % (TruePositiveNum / (len(compared) - exclude_num)))
    logging.info("Recall: %f" % (TruePositiveNum / (len(groundTruth) - exclude_neg)))

def addrInRange(addr):
    for sRange in SegRange:
        if addr >= sRange[0] and addr <= sRange[1]:
            return True
    return False

def getInstAddress(ref):
    if len(InstsInfo) == 0:
        return None
    global CurrentInstIndex 
    saved_index = CurrentInstIndex
    while True:
        current_inst = InstsInfo[CurrentInstIndex]
        if ref >= current_inst[0] and ref < current_inst[0] + current_inst[1]:
            return current_inst[0]
        CurrentInstIndex = (CurrentInstIndex + 1) % (len(InstsInfo))
        if saved_index == CurrentInstIndex:
            break
    return None

#def getInstAddressCompared(ref):
#    if len(InstsInfoCompared) == 0:
#        return None
#    global CurrentInstIndexCompared 
#    saved_index = CurrentInstIndexCompared
#    while True:
#        current_inst = InstsInfoCompared[CurrentInstIndexCompared]
#        if ref >= current_inst[0] and ref < current_inst[0] + current_inst[1]:
#            return current_inst[0]
#        CurrentInstIndexCompared = (CurrentInstIndexCompared + 1) % (len(InstsInfo))
#        if saved_index == CurrentInstIndexCompared:
#            break
#    return None

# if the address is the direct flow instruction (direct jump/call)
def directFlowInst(disassemble_content, current_addr):
    disasm_ins = MD.disasm(disassemble_content, current_addr, count = 1)
    try:
        cur_inst = next(disasm_ins)
    except StopIteration:
        return False
    return isDirect(cur_inst)

def readGroundTruth(refInf, accurate, binary):
    result = dict() # key_addr -> ref addr list
    open_binary = open(binary, 'rb')
    content = open_binary.read()
    global DIRECT_FLOW_REFS
    for r in refInf.ref:
        if not addrInRange(r.ref_va):
            continue
        if (r.kind == 0 or r.kind == 1) and not isInTextSection(r.ref_va):
            continue
        if isInExcludeRange(r.ref_va):
            continue
        if r.jt_entry == True:
            JTEntries.append(r.ref_va)
            continue
        ref_addr = r.ref_va
        target_addr = r.target_va
        if not isInRange(target_addr, load_range):
            continue
        if target_addr == 0x0:
            continue
        if (r.kind == 0 or r.kind == 1):
            inst_addr = getInstAddress(ref_addr)
            if inst_addr == None:
                logging.error("The ground truth of instruction or reference is wrong. Please check again! The ref address is 0x%x" \
                        % (ref_addr))
                exit(-1)
            textEndOffset = textSize + textOffset
            offset = inst_addr - textAddr + textOffset
            # we assume that any instruction length is less that 20 bytes
            endOffset = (offset + 20) if (offset + 20) < textEndOffset else textEndOffset
            disassemble_content = content[offset: endOffset] 
            # we don't collect direct jump/call reference
            if accurate:
                ref_addr = inst_addr 
            if directFlowInst(disassemble_content, inst_addr):
                DIRECT_FLOW_REFS.add(ref_addr)
                continue
        result[ref_addr] = target_addr

    return result

def readCompared(refInf):
    result = dict()
    for r in refInf.ref:
        ref_addr = r.ref_va
        target_addr = r.target_va
        if PIE:
            ref_addr = ref_addr - disassembler_base_addr
            target_addr = target_addr - disassembler_base_addr
        if isInExcludeRange(ref_addr):
            continue
        if not addrInRange(ref_addr):
            continue
        if ref_addr in JTEntries:
            continue
        # skip the reference in direct jump/call instruction
        if ref_addr in DIRECT_FLOW_REFS:
            continue
        result[ref_addr] = target_addr
    return result

"""
for PIE/PIC objects, if the most refs address are wrong, 
we switch the base address to 0x10000
"""
def doubleCheckGhidraBase(refInf, loaded_segs):
    invalid_count = 0x0
    global disassembler_base_addr
    for r in refInf.ref:
        ref_addr = r.ref_va - disassembler_base_addr
        in_seg = False
        for (seg_start, seg_end) in loaded_segs:
            if ref_addr >= seg_start and ref_addr < seg_end:
                in_seg = True
                break
        if not in_seg:
            invalid_count += 1

    # need python3
    if invalid_count / len(refInf) > 0.8:
        logging.warning("change ghidra base address to 0x10000!")
        disassembler_base_addr = 0x10000

def isInExcludeRange(addr):
    for (start, end) in linkerExcludeFunction.items():
        if addr >= start and addr < (start + end):
            return True
    return False

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
                logging.info("current func is 0x%x, prev is 0x%x" % (func, prev_func))
                if linkerExcludeFunction[prev_func] != 0:
                    # update the linker function paddings
                    end_addr = prev_func + linkerExcludeFunction[prev_func]
                    padding_size = func - prev_func - linkerExcludeFunction[prev_func]
                    assert padding_size >= 0, "[getLinkerFunctionRange]: padding size < 0"
                    assert padding_size < 0x30, "[getLinkerFunctionRange]: padding size > 0x30, Please check it manually!"
                    linkerExcludeFunction[prev_func] += padding_size
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


def readInstsInfo(inst_pb):
    global InstsInfo
    global InstsInfoSet
    global groundTruthInstructionsRange
    module = blocks_pb2.module()
    tmpFuncSet = set()
    global groundTruthFuncRange
    try:
        pb_file = open(inst_pb, 'rb')
        module.ParseFromString(pb_file.read())
        pb_file.close()
    except IOError:
        logging.error("Could not open the file %s!" % (inst_pb))
    range_start = 0x0
    range_end = 0x0
    for func in module.fuc:
        tmpFuncSet.add(func.va)
        for bb in func.bb:
            # add the range
            if bb.va != range_end:
                if range_start != range_end:
                    groundTruthInstructionsRange.append((range_start, range_end))
                range_start = bb.va
                range_end = bb.va + bb.size - bb.padding
            else:
                range_end += bb.size - bb.padding
                
            for inst in bb.instructions:
                InstsInfo.append((inst.va, inst.size))
                groundTruthFuncRange[inst.va] = inst.size
                InstsInfoSet[inst.va] = inst.size
    if range_start != range_end:
        groundTruthInstructionsRange.append((range_start, range_end))

    InstsInfo.sort(key=(lambda tup: tup[0]))

    for func in linkerFuncAddr:
        if func not in tmpFuncSet:
            notIncludedLinkerFunc.add(func)

def readInstsCompared(inst_pb):
    global InstsInfoCompared
    global InstsInfoComparedSet
    module = blocks_pb2.module()
    tmpFuncSet = set()
    try:
        pb_file = open(inst_pb, 'rb')
        module.ParseFromString(pb_file.read())
        pb_file.close()
    except IOError:
        logging.error("Could not open the file %s!" % (inst_pb))
    for func in module.fuc:
        tmpFuncSet.add(func.va)
        prev_size = -1
        inst_compared = False
        for bb in func.bb:
            prev_va = -1
            for inst in bb.instructions:
                inst_size = 0
                if inst.size != 0:
                    inst_size = inst.size
                    InstsInfoComparedSet[inst.va] = inst_size
                    InstsInfoCompared.append((inst.va, inst_size))
                elif prev_va != -1:
                    inst_compared = True
                    inst_size = inst.va - prev_va
                    InstsInfoComparedSet[prev_va] = inst_size
                    InstsInfoCompared.append((prev_va, inst_size))
                prev_va = inst.va
            if inst_compared:
                inst_size = bb.size + bb.va - prev_va
                InstsInfoComparedSet[prev_va] = inst_size
                InstsInfoCompared.append((prev_va, inst_size))
    InstsInfoCompared.sort(key=(lambda tup: tup[0]))

"""
get pie base offset according to the compared file name.
"""
def getPIEBaseOffset(comparedFile):
    for (tool, base_offset) in BASE_ADDR_MAP.items():
        if tool in comparedFile:
            return base_offset
    # default offset is 0x0
    return 0

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
            try:
                name = cxxfilt.demangle(sym.name)
            except:
                pass
            if name in linker_libc_func:
                logging.debug("linker: %s: %x" % (name, sym['st_value']))
                linkerFuncAddr.add(sym['st_value'])

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-g", "--groundtruth", dest = "groundtruth", action = "store", type = "string", help = "ground truth file path", default = None)
    parser.add_option("-c", "--compared", dest = "comparedfile", action = "store", type = "string", help = "compared file path", default = None)
    parser.add_option("-b", "--binary", dest = "binary", action = "store", \
            type = "string", help = "binary file path", default = None)
    parser.add_option("-a", "--accurate", dest = "accurate", action = "store_true", \
            help = "If the text reference from address is accurate address or instruction address", default = False)
    parser.add_option("-i", "--instruction", dest = "instruction", action = "store", \
            type = "string", help = "The instruction pb of gt", default = None)
    parser.add_option("-p", "--proto", dest = "proto", action = "store", \
            type = "string", help = "The instruction pb of compared", default = None)

    (options, args) = parser.parse_args()
    if options.groundtruth == None:
        logging.error("Please input the ground truth file")
        exit(-1)
    if options.comparedfile == None:
        logging.error("Please input the compared file")
        exit(-1)

    if options.accurate and options.instruction == None:
        logging.error("Please input the instruction pb file")
        exit(-1)
    getLinkerFunctionAddr(options.binary)
    # read ground truth file instructions
    readInstsInfo(options.instruction)
    readInstsCompared(options.proto)
    not_included = checkGroundTruthFuncNotIncluded(groundTruthFuncRange, options.binary)
    if not_included != None:
        logging.debug("Append the not included functions! {0}".format(not_included))
        notIncludedLinkerFunc != not_included
    load_range = getLoadAddressRange(options.binary)
    load_range = enlargeRange(load_range)
    logging.debug("load range is {}".format(load_range))
    getLinkerFunctionRange(options.binary)
    elfclass = readElfClass(options.binary)
    elfarch = readElfArch(options.binary)
    elfendian = readElfEndian(options.binary)
    bbl.init(elfarch, elfclass, elfendian)
    MD = init_capstone(elfclass)
    readSecRange(options.binary)
    loadedSegs = get_loaded_info(options.binary)
    PIE = isPIE(options.binary)
    if PIE:
        disassembler_base_addr = getPIEBaseOffset(options.comparedfile)
    refInf1 = refInf_pb2.RefList()
    refInf2 = refInf_pb2.RefList()
    try:
        f1 = open(options.groundtruth, 'rb')
        refInf1.ParseFromString(f1.read())
        f1.close()
    except:
        print("Could not open the file: %s\n"% options.groundtruth)
        exit(-1)
        
    try:
        f2 = open(options.comparedfile, 'rb')
        refInf2.ParseFromString(f2.read())
        f2.close()
    except:
        print("Could not open the file: %s\n" % options.comparedfile)
        exit(-1)

    if "ghidra" in options.comparedfile and PIE:
        doubleCheckGhidraBase(refInf2, loadedSegs)
    groundTruth = readGroundTruth(refInf1, options.accurate, options.binary)
    compared = readCompared(refInf2)
    compare(groundTruth, compared, options.accurate, options.binary)
