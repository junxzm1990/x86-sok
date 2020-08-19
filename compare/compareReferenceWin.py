from deps import *
import optparse
import logging

import refInf_pb2
import blocks_pb2
from elftools.elf.elffile import ELFFile
from BlockUtil import *
from PEUtil import *

InstsInfo = list() # (start_addr, inst_size)
InstsInfoSet = dict()
InstsInfoCompared = list()
InstsInfoComparedSet = dict()

CurrentInstIndex = 0
CurrentInstIndexComp = 0
logging.basicConfig(level=logging.DEBUG)
groundTruthInstructionsRange = list()

JTEntries = list()
DIRECT_FLOW_REFS = set()
MD = None
load_range = list()

BRANCH_RANGES = list()
IMAGE_BASE = 0x0

ALL_SECS = list()
groundTruthFuncRange = dict()

def compare(groundTruth, compared, accurate, binary, exec_secs):
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
            if isInExecSecs(exec_secs, addr): 
                if checkInRange(addr, instructions_false_negitive, accurate):
                    exclude_neg += 1
                else:
                    logging.error("[False Negitive#%d]: Reference %x to %x that compared cant't find" % (cntFalseNeg, addr, target))
                    cntFalseNeg += 1
            else:
                region = "Data"

                # may not be accurate):
                if isInExecSecs(exec_secs, target):
                    region = "Code"
                    cntFalseNegCode += 1
                else:
                    cntFalseNegData += 1
                logging.error("[False Negitive#%d]: Reference %x to %x[%s] that compared cant't find" % (cntFalseNeg, addr, target, region))
                cntFalseNeg += 1
                

    for (addr, target) in compared.items():
        if addr not in groundTruth:
            region = "Data"
            pos = True
            if isInExecSecs(exec_secs, target):
                region = "Code"
                if not isInRange(addr, groundTruthInstructionsRange):
                    exclude_num += 1
                    pos = False
                else:
                    cntFalsePosCode += 1
            else:
                cntFalsePosData += 1
            if pos:
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

def getComparedInstAddress(ref):

    global CurrentInstIndexComp
    saved_index = CurrentInstIndexComp
    while True:
        current_inst = InstsInfoCompared[CurrentInstIndexComp]
        if ref >= current_inst[0] and ref < current_inst[0] + current_inst[1]:
            return current_inst[0]
        CurrentInstIndexComp = (CurrentInstIndexComp + 1) % (len(InstsInfoCompared))
        if saved_index == CurrentInstIndexComp:
            break
    return None

# if the address is the direct flow instruction (direct jump/call)
def FlowInst(disassemble_content, current_addr):
    disasm_ins = MD.disasm(disassemble_content, current_addr, count = 1)
    try:
        cur_inst = next(disasm_ins)
    except StopIteration:
        return False
    return x86.X86_GRP_JUMP in cur_inst.groups or x86.X86_GRP_CALL in cur_inst.groups or cur_inst.id in {x86.X86_INS_LOOP, x86.X86_INS_LOOPE, x86.X86_INS_LOOPNE}

def get_file_offset(exec_secs, va, image_base):
    offset = None
    for cur_sec in exec_secs:
        if va >= cur_sec.addr + image_base and va <=  image_base + cur_sec.addr + cur_sec.size:
            offset = va - image_base - cur_sec.addr + cur_sec.offset
            break
    return offset

def readGroundTruth(refInf, accurate, binary, exec_secs):
    result = dict() # key_addr -> ref addr list
    open_binary = open(binary, 'rb')
    content = open_binary.read()

    global DIRECT_FLOW_REFS
    global JTEntries

    open_binary = open(binary, 'rb')
    content = open_binary.read()
    content_len = len(content)

    for r in refInf.ref:
        if r.jt_entry == True:
            JTEntries.append(r.ref_va)
            continue

        ref_addr = r.ref_va
        target_addr = r.target_va

        if not isInExecSecs(ALL_SECS, ref_addr):
            continue

        if isInExecSecs(exec_secs, ref_addr):
            inst_addr = getInstAddress(ref_addr)
            if inst_addr != None:
                file_offset = get_file_offset(exec_secs, inst_addr, IMAGE_BASE)
                # we assume that any instruction length is less that 20 bytes
                endOffset = (file_offset + 20) if (file_offset + 20) < content_len else content_len
                disassemble_content = content[file_offset: endOffset] 
                # we don't collect direct jump/call reference
                if accurate:
                    ref_addr = inst_addr 
                if FlowInst(disassemble_content, inst_addr):
                    DIRECT_FLOW_REFS.add(ref_addr)
                    continue
        result[ref_addr] = target_addr
    open_binary.close()
    return result

def readCompared(refInf, binary, accurate):
    result = dict()
    open_binary = open(binary, 'rb')
    content = open_binary.read()
    content_len = len(content)
    for r in refInf.ref:
        ref_addr = r.ref_va
        target_addr = r.target_va

        if ref_addr in JTEntries:
            continue

        if not isInExecSecs(ALL_SECS, ref_addr):
            continue

        if isInExecSecs(exec_secs, ref_addr):
            inst_addr = None
            if accurate:
                if ref_addr in InstsInfoComparedSet:
                    inst_addr = ref_addr
            else:
                inst_addr = getComparedInstAddress(ref_addr)

            if inst_addr != None:
                file_offset = get_file_offset(exec_secs, inst_addr, IMAGE_BASE)
                # we assume that any instruction length is less that 20 bytes
                endOffset = (file_offset + 20) if (file_offset + 20) < content_len else content_len
                disassemble_content = content[file_offset: endOffset] 
                # we don't collect direct jump/call reference
                if FlowInst(disassemble_content, inst_addr):
                    DIRECT_FLOW_REFS.add(ref_addr)
                    continue

        result[ref_addr] = target_addr
        open_binary.close()
    return result


def readInstsInfo(inst_pb):
    global InstsInfo
    global InstsInfoSet
    global groundTruthInstructionsRange
    global BRANCH_RANGES
    module = blocks_pb2.module()
    tmpFuncSet = set()
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
            if bb.va != range_end:
                if range_start != range_end:
                    groundTruthInstructionsRange.append((range_start, range_end))
                range_start = bb.va
                range_end = bb.va + bb.size - bb.padding
            else:
                range_end += bb.size - bb.padding

            if len(bb.instructions) > 0 and bb.type in \
                    {BlockType.COND_BRANCH, BlockType.DIRECT_BRANCH, BlockType.INDIRECT_BRANCH, BlockType.INDIRECT_CALL, BlockType.DIRECT_CALL}:
                last_inst = bb.instructions[-1]
                BRANCH_RANGES.append((last_inst.va, last_inst.va + last_inst.size))
            for inst in bb.instructions:
                InstsInfo.append((inst.va, inst.size))
                InstsInfoSet[inst.va] = inst.size

    InstsInfo.sort(key=(lambda tup: tup[0]))

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
        inst_compared = True
        for bb in func.bb:
            prev_va = -1
            for inst in bb.instructions:
                inst_size = 0
                if inst.size != 0:
                    inst_compared = False
                    inst_size = inst.size
                    InstsInfoComparedSet[inst.va] = inst_size
                    InstsInfoCompared.append((inst.va, inst_size))
                elif prev_va != -1:
                    inst_size = inst.va - prev_va
                    InstsInfoComparedSet[prev_va] = inst_size
                    InstsInfoCompared.append((prev_va, inst_size))
                prev_va = inst.va
            if inst_compared:
                inst_size = bb.size + bb.va - prev_va
                InstsInfoComparedSet[prev_va] = inst_size
                InstsInfoCompared.append((prev_va, inst_size))
    InstsInfoCompared.sort(key=(lambda tup: tup[0]))

def isInExecSecs(secs, va):
    for sec in secs:
        if va >= sec.addr + IMAGE_BASE and va < IMAGE_BASE + sec.addr + sec.size:
            return True

    return False

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-g", "--groundtruth", dest = "groundtruth", action = "store", type = "string", help = "ground truth file path", default = None)
    parser.add_option("-c", "--compared", dest = "comparedfile", action = "store", type = "string", help = "compared file path", default = None)
    parser.add_option("-b", "--binary", dest = "binary", action = "store", \
            type = "string", help = "binary file path", default = None)
    parser.add_option("-a", "--accurate", dest = "accurate", action = "store_true", \
            help = "If the text reference from address is accurate address or instruction address", default = False)
    parser.add_option("-i", "--instruction", dest = "instruction", action = "store", \
            type = "string", help = "The instruction pb", default = None)
    parser.add_option("-p", "--proto", dest = "proto", action = "store", \
            type = "string", help = "The instruction pb of compared tool", default = None)

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

    # read ground truth file instructions
    readInstsInfo(options.instruction)
    readInstsCompared(options.proto)

    (IMAGE_BASE, class_type) = parsePEFile(options.binary)

    MD = init_capstone(class_type)

    exec_secs = parsePEExecSecs(options.binary)
    ALL_SECS = exec_secs[:]
    rdata = parsePERdata(options.binary)
    if rdata != None:
        ALL_SECS.append(rdata)

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

    groundTruth = readGroundTruth(refInf1, options.accurate, options.binary, exec_secs)
    compared = readCompared(refInf2, options.binary, options.accurate)
    compare(groundTruth, compared, options.accurate, options.binary, exec_secs)
