from deps import *
import optparse
import logging
import capstone as cs

import blocks_pb2
from elftools.elf.elffile import ELFFile
from capstone import x86
from BlockUtil import *


logging.basicConfig(format = "%(asctime)-15s %(levelname)s:%(message)s", level=logging.DEBUG)

textAddr = 0
textSize = 0
textOffset = 0
MD = None
#assemble_file_range = dict()

# pie/pic base address
# angr base address is 0x400000
# ghidra base address is 0x100000
# others are 0x0
BASE_ADDR_MAP = {"angr": 0x400000, "ghidra": 0x100000}
disassembler_base_addr = 0x0
PIE = False
isGhidra = False


def isGhidraTool(cur_file):
    global isGhidra
    if "ghidra" in cur_file:
        isGhidra = True

def compareSuccessors(succes, com_succes):
    if isGhidra:
        if len(succes) - len(com_succes) == 0 or len(succes) + 1 - len(com_succes) == 0:
            return 0
        return len(succes) + 1 - len(com_succes)
    else:
        return len(succes) - len(com_succes)

def isInRange(asm_file_range, addr):
    for (start, end) in asm_file_range.items():
        if addr >= start and addr < start + end:
            return True
    return False

def compareJmpTables(groundTruth, compared, insts):
    """
    compare the jump tables
    """
    logging.info("Compare Jump tables:")
    falsePositive = 0 # false positive number
    falseNegative = 0 # false negative number
    nopInstructions = 0 # tools that identify padding bytes as instructions
    truePositive = 0
    successorWrong = 0

    ## compute the false positive number
    for (terminator, successors) in compared.items():
        compare_result = compareSuccessors(groundTruth[terminator], successors)
        if compare_result == 0:
            truePositive += 1
            continue
        ground_truth_result = ", ".join(f"0x{x:x}" for x in groundTruth[terminator])
        successors_result = ", ".join(f"0x{x:x}" for x in successors)
        logging.error("[Jump Table successors wrong #{0} in 0x{1:x}]: \n Ground Truth is {2}\n compared is {3}".format(successorWrong, terminator, ground_truth_result, successors_result))
        successorWrong += 1
        if compare_result < 0:
            logging.error("[More than ground truth]: 0x%x" % terminator)
        else:
            logging.error("[Less thatn ground truth]: 0x%x" % terminator)

    ## compute the false negative number
    exclude_num = 0
    for (terminator, successors) in groundTruth.items():
        if terminator not in compared:
            if terminator not in insts:
                exclude_num += 1
                continue

            ground_truth_result = ", ".join(f"0x{x:x}" for x in groundTruth[terminator])
            logging.error("[Instruction False Negative #%d]Instruction address %x not in compared. Ground Truth is %s" % 
                    (falseNegative, terminator, ground_truth_result))
            falseNegative += 1

    ground_truth_num = len(groundTruth) - exclude_num
    print("[Result]:The total jump table in ground truth is %d" % (ground_truth_num))
    print("[Result]:The total jump table in compared is %d" % (len(compared)))
    print("[Result]:False negative number is %d" % (falseNegative))
    print("[Result]:Wrong successors number is %d" % (successorWrong))
    if ground_truth_num > 0:
        print("[Result]: Recall: %f" % ((truePositive/ground_truth_num)))

    if len(compared) > 0:
        print("[Result]: Precision: %f" % ((truePositive/(len(compared)))))
            

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

def readJmpTablesGroundTruth(mModule, binary):
    """
    read jump tables from protobufs
    params:
        mModule: protobuf module
    returns:
        jmp tables: store the result of jmp tables
    """
    tmpFuncSet = set()
    result = dict()
    open_binary = open(binary, 'rb')
    content = open_binary.read()

    for func in mModule.fuc:
        funcAddr = func.va
        if funcAddr not in tmpFuncSet:
            tmpFuncSet.add(funcAddr)
        else:
            logging.warning("repeated handle the function in address %x" % func.va)
            continue

        textEndOffset = textSize + textOffset
        for bb in func.bb:
            # If the number of basic block's successors number is bigger than 2 
            if bb.type == BlockType.JUMP_TABLE and len(bb.instructions) > 0:
                successors = set()
                terminator_addr = bb.instructions[-1].va
                [successors.add(suc.va) for suc in bb.child]
                result[terminator_addr] = successors
    return result

def readJmpTablesCompared(mModule, binary, groundTruth):
    """
    read jump tables from protobufs
    params:
        mModule: protobuf module
    returns:
        jmp tables: store the result of jmp tables
    """
    tmpFuncSet = set()
    result = dict()
    open_binary = open(binary, 'rb')
    content = open_binary.read()
    insts = set()
    for func in mModule.fuc:
        funcAddr = func.va
        if funcAddr not in tmpFuncSet:
            tmpFuncSet.add(funcAddr)
        else:
            logging.warning("repeated handle the function in address %x" % func.va)
            continue

        textEndOffset = textSize + textOffset
        for bb in func.bb:
            if len(bb.instructions) == 0:
                continue
            [insts.add(inst.va - disassembler_base_addr) for inst in bb.instructions]
            terminator_addr = bb.instructions[-1].va
            if PIE:
                terminator_addr -= disassembler_base_addr

            # the comapred disassembler find the jump table
            # FIXME: we deemed that jump table has at least 2 successors
            if terminator_addr in groundTruth:
                successors = set()
                for suc in bb.child:
                    if not isInTextSection(suc.va - disassembler_base_addr):
                        continue
                    successors.add(suc.va - disassembler_base_addr)

                if len(successors) == 0:
                    continue
                successors_result = ", ".join(f"0x{x:x}" for x in successors)
                logging.debug("[Indirect jump at 0x%x: successors is %s]" % (terminator_addr, successors_result))
                result[terminator_addr] = successors
    return (result, insts)

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

def readAsmFileRange(mModule_shuffle):
    asm_file_range = dict()
    for layout in mModule_shuffle.layout:
        if layout.assemble_type == 2 and layout.offset not in asm_file_range:
            asm_file_range[layout.offset] = layout.bb_size
    asm_file_range = sorted(asm_file_range.items(), key=lambda x: x[0])

    # merge the range if it is continues
    merged_range = dict()
    pre_range = None
    for (start, size) in asm_file_range:
        if pre_range == None:
            pre_range = (start, size)
            continue

        # if the previous range is continues to current range, merge them
        if pre_range[0] + pre_range[1] == start:
            pre_range = (start, size + pre_range[1])
        else:
            merged_range[start] = size
            pre_range = (start, size)
    if pre_range != None:
        merged_range[pre_range[0]] = pre_range[1]
    for (start, end) in merged_range.items():
        logging.info("range from 0x%x to 0x%x" % (start, start + end))
    return merged_range

"""
get pie base offset according to the compared file name.
"""
def getPIEBaseOffset(comparedFile):
    for (tool, base_offset) in BASE_ADDR_MAP.items():
        if tool in comparedFile:
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

    assert options.groundtruth != None, "Please input the ground truth file!"
    assert options.comparedfile != None, "Please input the compared file!"
    assert options.binaryFile != None, "Please input the binary file!"

    isGhidraTool(options.comparedfile)

    readTextSection(options.binaryFile)
    elfclass = readElfClass(options.binaryFile)
    MD = init_capstone(elfclass)
    PIE = isPIE(options.binaryFile)
    if PIE:
        disassembler_base_addr = getPIEBaseOffset(options.comparedfile)
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
        logging.error("Could not open the file\n")
        exit(-1)
    if "ghidra" in options.comparedfile and PIE:
        doubleCheckGhidraBase(mModule2)
    truthTables = readJmpTablesGroundTruth(mModule1, options.binaryFile)
    (comparedTables, insts) = readJmpTablesCompared(mModule2, options.binaryFile, truthTables)
    compareJmpTables(truthTables, comparedTables, insts)
