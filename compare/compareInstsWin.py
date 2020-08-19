from deps import *
import optparse
import logging
import blocks_pb2
from BlockUtil import *
from PEUtil import *
from capstone import x86

logging.basicConfig(level=logging.INFO)

# some decompiler decompile padding as instructions
paddingMap = dict()
paddingAddrList = set()


IMAGE_BASE = 0x0
CLASS_TYPE = 0x0

# in order to increase the speed, we expand the range list
def expandPadding():
    global paddingAddrList
    for (start, end) in paddingMap.items():
        [paddingAddrList.add(addr) for addr in range(start, start + end)]

def is_nop(md, content, current_addr):
    nop_group = {x86.X86_INS_NOP, x86.X86_INS_FNOP, x86.X86_INS_INT3}
    disasm_ins = md.disasm(content, current_addr, count = 1)
    try:
        cur_inst = next(disasm_ins)
    except StopIteration:
        return False

    if cur_inst != None and cur_inst.id in nop_group:
        return True
    return False

def get_file_offset(exec_secs, va, image_base):
    offset = None
    for cur_sec in exec_secs:
        if va >= cur_sec.addr + image_base and va <=  image_base + cur_sec.addr + cur_sec.size:
            offset = va - image_base - cur_sec.addr + cur_sec.offset
            break
    return offset

def compareInsts(groundTruth, compared, binary_path, md, exec_secs):
    """
    compare the basic blocks with their address, size, and successors
    """
    logging.info("Compare the Instrucstions:")
    falsePositive = 0 # false positive number
    falseNegitive = 0 # false negitive number
    truePositive = 0 # false negitive number
    nopInstructions = 0 # tools that identify padding bytes as instructions
    ## compute the false positive number

    open_binary = open(binary_path, 'rb')
    binary_content = open_binary.read()
    binary_length = len(binary_content)

    for inst in compared:
        if inst not in groundTruth:
            if inst in paddingAddrList:
                #logging.warning("[padding bytes %x is deemd as a instruction]" % (inst))
                nopInstructions += 1
            else:
                offset_addr = get_file_offset(exec_secs, inst, IMAGE_BASE)
                if offset_addr != None:
                    assert(offset_addr < binary_length)
                    end_offset = offset_addr + 64 if (offset_addr + 64) < binary_length else binary_length
                    disassemble_content = binary_content[offset_addr : end_offset]
                    if is_nop(md, disassemble_content, inst):
                        nopInstructions += 1
                    else:
                        logging.error("[Instruction False Positive #%d]Instruction address %x not in ground truth" % 
                            (falsePositive, inst))
                        falsePositive += 1
                else:
                    logging.error("[Instruction False Positive #%d]Instruction address %x not in ground truth" % 
                        (falsePositive, inst))
                    falsePositive += 1
        else:
            truePositive += 1

    cmp_num = len(compared) - nopInstructions

    ## compute the false negitive number
    for inst in groundTruth:
        if inst not in compared:
            logging.error("[Instruction False Negitive #%d]Instruction address %x not in compared" % 
                    (falseNegitive, inst))
            falseNegitive += 1

    print("[Result]:The total instruction number is %d" % (len(groundTruth)))
    print("[Result]:Instruction false positive number is %d, rate is %f" % 
            (falsePositive, falsePositive/len(groundTruth)))
    print("[Result]:Instruction false negitive number is %d, rate is %f" % 
            (falseNegitive, falseNegitive/len(groundTruth)))

    print("[Result]: Recall %f" % (truePositive/len(groundTruth)))
    print("[Result]: Precision %f" % (truePositive/cmp_num))

    open_binary.close()

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

                if inst_va not in tmpInstSet:
                    tmpInstSet.add(inst_va)

    return tmpInstSet


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-g", "--groundtruth", dest = "groundtruth", action = "store", \
            type = "string", help = "ground truth file path", default = None)
    parser.add_option("-c", "--comparedfile", dest = "comparedfile", action = "store", \
            type = "string", help = "compared file path", default = None)

    parser.add_option("-b", "--binaryfile", dest = "binaryfile", action = "store", \
            type = "string", help = "binary file path", default = None)


    (options, args) = parser.parse_args()
    if options.groundtruth == None:
        print("Please input the ground truth file")
        exit(-1)
    if options.comparedfile == None:
        print("Please input the compared file")
        exit(-1)

    if options.binaryfile == None:
        print("Please input the binary file")
        exit(-1)

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

    truthInsts = readInstructions(mModule1, True)
    comparedInsts = readInstructions(mModule2, False)

    expandPadding()

    (IMAGE_BASE, class_type) = parsePEFile(options.binaryfile)
    exec_secs = parsePEExecSecs(options.binaryfile)

    md = init_capstone(class_type)

    compareInsts(truthInsts, comparedInsts, options.binaryfile, md, exec_secs)
