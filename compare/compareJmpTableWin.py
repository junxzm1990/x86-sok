from deps import *
import optparse
import logging
import capstone as cs
import functools

import blocks_pb2
from capstone import x86
from BlockUtil import *
from PEUtil import *


logging.basicConfig(format = "%(asctime)-15s %(levelname)s:%(message)s", level=logging.INFO)

IMAGE_BASE = 0x0

def xor(x, y):
    return x ^ y

def hash64(x):
    x = (x ^ (x >> 30)) * (0xbf58476d1ce4e5b9)
    x = (x ^ (x >> 27)) * (0x94d049bb133111eb)
    x = x ^ (x >> 31)
    return x

def compareJmpTables(groundTruth, compared):
    """
    compare the jump tables
    """
    logging.info("Compare Jump tables:")
    falsePositive = 0 # false positive number
    falseNegitive = 0 # false negitive number
    nopInstructions = 0 # tools that identify padding bytes as instructions
    truePositive = 0
    successorWrong = 0

    ## compute the false positive number
    for (terminator, successors) in compared.items():
        not_in_groundTruth = True
        equal_groundTruth = False
        groundTruth_successors = None
        for (t_terminator, t_successors) in groundTruth.items():
            tmp_s = successors - t_successors
            # find the corrosponding jtable
            if len(tmp_s) < len(successors):
                not_in_groundTruth = False
                if len(t_successors) != len(successors):
                    groundTruth_successors = t_successors
                else:
                    equal_groundTruth = True
                    break

        if equal_groundTruth:
            continue

        if not_in_groundTruth:
            indirect_result = ", ".join(f"0x{x:x}" for x in successors)
            logging.error("[Jump Table False Positive #{0}]:Switch basic block terminator address {1:x} not in ground truth. Successors is {2}".format(falsePositive, terminator, indirect_result))
            falsePositive += 1
        elif groundTruth_successors != None:
            ground_truth_result = ", ".join(f"0x{x:x}" for x in groundTruth_successors)
            successors_result = ", ".join(f"0x{x:x}" for x in successors)
            logging.error("[Jump Table successors wrong #{0} in 0x{1:x}]: \n Ground Truth is {2}\n compared is {3}".format(successorWrong, terminator, ground_truth_result, successors_result))
            successorWrong += 1


    ## compute the false negitive number
    for (terminator, successors) in groundTruth.items():
        not_in_compared = True

        for (t_terminator, t_successors) in compared.items():
            if len(successors - t_successors) < len(successors):
                not_in_compared = False
                break
        if not_in_compared:
            ground_truth_result = ", ".join(f"0x{x:x}" for x in successors)
            logging.error("[Instruction False Negitive #%d]Instruction address %x not in compared. Ground Truth is %s" % 
                    (falseNegitive, terminator, ground_truth_result))
            falseNegitive += 1

    print("[Result]:The total jump table in ground truth is %d" % (len(groundTruth)))
    print("[Result]:The total jump table in compared is %d" % (len(compared)))
    print("[Result]:False negitive number is %d" % (falseNegitive))
    print("[Result]:Wrong successors number is %d" % (successorWrong))
    print("[Result]:False positive number is %d" % (falsePositive))
    try:
        print("[Result]: Recall: %f" % (1 - (falseNegitive/len(groundTruth))))
        print("[Result]: Precision: %f" % (1 - ((successorWrong + falsePositive)/(len(compared)))))
    except:
        pass
            
def readJmpTables(mModule, binary, MD, exec_secs):
    """
    read jump tables from protobufs
    params:
        mModule: protobuf module
    returns:
        jmp tables: store the result of jmp tables
    """
    tmpFuncSet = set()
    result = dict()
    indirect_insts = dict()
    open_binary = open(binary, 'rb')
    content = open_binary.read()
    content_len = len(content)
    for func in mModule.fuc:
        funcAddr = func.va
        if funcAddr not in tmpFuncSet:
            tmpFuncSet.add(funcAddr)
        else:
            logging.warning("repeated handle the function in address %x" % func.va)
            continue

        for bb in func.bb:
            # If the number of basic block's successors number is bigger than 2 
            if len(bb.child) > 2:
                assert len(bb.instructions) > 0,\
                        "[readJmpTables]: The basic block 0x%x does not contain any instruction!" % (bb.va)
                terminator_addr = bb.instructions[-1].va

                offset = get_file_offset(exec_secs, terminator_addr, IMAGE_BASE)

                # we assume that any instruction length is less than 20 bytes
                endOffset = (offset + 48) if (offset + 48) < content_len else content_len
                disassemble_content = content[offset: endOffset]
                if not checkTerminatorIsIndirectJump(disassemble_content, terminator_addr):
                    continue
                successors = set()
                for suc in bb.child:
                    if suc.va < IMAGE_BASE:
                        successors.add(suc.va + IMAGE_BASE)
                    else:
                        successors.add(suc.va)

                '''
                # hash integer and xor them
                tmp_successors = set()
                [tmp_successors.add(hash64(suc)) for suc in successors]
                hashed_result = functools.reduce(xor, tmp_successors)
                '''

                result[terminator_addr] = successors
    return result

def checkTerminatorIsIndirectJump(disassemble_content, current_addr):
    disasm_ins = MD.disasm(disassemble_content, current_addr, count = 1)
    try:
        cur_inst = next(disasm_ins)
    except StopIteration:
        return False 
    if cur_inst != None and x86.X86_GRP_JUMP in cur_inst.groups and isIndirect(cur_inst):
        return True
    return False


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

    (IMAGE_BASE, elfclass) = parsePEFile(options.binaryFile)

    MD = init_capstone(elfclass)

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

    exec_secs = parsePEExecSecs(options.binaryFile)

    truthTables = readJmpTables(mModule1, options.binaryFile, MD, exec_secs)
    comparedTables = readJmpTables(mModule2, options.binaryFile, MD, exec_secs)
    compareJmpTables(truthTables, comparedTables)
