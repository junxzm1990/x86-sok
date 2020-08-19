from deps import *
import optparse
import logging
import capstone as cs

import blocks_pb2
from PEUtil import *


logging.basicConfig(level=logging.INFO)

def compareFuncs(groundTruth, compared, thunks_set):
    """
    compare the jump tables
    """
    logging.info("Compare Funcs Start:")
    falsePositive = 0 # false positive number
    falseNegitive = 0 # false negitive number
    truePositive = 0
    thunks_cnt = 0

    ## compute the false positive number
    for func in compared:
        if func not in groundTruth:
            if func in thunks_set:
                thunks_cnt += 1
                continue
            else:
                logging.error("[Func Start False Positive #{0}]:Function Start 0x{1:x} not in Ground Truth.".format(falsePositive, func))
                falsePositive += 1
        else:
            truePositive += 1

    ## compute the false negitive number
    for func in groundTruth:
        if func not in compared:
            logging.error("[Func Start False Negitive #{0}]:Function Start 0x{1:x} not in compared.".format(falseNegitive, func))
            falseNegitive += 1

    logging.info("[Result]:The total Functions in ground truth is %d" % (len(groundTruth)))
    logging.info("[Result]:The total Functions in compared is %d" % (len(compared) - thunks_cnt))
    logging.info("[Result]:False positive number is %d" % (falsePositive))
    logging.info("[Result]:False negitive number is %d" % (falseNegitive))
    logging.info("[Result]: Precision %f" % (truePositive / (len(compared) - thunks_cnt)))
    logging.info("[Result]: Recall %f" % (truePositive / len(groundTruth)))


def readFuncs(mModule):
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
        # this is the dummy function
        if func.va == 0x0:
            continue

        funcAddr = func.va
        if funcAddr not in tmpFuncSet:
            tmpFuncSet.add(funcAddr)
        else:
            logging.warning("repeated handle the function in address %x" % func.va)
            continue
    return tmpFuncSet

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-g", "--groundtruth", dest = "groundtruth", action = "store", \
            type = "string", help = "ground truth file path", default = None)
    parser.add_option("-c", "--comparedfile", dest = "comparedfile", action = "store", \
            type = "string", help = "compared file path", default = None)
    parser.add_option("-b", "--binaryfile", dest = "binaryfile", action = "store", \
            type = "string", help = "binary file path", default = None)
    parser.add_option("-p", "--pdbfile", dest = "pdbfile", action = "store", \
            type = "string", help = "debug file(pdb) path", default = None)

    (options, args) = parser.parse_args()

    assert options.groundtruth != None, "Please input the ground truth file!"
    assert options.comparedfile != None, "Please input the compared file!"
    assert options.binaryfile != None, "Please input the ground truth file!"
    assert options.pdbfile != None, "Please input the ground truth file!"
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
    secs = parsePESecs(options.binaryfile)
    (image_base, _) = parsePEFile(options.binaryfile)

    thunks_set = parseThunkSyms(options.pdbfile, secs, image_base)
    truthFuncs = readFuncs(mModule1)
    comparedFuncs = readFuncs(mModule2)
    compareFuncs(truthFuncs, comparedFuncs, thunks_set)
