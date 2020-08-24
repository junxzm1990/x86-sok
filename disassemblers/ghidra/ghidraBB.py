#TODO write a description for this script
#@author 
#@category Functions
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here

# reference https://github.com/NationalSecurityAgency/ghidra/issues/826
from __future__ import division
import logging
import site
import sys
import os

from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.block import CodeBlockIterator
from ghidra.program.model.block import CodeBlockReference 
from ghidra.program.model.block import CodeBlockReferenceIterator 
from ghidra.program.model.listing import CodeUnitIterator;
from ghidra.program.model.listing import Function;
from ghidra.program.model.listing import FunctionManager;
from ghidra.program.model.listing import Listing;
from ghidra.program.database.code import InstructionDB
# as ghidra uses jython
# add the default python27 dist-packages to the sys path
# protobuf is installed in these two pathes
sys.path.append('/usr/local/lib/python2.7/dist-packages')
sys.path.append('/usr/lib/python2.7/dist-packages')
# print("current python version is {0}".format(site.getsitepackages()))
# print(os.path.join(os.path.dirname(os.path.realpath("__file__")), "../protobuf_def"))
#protobuf_path = os.path.join(os.path.dirname(os.path.realpath("__file__")), "../protobuf_def")
# sys.path.append("../protobuf_def")
#sys.path.append(protobuf_path)
import blocks_pb2

logging.basicConfig(level = logging.ERROR)

def addBB(pbBB, bb, pbFunc):
    pbBB.size = bb.getMaxAddress().subtract(bb.getMinAddress()) + 1
    pbBB.va = bb.getMinAddress().getOffset()
    pbBB.parent = pbFunc.va
    logging.debug("The basic block address is 0x{0:x}, size is {1}".format(pbBB.va, pbBB.size))

    listing = currentProgram.getListing();
    # iter over the instructions
    codeUnits = listing.getCodeUnits(bb, True)
    lastInstStart = 0x0
    lastInstEnd = 0x0
    while codeUnits.hasNext():
        codeUnit = codeUnits.next()
        # check if the code unit is the instruction
        if not isinstance(codeUnit, InstructionDB):
            continue
        logging.debug("Instruction address is 0x{0:x}, size is {1}"\
                .format(codeUnit.getAddress().getOffset(), codeUnit.getLength()))
        pbInst = pbBB.instructions.add()
        pbInst.va = codeUnit.getAddress().getOffset()
        pbInst.size = codeUnit.getLength()
        lastInstStart = pbInst.va
        lastInstEnd = pbInst.va + pbInst.size

    # get successors
    successors = bb.getDestinations(monitor)
    idx = 0
    sucSet = set()
    while successors.hasNext():
        sucBBRef = successors.next()
        sucBBRefAddr = sucBBRef.getReferent().getOffset()
        # the reference is not in the last instruction
        if sucBBRefAddr < lastInstStart or sucBBRefAddr >= lastInstEnd:
            continue
        sucBB = sucBBRef.getDestinationBlock()
        sucOffset = sucBB.getFirstStartAddress().getOffset()
        if sucOffset in sucSet:
            continue
        idx += 1
        sucSet.add(sucOffset)
        child = pbBB.child.add()
        child.va = sucOffset
        logging.debug("Successor {0}: 0x{1:x}".format(idx, sucOffset))


def dumpBlocks(output):
    bbModel = BasicBlockModel(currentProgram)
    functionManager = currentProgram.getFunctionManager()
    module = blocks_pb2.module()
    # record the basic block that has been added by functions
    bb_set = set()
    # get all functions
    funcs_set = set()
    for func in functionManager.getFunctions(True):
        # we skip external functions
        if func.isExternal():
            continue
        func_va = func.getEntryPoint().getOffset()
        if func_va in funcs_set:
            continue
        funcs_set.add(func_va)
        logging.debug("Function address is 0x{0:x}".format(func.getEntryPoint().getOffset()))
        codeBlockIterator = bbModel.getCodeBlocksContaining(func.getBody(), monitor);
        pbFunc = module.fuc.add()
        pbFunc.va = func.getEntryPoint().getOffset()

        if func.hasNoReturn():
            pbFunc.type = 0x5
            logging.debug("function at 0x%x does not return!" % pbFunc.va)

        # iter over the basic blocks
        while codeBlockIterator.hasNext(): 
            bb = codeBlockIterator.next()
            pbBB = pbFunc.bb.add()
            bb_set.add(bb.getMinAddress().getOffset())
            addBB(pbBB, bb, pbFunc)
    
    codeBlocks = bbModel.getCodeBlocks(monitor)
    dummy_func = module.fuc.add()
    dummy_func.va = 0x0
    while codeBlocks.hasNext():
        bb = codeBlocks.next()
        if bb.getMinAddress().getOffset() in bb_set:
            continue
        pbBB = dummy_func.bb.add()
        bb_set.add(bb.getMinAddress().getOffset())
        logging.debug("Find another basic block 0x%x" % (bb.getMinAddress().getOffset()))
        addBB(pbBB, bb, dummy_func)

    f = open(output, "wb")
    f.write(module.SerializeToString())
    f.close()

def getFuncStartMatching(output):
    FUNCTION_START = "Function Start Search"
    functionManager = currentProgram.getFunctionManager()
    bookMgr = currentProgram.getBookmarkManager();
    bookAddrs= bookMgr.getBookmarkAddresses("Analysis")
    #print(bookmarks)
    #for addr in bookmarks:
    #    logging.debug("Got it!")
    bookAddrs = bookAddrs.getAddresses(True)
    func_start_count = 0
    output_str = "====================Function Matching Information:========================\n"
    while bookAddrs.hasNext():
        bookAddr = bookAddrs.next()
        bookmark = bookMgr.getBookmark(bookAddr, "Analysis", FUNCTION_START)
        if bookmark != None:
            output_str += ("Func #%d: 0x%x\n" % (func_start_count, bookAddr.getOffset()))
            logging.debug("Got it! The address is 0x%x" % (bookAddr.getOffset()))
            func_start_count += 1

    logging.info("The number of function start search bookmark is %d" % (func_start_count))
    functionManager = currentProgram.getFunctionManager()
    total_func_count = 0
    for func in functionManager.getFunctions(True):
        if func.isExternal():
            continue
        total_func_count += 1

    output_str += ("All function numbers: %d\n" % (total_func_count))
    output_str += ("Function matching numbers: %d\n" % (func_start_count))
    output_str += ("Function matching rate: %f" % (func_start_count / total_func_count))

    f = open(output, "w")
    f.write(output_str)
    f.close()

if __name__ == "__main__":
    # parser = optparse.OptionParser()
    # parser.add_option("-o", "--output", dest = "output", action = "store", type = "string", \
    #        help = "output of the protobuf file", default = "/tmp/ghidra_block.pb2")
    # (options, args) = parser.parse_args()
    output = "/tmp/ghidra_block.pb2"
    funcStartOutput = "/tmp/Stat_ghidra.log"
    # FIXME: Here, can't get the argument by sys.argv from ghidra analyzeHeadless
    # if len(sys.argv) > 1:
    #     output = sys.argv[1]
    
    # Get the output path from environment variable
    try:
        if os.environ['GHIDRA_OUT_PATH']:
            output = os.environ['GHIDRA_OUT_PATH']
            logging.debug("ghidra output path is {0}".format(os.environ['GHIDRA_OUT_PATH']))
        if os.environ['GHIDRA_STAT_OUT_PATH']:
            funcStartOutput = os.environ['GHIDRA_STAT_OUT_PATH']
            logging.debug("Ghidra stat output path is {0}".format(os.environ['GHIDRA_STAT_OUT_PATH']))
    except:
        pass
    dumpBlocks(output)
    getFuncStartMatching(funcStartOutput)
