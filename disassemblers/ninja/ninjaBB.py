from deps import *
import sys
import binaryninja as binja
import optparse
import os

import blocks_pb2

def dumpBlocks(bv, output):
    module = blocks_pb2.module()
    for (func_idx, func) in enumerate(bv.functions):
        pbFunc = module.fuc.add()
        pbFunc.va = func.start
        binja.log_info("Function {0}: {1}".format(func_idx, func.start))
        for (blk_idx, block) in enumerate(func):
            blk_start = None
            pbBB = pbFunc.bb.add()
            pbBB.va = block.start
            # can't get the basic block size for now
            pbBB.parent = pbFunc.va
            block_start = block.start
            binja.log_info("\tBasic Block {0:x}: {1:x}".format(blk_idx, block_start))
            insn_cur = block_start
            if not block.can_exit:
                pbBB.type = 0x20 # ninja potentially non-return type
                binja.log_info("\t bb 0x%x can exit" % pbBB.va)

            for insn in block:
                instruction = pbBB.instructions.add()
                instruction.va = insn_cur
                binja.log_info("\t\t{0:x}".format(insn_cur))
                insn_cur += insn[1]
            for (successor_idx, out_edge) in enumerate(block.outgoing_edges):
                print(out_edge)
                binja.log_info("\t\tsuccessor {0:x}: {1:x}".format(successor_idx, out_edge.target.start))
                child = pbBB.child.add()
                child.va = out_edge.target.start
    f = open(output, "wb")
    f.write(module.SerializeToString())
    f.close()

if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("-o", "--output", dest = "output", action= "store", type = "string", \
            help = "output of the protobuf file", default = "/tmp/angr_blocks.pb2") 
    parser.add_option("-b", "--binary", dest = "binary", action = "store", type = "string", \
            help = "binary file", default = None)
    parser.add_option("-s", "--ss", dest = "ss", action = "store", type = "string", \
            help = "binary file", default = None)
    (options, args) = parser.parse_args()
    if options.binary == None:
        binja.log_info("please input the binary file")
        exit(-1)

    bv = binja.BinaryViewType.get_view_of_file(options.binary)
    #binja.log_to_stdout(binja.LogLevel.DebugLog)
    binja.log_to_stdout(binja.LogLevel.ErrorLog)
    #binja.log_info("----------------- %s ------------" % options.binary)
    binja.log_info("START: 0x%x" % bv.start)
    binja.log_info("ENTRY: 0x%x" % bv.entry_point)
    binja.log_info("ARCH: %s" % bv.arch.name)
    binja.log_info("\n--------------- Function List -----------")
    #bv.update_analysis_and_wait()
    dumpBlocks(bv, options.output)
