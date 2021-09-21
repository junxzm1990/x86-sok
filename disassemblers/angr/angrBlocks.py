from deps import *
import angr
import logging
import optparse
import blocks_pb2
from BlockUtil import *

def outputFuncMatching(cfg, output_sta):
    file_sta = open(output_sta, "w")
    logging.debug("Output Function Matching Information...")
    output_str = "================Function Matching Information:====================\n"
    for (idx, func_addr) in enumerate(cfg.function_prologue_matching_addrs):
        logging.debug("Func #%d: 0x%x" % (idx, func_addr))
        output_str += ("Func #%d: 0x%x\n" % (idx, func_addr))
    output_str += ("All function numbers: %d\n" % (len(cfg.functions)))
    output_str += ("Function matching numbers: %d\n" % (len(cfg.function_prologue_matching_addrs)))
    output_str += ("Function matching rate: %f" % (len(cfg.function_prologue_matching_addrs) / len(cfg.functions)))
    file_sta.write(output_str)
    file_sta.close()
    
logging.getLogger('angr.analyses').setLevel(logging.ERROR)
def dumpBlocks(binary, output, output_sta):
    # "force_complete_scan" default is True
    p = angr.Project(binary, load_options={'auto_load_libs': False})
    cfg = p.analyses.CFGFast(normalize=True, detect_tail_calls = True)
    # output func matching counts
    # outputFuncMatching(cfg, output_sta)

    module = blocks_pb2.module()

    # iter over the cfg functions
    for func_addr in cfg.functions:
        func = cfg.functions[func_addr]
        if func.returning == False:
            print("Non-return function at 0x%x" % func.addr)

        if func.alignment:
            print("function 0x%x is alignment function, skip!" % (func.addr))
            continue

        # collect non-return calls
        current_non_bbs = set()
        for non_ret in func.callout_sites:
            if non_ret != None:
                print("non-return call at 0x%x" % non_ret.addr)
                current_non_bbs.add(non_ret.addr)
        #[current_non_bbs.add(non_ret.addr) for non_ret in func.callout_sites]
        pbFunc = module.fuc.add()
        pbFunc.va = func_addr
        print("function %s, its addr is 0x%x" % (func.name, func.addr))
        # iter over blocks
        for bb in func.blocks:
            if bb == None:
                continue
            print("basic block addr 0x%x, its size 0x%x" % (bb.addr, bb.size))
            cfg_node = cfg.get_any_node(bb.addr)
            # bb.instruction_addrs can get the instrction address of block
            if cfg_node != None and bb.size != 0:
                pbBB = pbFunc.bb.add()
                pbBB.va = bb.addr
                pbBB.size = bb.size
                pbBB.parent = func_addr
                successors = cfg_node.successors
                for suc in successors:
                    child = pbBB.child.add()
                    child.va = suc.addr
                    print("Edge 0x%x -> 0x%x" % (bb.addr, suc.addr))

                # iter over instructions
                # bb.instruction_addrs may have bug
                # we use capstone instead to extract instuction
                # for inst in bb.instruction_addrs:
                for inst in bb.capstone.insns:
                    inst_va = inst.address
                    instruction = pbBB.instructions.add()
                    instruction.va = inst_va
                    print("instruction: 0x%x" % (instruction.va))
                    # can't get its size from angr for now

            if bb.addr in current_non_bbs:
                pbBB.type = BlockType.NON_RETURN_CALL

    f = open(output, "wb")
    f.write(module.SerializeToString())
    f.close()

if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("-o", "--output", dest = "output", action= "store", type = "string", \
            help = "output of the protobuf file", default = "/tmp/angr_blocks.pb2") 
    parser.add_option("-b", "--binary", dest = "binary", action = "store", type = "string", \
            help = "binary file", default = None)
    parser.add_option("-s", "--statistics", dest = "statistics", action= "store", type = "string", \
            help = "output of statistics of the tool. Such as the count of function matching.", default= "/tmp/angr_statics.log")
    (options, args) = parser.parse_args()
    if options.binary == None:
        print("please input the binary file")
        exit(-1)

    dumpBlocks(options.binary, options.output, options.statistics)
