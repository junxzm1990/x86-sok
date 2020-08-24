'''
file: radareBlocks.py
dependencies: radare2, r2pipe, json, optparse

Extract the radare's basic block related information.
'''
from deps import *
import optparse
import logging
import r2pipe
import json
import sys
import blocks_pb2

logging.basicConfig(format = "%(asctime)-15s %(levelname)s:%(message)s", level = logging.INFO)

def outputFuncMatching(afl_func_result, func_sets, output_sta):
    file_sta = open(output_sta, "w")
    logging.debug("Output Function Matching Information...")
    output_str = "===================Function Matching Information:==================\n"
    for (idx, func_addr) in enumerate(func_sets):
        logging.debug("Func #%d: 0x%x" % (idx, func_addr))
        output_str += ("Func #%d: 0x%x\n" % (idx, func_addr))
    output_str += ("All function numbers: %d\n" % (len(afl_func_result)))
    output_str += ("Function matching numbers: %d\n" % (len(func_sets)))
    output_str += ("Function matching rate: %f" % (len(func_sets) / len(afl_func_result)))
    file_sta.write(output_str)
    file_sta.close()

def dumpBlocks(binary, output, statics):
    prelude_funcs = set()
    try:
        r2 = r2pipe.open(binary)
    except:
        logging.error("r2pipe open binary error!")
        exit(-1)

    pbModule = blocks_pb2.module()
    ## analyse all
    #r2.cmd('aaa')
    r2.cmd('aa')
    r2.cmd('e anal.depth = 0x10000000')
    # recursivly disassemble from main function
    r2.cmd('s main')
    r2.cmd("afr")
    # aac heuristic, default is on in `aaa` analysis
    r2.cmd('aac')
    # scan the function prologue
    logging.debug("Before aap Analysis...")
    prelude_results = r2.cmd('aap')
    logging.debug(prelude_results)
    logging.debug("Done aap Analysis!")
    count_prelude = 0x0
    for res in prelude_results.split('\n'):
        # demo output: [Binpang Debug]: Preludecnt number is 3
        if "Binpang" not in res:
            continue
        if "Preclude" in res:
            prelude_addr = int(res.split()[-1], 16)
            prelude_funcs.add(prelude_addr)
        else:
            count_prelude += int(res.split()[-1], 10)

    r2.cmd('aanr')
    afl_result = r2.cmd('aflj')
    afl_result = json.loads(afl_result)
    all_func_result = set()
    for func in afl_result:
        func_addr = func['offset']
        if func_addr in all_func_result:
            continue
        no_return = func['noreturn']
        all_func_result.add(func_addr)
        pbFunc = pbModule.fuc.add()
        pbFunc.va = func_addr
        if no_return == True:
            pbFunc.type = 0x5

        logging.info("Find function in %x" % (func_addr))
        # seek the function start address
        r2.cmd('s %d' % func_addr)
        # output current function's basic block information
        afb_result = r2.cmd("afbj")
        try:
            afb_result = json.loads(afb_result)
        except:
            continue
        for bb in afb_result:
            bb_addr = bb['addr']
            bb_size = bb['size']
            pbBB = pbFunc.bb.add()
            pbBB.va = bb_addr
            pbBB.size = bb_size
            pbBB.parent = func_addr
            logging.info("Find basic block %x" % bb_addr)
            r2.cmd('s %d' % bb_addr)
            inst_num = bb['ninstr']
            inst_result = r2.cmd('pdj %d' % bb['ninstr'])
            try:
                inst_result = json.loads(inst_result)
            except:
                continue
            for inst in inst_result:
                inst_addr = inst['offset']
                inst_size = inst['size']
                logging.info("Find instruction %x, size %x" % (inst_addr, inst_size))
                instruction = pbBB.instructions.add()
                instruction.va = inst_addr
                instruction.size = inst_size

            # basic block fail address
            bb_fail = bb.get("fail", None)
            # basic block jump address
            bb_jmp = bb.get("jump", None)
            if bb_fail != None:
                logging.info("Successor: 0x%x" % (bb_fail))
                child = pbBB.child.add()
                child.va = bb_fail
            if bb_jmp != None:
                logging.info("Successor: 0x%x" % (bb_jmp))
                child = pbBB.child.add()
                child.va = bb_jmp

            # get switch cases successors
            switch_op = bb.get("switch_op", None)
            if switch_op == None:
                continue
            bb_cases = switch_op.get("cases", None)
            if bb_cases == None:
                continue
            visited_cases = set()
            for (idx, case) in enumerate(bb_cases):
                if case['addr'] in visited_cases:
                    continue
                visited_cases.add(case['addr'])
                logging.info("jmptbl successor#%d: 0x%x" % (idx, case['addr']))
                child = pbBB.child.add()
                child.va = case['addr']

    f = open(output, "wb")
    f.write(pbModule.SerializeToString())
    f.close()

    # dump scan function information
    outputFuncMatching(all_func_result, prelude_funcs, statics)
    #file_sta = open(statics, "w+")
    #logging.debug("Output Function Matching Information...")
    #output_str = "======================Function Matching Information:========================\n"
    #func_idx = 0

    #output_str += ("All function numbers: %d\n" % (len(all_func_result)))
    #output_str += ("Function matching numbers: %d\n" % (count_prelude))
    #output_str += ("Function matching rate: %f" % (count_prelude / len(all_func_result)))
    #file_sta.write(output_str)
    #file_sta.close()


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-o", "--output", dest = "output", action = "store", type = "string", \
                        help = "output of the protobuf file", default = "/tmp/radare_blocks.pb2")
    parser.add_option("-b", "--binary", dest = "binary", action = "store", type = "string", \
                        help = "binary file", default = None)
    parser.add_option("-s", "--statistics", dest = "statistics", action= "store", type = "string", \
            help = "output of statistics of the tool. Such as the count of function matching.", default= "/tmp/Sta_radare.log")

    (options, args) = parser.parse_args()
    if options.binary == None:
        logging.error("Please input the binary file")
        exit(-1)

    dumpBlocks(options.binary, options.output, options.statistics)

