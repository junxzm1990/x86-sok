"""
file: compareCFG.py
date: 08/01/2019
author: binpang
compare the functions and basic blocks information
between ground truth(ccr) and compared tool
"""
from deps import *
import optparse
import logging
import cxxfilt
import bbinfoconfig as bbl
import blocks_pb2
from elftools.elf.elffile import ELFFile
from BlockUtil import *

logging.basicConfig(level=logging.INFO)

# some decompiler decompile padding as instructions
paddingMap = dict()
paddingAddrList = set()

# plt range
pltAddr = 0
pltSize = 0

linkerExcludeFunction = dict()
groundTruthFuncRange = dict()

# default _init and _fini function size
default_x86_get_pc_thunk_bx = 0x10

notIncludedLinkerFunc = set()

# pie/pic base address
# angr base address is 0x400000
# ghidra base address is 0x100000
# others are 0x0
BASE_ADDR_MAP = {"angr": 0x400000, "ghidra": 0x100000}
disassembler_base_addr = 0x0
PIE = False

ELFCLASS = 64

textAddr = 0
textSize = 0
textOffset = 0
FuncRanges = dict()
GroundTruthFunc = set()
GroundTruthRange = list()

def isInPltSection(addr):
    if addr >= pltAddr and addr < pltAddr + pltSize:
        return True
    return False

def isInTextSection(addr):
    if addr >= textAddr and addr < textAddr + textSize:
        return True
    return False

def isInExcludeRange(addr):
    for (start, end) in linkerExcludeFunction.items():
        if addr >= start and addr < (start + end):
            return True
    return False

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

def parseCallInsts(content, cur_addr, count_ = None):
    MD = init_capstone(ELFCLASS)
    if count_ == None:
        disasm_ins = MD.disasm(content, cur_addr)
    else:
        disasm_ins = MD.disasm(content, cur_addr, count = count_)
    result = set()
    indirect_result = set()
    last_inst = None
    while True:
        try:
            cur_inst = next(disasm_ins)
        except StopIteration:
            break

        if cur_inst == None:
            continue
        last_inst = cur_inst
        if x86.X86_GRP_CALL in cur_inst.groups:
            if isIndirect(cur_inst):
                logging.debug("indirect call instruction is 0x%x" % cur_inst.address)
                indirect_result.add(cur_inst.address)
            else:
                result.add(cur_inst.address)
    return result, indirect_result, last_inst

def readGroundCFG(mModule, binary):
    """
    parse ground truth cfg from protobuf
    params:
        mModule: protobuf module
        groundTruth: if this is the groundTruth file
        jmptbl_insts: jump table indirect jump insts
    returns:
        cfg
        cg: call instructions
        jmptbl_edges: jump table edges
        non_ret: non-ret related edges
    """
    call_insts = set()
    indirect_jumps = set()
    indirect_calls = set()
    edges = dict()
    non_ret_calls = set()
    open_binary = open(binary, 'rb')
    content = open_binary.read()
    textEndOffset = textSize + textOffset
    tmpFuncSet = set()
    global groundTruthFuncRange
    for func in mModule.fuc:
        logging.debug("current function is 0x%x", func.va)
        funcAddr = func.va
        if funcAddr not in tmpFuncSet:
            tmpFuncSet.add(funcAddr)
        else:
            logging.warning("repeated handle the function in address %x" % func.va)
            continue

        no_call = True
        all_successors = set()
        for bb in func.bb:
            # parse all call instructions
            if bb.size > 0:
                bb_offset = bb.va - textAddr + textOffset
                bb_end_offset = bb_offset + bb.size 

                (call_sets, indirect_call_sets, _) = parseCallInsts(content[bb_offset: bb_end_offset], bb.va)

                # store direct and indirect calls
                call_insts = call_insts.union(call_sets)
                indirect_calls = indirect_calls.union(indirect_call_sets)

            if bb.type == BlockType.DIRECT_CALL or bb.type == BlockType.INDIRECT_CALL:
                no_call = False
            else:
                [all_successors.add(suc.va) for suc in bb.child]

            # check if current terminator is jump table indirect jumps
            if len(bb.child) > 2:
                assert len(bb.instructions) > 0, \
                        "[readJmpTables]: The basic block 0x%x does not contain any instruction!" % (bb.va)
                terminator_addr = bb.instructions[-1].va
                if not isInTextSection(terminator_addr):
                    continue

                offset = terminator_addr - textAddr + textOffset
                endOffset = (offset + 20) if (offset + 20) < textEndOffset else textEndOffset
                disassemble_content = content[offset: endOffset]
                MD = init_capstone(ELFCLASS)
                if checkTerminatorIsIndirectJump(MD, disassemble_content, terminator_addr):
                    indirect_jumps.add(terminator_addr);

            for inst in bb.instructions:
                groundTruthFuncRange[inst.va] = inst.size

        if not no_call:
            merge_call_edges(func, all_successors)

        for bb in func.bb:
            if bb.type == BlockType.INVALID_BB:
                continue

            cur_hash = hash64(bb.va)
            # collect all non-ret call instruction
            if bb.type == BlockType.NON_RETURN_CALL:
                non_ret_calls.add(bb.instructions[-1].va)
            else:
                for suc in bb.child:
                    # edge = prev_bb ^ (suc_bb >> 1)
                    suc_hash = hash64(suc.va) >> 1
                    hash_result = cur_hash ^ suc_hash
                    edges[hash_result] = (bb.va, suc.va)

    return (call_insts, indirect_calls, indirect_jumps, edges, non_ret_calls)

def readComparedCFG(mModule, binary, jtable_jumps):
    """
    parse compared cfg from protobuf
    params:
        mModule: protobuf module
        groundTruth: if this is the groundTruth file
        jmptbl_insts: jump table indirect jump insts
    returns:
        cfg
        cg: call instructions
        jmptbl_edges: jump table edges
        non_ret: non-ret related edges
    """
    call_insts = set()
    indirect_calls = set()
    edges = dict()
    non_ret_calls = set()
    open_binary = open(binary, 'rb')
    content = open_binary.read()
    textEndOffset = textSize + textOffset
    tmpFuncSet = set()
    for func in mModule.fuc:
        all_successors = set()
        funcAddr = func.va

        if PIE:
            funcAddr = func - disassembler_base_addr

        if funcAddr not in tmpFuncSet:
            tmpFuncSet.add(funcAddr)
        else:
            logging.warning("repeated handle the function in address %x" % func.va)
            continue

        if not isInTextSection(funcAddr) or isInPltSection(funcAddr):
            continue

        # first step, mark DIRECT_CALL Type of basic block
        no_call = True
        fall_through_edges = dict()
        last_call_inst = None
        for bb in func.bb:
            cur_bb_call = set()
            cur_bb_indirect = set()

            bb_va = bb.va
            if PIE:
                bb_va = bb_va - disassembler_base_addr

            # parse all call instructions
            if bb.size > 0:
                bb_offset = bb_va - textAddr + textOffset
                bb_end_offset = bb_offset + bb.size 
                (call_sets, indirect_set, last_inst) = parseCallInsts(content[bb_offset: bb_end_offset], bb.va)
                cur_bb_call = cur_bb_call.union(call_sets)
                cur_bb_indirect = cur_bb_indirect.union(indirect_set)

                if len(bb.instructions)> 0 and bb.instructions[-1].size == 0 and last_inst:
                    bb.instructions[-1].size = last_inst.size

            else:
                for inst in bb.instructions:
                    inst_va = inst.va - disassembler_base_addr
                    inst_offset = inst_va - textAddr + textOffset
                    inst_end_offset = (inst_offset + 20) if (inst_offset + 20) < textEndOffset else textEndOffset
                    (call_sets, indirect_set, last_inst) = parseCallInsts(content[inst_offset: inst_end_offset], inst.va, 1)

                    cur_bb_call = cur_bb_call.union(call_sets)
                    cur_bb_indirect = cur_bb_indirect.union(indirect_set)
                    if inst.size == 0 and last_inst:
                        inst.size = last_inst.size

            if len(cur_bb_call) == 1 and \
                    bb.instructions[-1].va == list(cur_bb_call)[0]:
                # current basic block's terminator is a direct call
                # and fall through
                if len(bb.child) == 2:
                    bb.type = BlockType.DIRECT_CALL
                    no_call = False
                else: # child number is 1. deem it as non-return call
                    bb.type == BlockType.NON_RETURN_CALL
            # indirect call type
            elif len(cur_bb_indirect) == 1 and \
                    bb.instructions[-1].va == list(cur_bb_indirect)[0]:
                no_call = False
                bb.type = BlockType.INDIRECT_CALL
            else:
                [all_successors.add(suc.va) for suc in bb.child]

            if last_inst != None and x86.X86_GRP_RET in last_inst.groups:
                bb.type = BlockType.RET

            call_insts = call_insts.union(cur_bb_call)
            indirect_calls = indirect_calls.union(cur_bb_indirect)
            

        # merge call edges into cfg
        if not no_call:
            merge_call_edges(func, all_successors)

        for bb in func.bb:

            if bb.type in {BlockType.INVALID_BB, BlockType.RET}:
                continue

            if isInExcludeRange(bb.va - disassembler_base_addr):
                continue

            if len(bb.instructions) > 0:
                terminator_addr = bb.instructions[-1].va - disassembler_base_addr
                
                if terminator_addr not in jtable_jumps and len(bb.child) > 2:
                    # as these jump tables not in our ground truth,
                    # so we skip these edges
                    logging.debug("skip indirect jump at address 0x%x" % terminator_addr)
                    continue

            cur_hash = hash64(bb.va)
            for suc in bb.child:
                if suc.va == 0xffffffffffffffff:
                    continue
                # edge = prev_bb ^ (suc_bb >> 1)
                suc_hash = hash64(suc.va) >> 1
                hash_result = cur_hash ^ suc_hash
                edges[hash_result] = (bb.va, suc.va)

    return (call_insts, indirect_calls, edges)

def compareCFG(cfg_ground, cfg_compared):
    false_neg = 0
    false_pos = 0

    for (hash_val, edge) in cfg_ground.items():
        if hash_val not in cfg_compared:
            logging.error("False Negative %d, 0x%x -> 0x%x" % (false_neg, edge[0], edge[1]))
            false_neg += 1

    for (hash_val, edge) in cfg_compared.items():
        if hash_val not in cfg_ground:
            logging.error("False Positive %d, 0x%x -> 0x%x" % (false_pos, edge[0], edge[1]))
            false_pos += 1

    true_pos = len(cfg_compared) - false_pos
    logging.info("[Result]: All cfg edges in ground truth is %d" % len(cfg_ground))
    logging.info("[Result]: All cfg edges in compared is %d" % len(cfg_compared))
    logging.info("[Result]: False positive number is %d" % false_pos)
    logging.info("[Result]: False negative number is %d" % false_neg)
    logging.info("[Result]: Precision %f" % (true_pos / len(cfg_compared)))
    logging.info("[Result]: Recall %f" % (true_pos / len(cfg_ground)))

def pltRange(binary):
    with open(binary, 'rb') as openFile:
        elffile = ELFFile(openFile)
        for sec in elffile.iter_sections():
            if sec.name == '.plt':
                global pltSize
                global pltAddr
                pltSec = sec
                pltSize= pltSec['sh_size']
                pltAddr = pltSec['sh_addr']
                logging.info(".plt section addr: 0x%x, size: 0x%x" % (pltAddr, pltSize))

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
                if not isInTextSection(prev_func):
                    continue
                logging.info("current func is 0x%x, prev is 0x%x" % (func, prev_func))
                if linkerExcludeFunction[prev_func] != 0:
                    # update the linker function paddings
                    end_addr = prev_func + linkerExcludeFunction[prev_func]
                    padding_size = func - prev_func - linkerExcludeFunction[prev_func]
                    assert padding_size >= 0, "[getLinkerFunctionRange]: padding size < 0"
                    if padding_size < 0x30:
                        paddingMap[end_addr] = padding_size
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
    if options.groundtruth == None:
        print("Please input the ground truth file")
        exit(-1)
    if options.comparedfile == None:
        print("Please input the compared file")
        exit(-1)
    
    if options.binaryFile == None:
        print("Please input the binary file")
        exit(-1)

    pltRange(options.binaryFile)
    PIE = isPIE(options.binaryFile)
    if PIE:
        disassembler_base_addr = getPIEBaseOffset(options.comparedfile)
    readTextSection(options.binaryFile)

    ELFCLASS = readElfClass(options.binaryFile)
    elfarch = readElfArch(options.binaryFile)
    elfendian = readElfEndian(options.binaryFile)
    bbl.init(elfarch, ELFCLASS, elfendian)

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

    if "ghidra" in options.comparedfile and PIE:
        doubleCheckGhidraBase(mModule2)

    (call_truth, indirect_calls, indirect_jumps, edges_truth, non_ret_calls) =\
            readGroundCFG(mModule1, options.binaryFile)

    not_included = checkGroundTruthFuncNotIncluded(groundTruthFuncRange, options.binaryFile)
    if not_included != None:
        logging.info("Append the not included functions! {0}".format(not_included))
        notIncludedLinkerFunc |= not_included 
    getLinkerFunctionRange(options.binaryFile)

    (call_compared, indirect_calls_compared, edges_compared) = readComparedCFG(mModule2, options.binaryFile, indirect_jumps)
    compareCFG(edges_truth, edges_compared)
