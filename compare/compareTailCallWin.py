from deps import *
import optparse
import logging
import blocks_pb2
from elftools.elf.elffile import ELFFile
from BlockUtil import *
from PEUtil import *

logging.basicConfig(level=logging.INFO)

# some decompiler decompile padding as instructions
paddingMap = dict()
paddingAddrList = set()

linkerFuncAddr = dict()
# plt range
pltAddr = 0
pltSize = 0

linkerExcludeFunction = dict()
groundTruthFuncRange = dict()

def readGroundTruthFuncsRange(mModule):
    global groundTruthFuncRange
    for func in mModule.fuc:
        funcAddr = func.va
        for bb in func.bb:
            groundTruthFuncRange[bb.va] = bb.size

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

NORMAL_CFG_TOOL = {"ghidra", "ida", "ninja", "radare"}
NO_INTEPROC_CALL_TOOL = {"ninja", "bap", "ida", "radare"} 
NO_INTEPROC_CALL = False
NORMAL_CFG = False
isAngr = False
isBAP = False

def isInPltSection(addr):
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

def parseCallInsts(MD, content, cur_addr, count_ = None):
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
                indirect_result.add(cur_inst.address - disassembler_base_addr)
            else:
                logging.debug("call instruction is 0x%x" % cur_inst.address)
                result.add(cur_inst.address - disassembler_base_addr)
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
    instructions = set()
    non_ret_edges = dict()
    tail_calls = dict()

    open_binary = open(binary, 'rb')
    tmpFuncSet = set()

    for func in mModule.fuc:
        logging.debug("current function is 0x%x", func.va)
        funcAddr = func.va
        if funcAddr not in tmpFuncSet:
            tmpFuncSet.add(funcAddr)
        else:
            logging.warning("repeated handle the function in address %x" % func.va)
            continue

        all_successors = set()
        incomming_edges = dict() # bb corrosponding to the incomming edges count
        no_call = True

        for bb in func.bb:
            if isInExcludeRange(bb.va):
                continue

            if len(bb.instructions) == 0:
                continue

            last_call = 0x0
            # parse all call instructions
            for inst in bb.instructions:
                instructions.add(inst.va)
                if inst.call_type == 0x3: # direct call type
                    last_call = inst.va

            if last_call != 0 and bb.type == BlockType.NON_RETURN_CALL and len(bb.child) > 0:
                non_ret_edges[last_call] = bb.child[0].va

            if bb.type == BlockType.TAIL_CALL:
                if len(bb.child) == 0:
                    continue

                last_va = bb.instructions[-1].va
                suc_va = 0x0
                if len(bb.child) == 1:
                    suc_va = bb.child[0].va

                elif len(bb.child) == 2:
                    suc_va = bb.child[0].va
                    diff1 = abs(last_va - bb.child[0].va)
                    diff2 = abs(last_va - bb.child[1].va)
                    if diff1 < diff2:
                        suc_va = bb.child[1].va

                if bb.child[0].va == funcAddr or isInPltSection(bb.child[0].va) or suc_va == 0x0:
                    continue

                tail_calls[last_va] = suc_va

    return (non_ret_edges, tail_calls, instructions)

def parseBBType(bb, last_inst):
    if last_inst == None:
        return
    indirect = isIndirect(last_inst)
    # call instruction
    if x86.X86_GRP_CALL in last_inst.groups:
        if indirect:
            bb.type = BlockType.INDIRECT_CALL
            return

        if NO_INTEPROC_CALL:
            if len(bb.child) == 1:
                bb.type = BlockType.DIRECT_CALL
            else:
                bb.type = BlockType.NON_RETURN_CALL
        elif isAngr:
            if bb.type != BlockType.NON_RETURN_CALL:
                bb.type = BlockType.DIRECT_CALL
        else:
            if len(bb.child) == 2:
                bb.type = BlockType.DIRECT_CALL
            else:
                bb.type = BlockType.NON_RETURN_CALL

    # jump instruction
    elif x86.X86_GRP_JUMP in last_inst.groups:
        if indirect:
            bb.type = BlockType.INDIRECT_BRANCH
        elif 'jmp' in last_inst.mnemonic:
            bb.type = BlockType.DIRECT_BRANCH
        else:
            bb.type = BlockType.COND_BRANCH
    elif x86.X86_GRP_RET in last_inst.groups:
        bb.type = BlockType.RET

def collectNonRets(non_rets_func, bb, last_inst):
    if not NO_INTEPROC_CALL:
        if len(bb.child) == 0:
            logging.error("Call Non return function no successor? 0x%x" % bb.va)
        else:
            non_rets_func[last_inst.address] = bb.child[0].va
    else:
        # parse direct call target
        result = getDirectTarget(last_inst)
        if result:
            logging.debug("collect non-return function 0x%x" % result)
            non_rets_func[last_inst.address] = result

def collectTailCalls(tail_calls, bb, all_identified_funcs, cur_func, last_inst):
    if len(bb.instructions) == 0:
        return

    if NO_INTEPROC_CALL:
        if len(bb.child) == 0:
            cur_addr = bb.instructions[-1].va - disassembler_base_addr
            result = getDirectTarget(last_inst)
            if not result or isInPltSection(result):
                return
            if result not in all_identified_funcs:
                return

            if result == cur_func:
                return

            tail_calls[cur_addr] = result
            logging.debug("collect tail-call instruction 0x%x" % (cur_addr))
            return

    suc_addr = 0x0
    if len(bb.child) == 1:
        suc_addr = bb.child[0].va
    
    if len(bb.child) == 2:
        diff1 = abs(bb.child[0].va - last_inst.address - disassembler_base_addr)
        sur_addr = bb.child[0].va
        if diff1 < abs(bb.child[1].va - last_inst.address - disassembler_base_addr):
            sur_addr = bb.child[1].va

    if suc_addr == 0x0:
        return
    if suc_addr - disassembler_base_addr == cur_func:
        return

    if isInPltSection(suc_addr - disassembler_base_addr):
        return

    if suc_addr in all_identified_funcs:
        bb.type = BlockType.TAIL_CALL
        cur_addr = bb.instructions[-1].va - disassembler_base_addr
        tail_calls[cur_addr] = suc_addr
        logging.debug("collect tail-call instruction 0x%x" % (cur_addr))


def readComparedCFG(mModule, binary, exec_secs, thunks_funcs):
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
    non_ret_funcs = dict()
    tail_calls = dict()
    insts = set()

    open_binary = open(binary, 'rb')
    content = open_binary.read()
    content_length = len(content)
    tmpFuncSet = set()

    all_identified_funcs = set()

    for func in mModule.fuc:
        all_identified_funcs.add(func.va)

    all_identified_funcs = all_identified_funcs.difference(thunks_funcs)

    MD = init_capstone(ELFCLASS)

    for func in mModule.fuc:

        all_successors = set()
        all_successors.clear()
        funcAddr = func.va

        funcAddr = func.va - disassembler_base_addr

        if funcAddr not in tmpFuncSet:
            tmpFuncSet.add(funcAddr)
        else:
            logging.warning("repeated handle the function in address %x" % func.va)
            continue

        # first step, mark DIRECT_CALL Type of basic block
        fall_through_edges = dict()
        last_call_inst = None

        for bb in func.bb:
            cur_bb_call = set()
            cur_bb_indirect = set()
            [insts.add(inst.va - disassembler_base_addr) for inst in bb.instructions]

            if len(bb.instructions) == 0:
                continue

            last_inst = None
            bb_va = bb.va - disassembler_base_addr

            inst_va = bb.instructions[-1].va - disassembler_base_addr
            inst_offset = get_file_offset(exec_secs, inst_va, IMAGE_BASE)
            inst_end_offset = (inst_offset + 20) if (inst_offset + 20) < content_length else content_length
            (call_sets, indirect_set, last_inst) = parseCallInsts(MD, content[inst_offset: inst_end_offset], inst_va, 1)

            parseBBType(bb, last_inst)

            if bb.type == BlockType.NON_RETURN_CALL:
                collectNonRets(non_ret_funcs, bb, last_inst)
            elif bb.type == BlockType.DIRECT_BRANCH or bb.type == BlockType.COND_BRANCH: 
                collectTailCalls(tail_calls, bb, all_identified_funcs, funcAddr, last_inst)

    return (non_ret_funcs, tail_calls, insts)

def compareNonRetFuncs(nonret_ground, nonret_compared, neg_insts, mModule):

    funcs_set_truth = dict()
    funcs_set_cmp = set()
    false_pos_candidate = set()

    for (call, target) in nonret_ground.items():
        if target not in funcs_set_truth:
            funcs_set_truth[target] = set()
        funcs_set_truth[target].add(call)

    for (call, target) in nonret_compared.items():
        funcs_set_cmp.add(target)

    false_neg = 0
    false_pos = 0
    exclude_neg_num = 0
    for (target, all_site) in funcs_set_truth.items():
        if target not in funcs_set_cmp:
            # check if the tool does not have all the call edges
            if len(all_site.difference(neg_insts)) == 0:
                exclude_neg_num += 1
            else:
                logging.error("[NonRet False Negative %d]: 0x%x" % (false_neg, target))
                false_neg += 1

    for cur_func in funcs_set_cmp:
        if cur_func not in funcs_set_truth:
            false_pos_candidate.add(cur_func)

    # filter dummy false positive functions
    filted_funcs = set()
    if len(false_pos_candidate) > 0:
        for func in mModule.fuc:
            if func.va not in false_pos_candidate:
                continue
            contains_ret = False
            for bb in func.bb:
                if bb.type == BlockType.RET:
                    contains_ret = True
                    break
            if not contains_ret:
                filted_funcs.add(func.va)

    for func in false_pos_candidate:
        if isInPltSection(func):
            filted_funcs.add(func)

    false_pos_funcs = false_pos_candidate.difference(filted_funcs)

    for func in false_pos_funcs:
        logging.error("[NonRet False Positive %d]: 0x%x" % (false_pos, func))
        false_pos += 1


    compared_non_rets = len(funcs_set_cmp) - len(filted_funcs)
    true_pos = compared_non_rets - false_pos
    ground_truth_cnt = len(funcs_set_truth) - exclude_neg_num
    logging.info("[NonRet Result]: All non-rets in ground truth is %d" % (ground_truth_cnt))
    logging.info("[NonRet Result]: All non-rets in compared is %d" % (compared_non_rets))
    logging.info("[NonRet Result]: False positive number is %d" % false_pos)
    logging.info("[NonRet Result]: False negative number is %d" % false_neg)
    if compared_non_rets > 0:
        logging.info("[NonRet Result]: Precision %f" % (true_pos / compared_non_rets))
    if ground_truth_cnt > 0:
        logging.info("[NonRet Result]: Recall %f" % (true_pos / ground_truth_cnt))

def compareTailCalls(tailcall_ground, tailcall_compared, neg_insts, pos_insts):
    false_neg = 0
    false_pos = 0
    exclude_num = 0
    exclude_pos_num = 0
    false_neg_funcs = set()
    exclude_funcs = set()
    false_pos_funcs = set()
    exclude_pos_funcs = set()
    
    all_funcs_gt = set([target for (_, target) in tailcall_ground.items()])
    all_funcs_com = set([(target - disassembler_base_addr) for (_, target) in tailcall_compared.items()])

    true_pos_set = set()
    true_pos = 0
    for (cur_func, target) in tailcall_ground.items():
        if cur_func not in tailcall_compared:
            if cur_func in neg_insts:
                exclude_funcs.add(target)
            else:
                logging.error("[TailCall False Negative %d]: 0x%x" % (false_neg, cur_func))
                false_neg += 1
                false_neg_funcs.add(target)
        else:
            true_pos_set.add(target)
    
    all_funcs_gt = all_funcs_gt.difference(exclude_funcs.difference(false_neg_funcs))

    for (cur_addr, cur_func) in tailcall_compared.items():
        if cur_addr not in tailcall_ground:
            if cur_addr in pos_insts:
                exclude_pos_funcs.add(cur_func - disassembler_base_addr)
            else:
                logging.error("[TailCall False Positive %d]: 0x%x" % (false_pos, cur_addr))
                false_pos_funcs.add(cur_func - disassembler_base_addr)
                false_pos += 1

    all_funcs_com = all_funcs_com.difference(exclude_pos_funcs.difference(false_pos_funcs))
    false_pos = len(all_funcs_com.difference(all_funcs_gt))
    false_neg = len(all_funcs_gt.difference(all_funcs_com))

    true_pos = len(all_funcs_com) - false_pos
    logging.info("[TailCall Result]: All tailcalls in ground truth is %d" % (len(all_funcs_gt)))
    logging.info("[TailCall Result]: All tailcalls in compared is %d" % (len(all_funcs_com)))
    logging.info("[TailCall Result]: False positive number is %d" % false_pos)
    logging.info("[TailCall Result]: False negative number is %d" % false_neg)
    if len(all_funcs_com) > 0:
        logging.info("[TailCall Result]: Precision %f" % (true_pos / (len(all_funcs_com))))
    if len(all_funcs_gt) > 0:
        logging.info("[TailCall Result]: Recall %f" % (true_pos / (len(all_funcs_gt))))

def confirmTools(file_name):
    global NORMAL_CFG
    global isAngr
    global isBAP
    global NO_INTEPROC_CALL
    file_name = file_name.lower()
    for item in NORMAL_CFG_TOOL:
        if item in file_name:
            NORMAL_CFG = True
            break

    if 'angr' in file_name:
        isAngr = True
        return

    if 'bap' in file_name:
        isBAP = True

    for item in NO_INTEPROC_CALL_TOOL:
        if item in file_name:
            NO_INTEPROC_CALL = True
            break

def is_normal_cfg(file_name):
    file_name = file_name.lower()
    for item in NORMAL_CFG_TOOL:
        if item in file_name:
            return True
    return False

def is_angr(file_name):
    file_name = file_name.lower()
    if 'angr' in file_name:
        return True
    return False

def getBlockFile(com_file):
    if 'angrBlocksNorma' in com_file:
        return com_file.replace('angrBlocksNorma', 'angrBlocks')
    if 'dyninstBB' in com_file:
        return com_file.replace('dyninstBB', 'dyninstNoTailcall') 
    
    if 'ghidra' in com_file:
        tmp_file = com_file.replace('ghidraTailcall', 'ghidra')
        return tmp_file
    return None

def readFuncs(mModule):
    all_funcs = set()
    for func in mModule.fuc:
        all_funcs.add(func.va)
    return all_funcs

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-g", "--groundtruth", dest = "groundtruth", action = "store", \
            type = "string", help = "ground truth file path", default = None)
    parser.add_option("-c", "--comparedfile", dest = "comparedfile", action = "store", \
            type = "string", help = "compared file path", default = None)
    parser.add_option("-b", "--binaryFile", dest = "binaryFile", action = "store", \
            type = "string", help = "binary file path", default = None)
    parser.add_option("-p", "--pdbfile", dest = "pdbfile", action = "store", \
            type = "string", help = "pdb file path", default = None)

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

    if options.pdbfile == None:
        print("Please input the pdb file")
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

    exec_secs = parsePEExecSecs(options.binaryFile)
    secs = parsePESecs(options.binaryFile)
    (IMAGE_BASE, ELFClasss) = parsePEFile(options.binaryFile)

    thunks_funcs = parseThunkSyms(options.pdbfile, secs, IMAGE_BASE)

    # confirm which tool we are handling
    confirmTools(options.comparedfile)


    (non_rets_truth, tail_calls, gt_insts) =\
            readGroundCFG(mModule1, options.binaryFile)

    (non_rets_comp, tail_calls_comp, com_insts) =\
            readComparedCFG(mModule2, options.binaryFile, exec_secs, thunks_funcs)

    neg_insts = gt_insts.difference(com_insts)
    pos_insts = com_insts.difference(gt_insts)

    #compareNonRetFuncs(non_rets_truth, non_rets_comp, neg_insts, mModule1)
    compareTailCalls(tail_calls, tail_calls_comp, neg_insts, pos_insts)
