from deps import *
import optparse
import logging
import blocks_pb2
from elftools.elf.elffile import ELFFile
from BlockUtil import *
from PEUtil import *
import pepy

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

angr_black_plt = {'exit', 'abort', 'exit_group', 'pthread_exit', '__assert_fail', 'longjmp', 'siglongjmp', '__longjmp_chk', '__siglongjmp_chk', '__libc_init', '__libc_start_main', 'ExitProcess', '_exit', '_invoke_watson'}

BLACK_ADDRS = set()
NORMAL_CFG_TOOL = {"ghidra", "ida", "ninja", "radare"}
NO_INTEPROC_CALL_TOOL = {"ninja", "ida", "radare", "bap"} 
NO_INTEPROC_CALL = False
NORMAL_CFG = False
isAngr = False
isBAP = False

def isInPltSection(addr):
    if addr >= pltAddr and addr <= pltAddr + pltSize:
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


def parseCallInsts(MD, content, cur_addr, count_ = None):
    if count_ == None:
        disasm_ins = MD.disasm(content, cur_addr)
    else:
        disasm_ins = MD.disasm(content, cur_addr, count = count_)
    result = set()
    indirect_result = set()
    last_inst = None
    try:
        cur_inst = next(disasm_ins)
    except StopIteration:
        return (result, indirect_result, last_inst)

    last_inst = None
    if cur_inst != None:
        last_inst = cur_inst
        if x86.X86_GRP_CALL in cur_inst.groups:
            if isIndirect(cur_inst):
                logging.debug("indirect call instruction is 0x%x" % cur_inst.address)
                indirect_result.add(cur_inst.address - disassembler_base_addr)
            else:
                logging.debug("call instruction is 0x%x" % cur_inst.address)
                result.add(cur_inst)
   

    return result, indirect_result, last_inst

def readGroundCFG(mModule, binary, exec_secs):
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
    tail_calls = set()
    all_funcs = set()

    open_binary = open(binary, 'rb')
    content = open_binary.read()
    content_len = len(content)
    tmpFuncSet = set()

    for func in mModule.fuc:
        funcAddr = func.va
        all_funcs.add(funcAddr)
        if funcAddr not in tmpFuncSet:
            tmpFuncSet.add(funcAddr)
        else:
            logging.warning("repeated handle the function in address %x" % func.va)
            continue

        all_successors = set()
        incomming_edges = dict() # bb corrosponding to the incomming edges count
        no_call = True

        for bb in func.bb:

            if len(bb.instructions) == 0:
                continue

            if bb.type != BlockType.NON_RETURN_CALL:
                continue

            MD = init_capstone(ELFCLASS)

            last_call = 0x0
            # parse all call instructions
            for inst in bb.instructions:
                instructions.add(inst.va)
                if inst.call_type == 0x1: # direct call type
                    inst_offset = get_file_offset(exec_secs, inst.va, IMAGE_BASE)
                    endOffset = inst_offset + inst.size
                    (call_sets, _, _) = parseCallInsts(MD, content[inst_offset : endOffset], inst.va)
                    if len(call_sets) == 0:
                        continue

                    last_call = inst.va

            non_ret_edges[last_call] = bb.child[0].va

    return (non_ret_edges, tail_calls, instructions, all_funcs)

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
            if len(bb.child) == 0:
                bb.type = BlockType.NON_RETURN_CALL
            else:
                bb.type = BlockType.DIRECT_CALL
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
            result = getDirectTarget(last_inst)
            if result:
                if result == last_inst.address + last_inst.size:
                    return
                logging.debug("collect non-return function 0x%x at 0x%x" % (result, last_inst.address))
                non_rets_func[last_inst.address] = result

        else:
            if bb.child[0].va - disassembler_base_addr == last_inst.address + last_inst.size:
                return
            result = bb.child[0].va - disassembler_base_addr
            logging.debug("collect non-return function 0x%x at 0x%x" % (result, last_inst.address))
            non_rets_func[last_inst.address] = result
    else:
        # parse direct call target
        result = getDirectTarget(last_inst)
       
        if result:
            if result == last_inst.address + last_inst.size:
                return
            logging.debug("collect non-return function 0x%x at 0x%x" % (result, last_inst.address))
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
            tail_calls.add(cur_addr)
            logging.debug("collect tail-call instruction 0x%x" % (cur_addr))
            return

    for suc in bb.child:
        if suc.va - disassembler_base_addr == cur_func:
            continue
        if isInPltSection(suc.va - disassembler_base_addr):
            continue
        if suc.va in all_identified_funcs:
            bb.type = BlockType.TAIL_CALL
            cur_addr = bb.instructions[-1].va - disassembler_base_addr
            tail_calls.add(bb.instructions[-1].va - disassembler_base_addr)
            logging.debug("collect tail-call instruction 0x%x" % (cur_addr))


def readComparedCFG(mModule, binary, exec_secs):
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
    ret_funcs = set()
    tail_calls = set()
    insts = set()

    open_binary = open(binary, 'rb')
    content = open_binary.read()
    content_len = len(content)
    tmpFuncSet = set()

    all_identified_funcs = set()

    for func in mModule.fuc:
        all_identified_funcs.add(func.va)

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

            if bb.type != BlockType.NON_RETURN_CALL:
                continue

            last_inst = None
            bb_va = bb.va - disassembler_base_addr

            inst_va = bb.instructions[-1].va - disassembler_base_addr
            inst_offset = get_file_offset(exec_secs, inst_va, IMAGE_BASE)
            inst_end_offset = (inst_offset + 20) if (inst_offset + 20) < content_len else content_len
            (call_sets, indirect_set, last_inst) = parseCallInsts(MD, content[inst_offset: inst_end_offset], inst_va, 1)

            non_ret_site = 0x0
            collectNonRets(non_ret_funcs, bb, last_inst)
            non_ret_site = last_inst

            for inst in call_sets:
                if inst.address == non_ret_site:
                    continue
                result = getDirectTarget(inst)
                if not result:
                    ret_funcs.add(result)
                

    return (non_ret_funcs, tail_calls, insts, ret_funcs)

def compareNonRetFuncs(nonret_ground, nonret_compared, neg_insts, pos_insts, mModule, ret_funcs, all_identified_funcs):

    funcs_set_truth = dict()
    funcs_set_cmp = dict()
    false_pos_candidate = set()

    for (call, target) in nonret_ground.items():
        if target not in funcs_set_truth:
            funcs_set_truth[target] = set()
        funcs_set_truth[target].add(call)

    for (call, target) in nonret_compared.items():
        if target not in funcs_set_cmp:
            funcs_set_cmp[target] = set()
        funcs_set_cmp[target].add(call)

    #funcs_set_cmp = funcs_set_cmp.union(BLACK_ADDRS)

    false_neg = 0
    false_pos = 0
    exclude_neg_num = 0
    for (target, all_site) in funcs_set_truth.items():
        if target not in funcs_set_cmp:
            # check if the tool does not have all the call edges
            if len(all_site.difference(neg_insts)) == 0 or target in BLACK_ADDRS:
                exclude_neg_num += 1
            else:
                logging.error("[NonRet False Negative %d]: 0x%x" % (false_neg, target))
                false_neg += 1

    exclude_pos_num = 0
    for (cur_func, all_site) in funcs_set_cmp.items():
        if cur_func not in funcs_set_truth:
            # all call site are in false positive instructions
            if len(all_site.difference(pos_insts)) == 0:
                exclude_pos_num += 1
            else:
                false_pos_candidate.add(cur_func)

    # filter dummy false positive functions
    filted_funcs = ret_funcs.intersection(false_pos_candidate)

    for func in false_pos_candidate:
        if func not in all_identified_funcs:
            filted_funcs.add(func)

    false_pos_funcs = false_pos_candidate.difference(filted_funcs)

    for func in false_pos_funcs:
        logging.error("[NonRet False Positive %d]: 0x%x" % (false_pos, func))
        false_pos += 1


    compared_non_rets = len(funcs_set_cmp) - len(filted_funcs) - exclude_pos_num
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
    for cur_func in tailcall_ground:
        if cur_func not in tailcall_compared:
            if cur_func in neg_insts:
                exclude_num += 1
            else:
                logging.error("[TailCall False Negative %d]: 0x%x" % (false_neg, cur_func))
                false_neg += 1

    for cur_func in tailcall_compared:
        if cur_func not in tailcall_ground:
            if cur_func in pos_insts:
                exclude_pos_num += 1
            else:
                logging.error("[TailCall False Positive %d]: 0x%x" % (false_pos, cur_func))
                false_pos += 1

    true_pos = len(tailcall_compared) - false_pos - exclude_pos_num
    logging.info("[TailCall Result]: All tailcalls in ground truth is %d" % (len(tailcall_ground) - exclude_num))
    logging.info("[TailCall Result]: All tailcalls in compared is %d" % (len(tailcall_compared) - exclude_pos_num))
    logging.info("[TailCall Result]: False positive number is %d" % false_pos)
    logging.info("[TailCall Result]: False negative number is %d" % false_neg)
    if len(tailcall_compared) > 0:
        logging.info("[TailCall Result]: Precision %f" % (true_pos / (len(tailcall_compared) - exclude_pos_num)))
    if len(tailcall_ground) > 0:
        logging.info("[TailCall Result]: Recall %f" % (true_pos / (len(tailcall_ground) - exclude_num)))

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


"""
get pie base offset according to the compared file name.
"""
def getPIEBaseOffset(comparedFile):
    for (tool, base_offset) in BASE_ADDR_MAP.items():
        if tool in comparedFile:
            return base_offset
    # default offset is 0
    return 0

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

def getAngrBlackAddrs(binary, iat_base):
    global BLACK_ADDRS

    p = pepy.parse(binary)

    for iobj in p.get_imports():
        if iobj.sym in angr_black_plt:
            BLACK_ADDRS.add(iobj.addr + iat_base)

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
    (IMAGE_BASE, ELFClass) = parsePEFile(options.binaryFile)

    # confirm which tool we are handling
    confirmTools(options.comparedfile)

    iat_base = 0x100000000
    if ELFClass == 32:
        iat_base = 0x0

    if isAngr:
        getAngrBlackAddrs(options.binaryFile, iat_base)


    (non_rets_truth, tail_calls, gt_insts, all_funcs) =\
            readGroundCFG(mModule1, options.binaryFile, exec_secs)

    (non_rets_comp, tail_calls_comp, com_insts, ret_funcs) =\
            readComparedCFG(mModule2, options.binaryFile, exec_secs)

    neg_insts = gt_insts.difference(com_insts)
    pos_insts = com_insts.difference(gt_insts)

    compareNonRetFuncs(non_rets_truth, non_rets_comp, neg_insts, pos_insts, mModule1, ret_funcs, all_funcs)
    #compareTailCalls(tail_calls, tail_calls_comp, neg_insts, pos_insts)
