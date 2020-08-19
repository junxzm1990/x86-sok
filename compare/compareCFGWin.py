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

# plt range
pltAddr = 0
pltSize = 0
IMAGE_BASE = 0

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

NORMAL_CFG_TOOL = {"ghidra", "ida", "ninja", "radare"}
NO_INTEPROC_CALL_TOOL = {"ninja", "bap", "ida", "radare"} 
NO_INTEPROC_CALL = False
NORMAL_CFG = False
isAngr = False
isBAP = False

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
                indirect_result.add(cur_inst.address)
            else:
                logging.debug("call instruction is 0x%x" % cur_inst.address)
                result.add(cur_inst.address)
    return result, indirect_result, last_inst

def isInExecSecs(secs, va):
    for sec in secs:
        if va >= sec.addr + IMAGE_BASE and va < IMAGE_BASE + sec.addr + sec.size:
            return True

    return False

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
    call_insts = set()
    indirect_jumps = set()
    indirect_calls = set()
    edges = dict()
    non_ret_funcs = set()
    tail_calls = set()
    open_binary = open(binary, 'rb')
    content = open_binary.read()
    content_len = len(content)
    tmpFuncSet = set()
    MD = init_capstone(ELFCLASS)
    global groundTruthFuncRange
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

            for inst in bb.instructions:
                if inst.call_type == 1:
                    inst_offset = get_file_offset(exec_secs, inst.va, IMAGE_BASE)
                    endOffset = (inst_offset + 20) if (inst_offset + 20) < content_len else content_len
                    disassemble_content = content[inst_offset : endOffset]
                    if checkTerminatorIsIndirectCall(MD, disassemble_content, inst.va):
                        indirect_calls.add(inst.va)
                    else:
                        call_insts.add(inst.va)

            if bb.type == BlockType.DIRECT_CALL or bb.type == BlockType.INDIRECT_CALL or bb.type == BlockType.FALL_THROUGH:
                no_call = False
            else:
                for suc in bb.child:
                    all_successors.add(suc.va)
                    incomming_edges[suc.va] = 1 if suc.va not in incomming_edges else incomming_edges[suc.va] + 1
                #[all_successors.add(suc.va) for suc in bb.child]

            # check if current terminator is jump table indirect jumps
            if len(bb.child) > 2:
                assert len(bb.instructions) > 0, \
                        "[readJmpTables]: The basic block 0x%x does not contain any instruction!" % (bb.va)
                terminator_addr = bb.instructions[-1].va
                # change it
                if not isInExecSecs(exec_secs, terminator_addr):
                    continue

                offset = get_file_offset(exec_secs, terminator_addr, IMAGE_BASE)
                endOffset = (offset + 20) if (offset + 20) < content_len else content_len 
                disassemble_content = content[offset: endOffset]
                if checkTerminatorIsIndirectJump(MD, disassemble_content, terminator_addr):
                    indirect_jumps.add(terminator_addr);

        merge_call_edges(func, all_successors)

        for bb in func.bb:
            if bb.type == BlockType.INVALID_BB:
                continue

            cur_hash = hash64(bb.va)

            # we only collect only FALL_THROUGH edge
            if bb.type == BlockType.DIRECT_CALL:
                fall_through = bb.va + bb.size
                if bb.padding != 0 and incomming_edges.get(fall_through, 0) > 0:
                    suc_hash = hash64(fall_through) >> 1
                    hash_result = cur_hash ^ suc_hash
                    edges[hash_result] = (bb.va, fall_through)
                    next_fall_through = bb.va + bb.size + bb.padding
                    cur_hash_tmp = hash64(fall_through)
                    next_hash = hash64(next_fall_through) >> 1
                    hash_result = cur_hash_tmp ^ next_hash
                    edges[hash_result] = (fall_through, next_fall_through)
                else:
                    fall_through = bb.va + bb.size + bb.padding
                    suc_hash = hash64(fall_through) >> 1
                    hash_result = cur_hash ^ suc_hash
                    edges[hash_result] = (bb.va, fall_through)
                continue

            if bb.type == BlockType.COND_BRANCH and bb.padding != 0:
                succs = set()
                [succs.add(suc.va) for suc in bb.child]
                fall_through = bb.va + bb.size + bb.padding

                if fall_through in succs and len(bb.child) == 2:
                    succs.remove(fall_through)
                    fall_through = bb.va + bb.size
                    suc_hash = hash64(fall_through) >> 1
                    hash_result = cur_hash ^ suc_hash
                    edges[hash_result] = (bb.va, fall_through)
                    
                    # add nop fall through edges
                    next_fall_through = bb.va + bb.size + bb.padding
                    if incomming_edges.get(next_fall_through, 0) > 1:
                        cur_hash_tmp = hash64(fall_through)
                        next_hash = hash64(next_fall_through) >> 1
                        hash_result = cur_hash_tmp ^ next_hash
                        edges[hash_result] = (fall_through, next_fall_through)
                        logging.debug("add nop fall through bb 0x%x -> 0x%x" % (fall_through, next_fall_through))

                    if len(succs) == 0:
                        continue

                    suc_hash = hash64(list(succs)[0]) >> 1
                    hash_result = cur_hash ^ suc_hash
                    edges[hash_result] = (bb.va, list(succs)[0])
                    continue

                fall_through = bb.va + bb.size
                next_fall_through = bb.va + bb.size + bb.padding
                if fall_through in succs and incomming_edges.get(next_fall_through, 0) > 0:

                    logging.debug("add nop fall through bb 0x%x -> 0x%x" % (fall_through, next_fall_through))
                    cur_hash_tmp = hash64(fall_through)
                    next_hash = hash64(next_fall_through) >> 1
                    hash_result = cur_hash_tmp ^ next_hash
                    edges[hash_result] = (fall_through, next_fall_through)

            # collect tail-calls
            if bb.type in {BlockType.TAIL_CALL, BlockType.JUMP_TOFUNC}:
                if len(bb.instructions) > 0:
                    tail_calls.add(bb.instructions[-1].va)
            # collect all non-ret call instruction
            elif bb.type == BlockType.NON_RETURN_CALL:
                [non_ret_funcs.add(suc.va) for suc in bb.child]
            else:
                for suc in bb.child:
                    # edge = prev_bb ^ (suc_bb >> 1)
                    suc_hash = hash64(suc.va) >> 1
                    hash_result = cur_hash ^ suc_hash
                    edges[hash_result] = (bb.va, suc.va)

    return (call_insts, indirect_calls, indirect_jumps, edges, non_ret_funcs, tail_calls)

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
            non_rets_func.add(bb.child[0].va)
    else:
        # parse direct call target
        result = getDirectTarget(last_inst)
        if result:
            logging.debug("collect non-return function 0x%x" % result)
            non_rets_func.add(result)

def collectTailCalls(tail_calls, bb, all_identified_funcs):
    if len(bb.instructions) == 0:
        return

    if NO_INTEPROC_CALL:
        if len(bb.child) == 0:
            cur_addr = bb.instructions[-1].va - disassembler_base_addr
            tail_calls.add(cur_addr)
            logging.debug("collect tail-call instruction 0x%x" % (cur_addr))
            return

    for suc in bb.child:
        if suc.va in all_identified_funcs:
            bb.type = BlockType.TAIL_CALL
            cur_addr = bb.instructions[-1].va - disassembler_base_addr
            tail_calls.add(bb.instructions[-1].va - disassembler_base_addr)
            logging.debug("collect tail-call instruction 0x%x" % (cur_addr))


def readComparedCFG(mModule, binary, jtable_jumps, exec_secs):
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
    edges = dict()
    call_insts = set()
    indirect_calls = set()
    indirect_call_targets = dict()
    non_ret_calls = set()
    non_ret_funcs = set()
    tail_calls = set()

    open_binary = open(binary, 'rb')
    content = open_binary.read()
    content_len = len(content)
    tmpFuncSet = set()

    all_identified_funcs = set()

    for func in mModule.fuc:
        all_identified_funcs.add(func.va)

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

        if not isInExecSecs(exec_secs, funcAddr):
            continue

        # first step, mark DIRECT_CALL Type of basic block
        fall_through_edges = dict()
        last_call_inst = None

        for bb in func.bb:
            MD = init_capstone(ELFCLASS)
            cur_bb_call = set()
            cur_bb_indirect = set()

            if len(bb.instructions) == 0:
                continue
            last_inst = None
            bb_va = bb.va - disassembler_base_addr

            if NORMAL_CFG:
                # parse all call instructions
                if bb.size > 0:
                    bb_offset = get_file_offset(exec_secs, bb.va, IMAGE_BASE)
                    bb_end_offset = bb_offset + bb.size 
                    (call_sets, indirect_set, last_inst) = parseCallInsts(MD, content[bb_offset: bb_end_offset], bb.va)
                    cur_bb_call = cur_bb_call.union(call_sets)
                    cur_bb_indirect = cur_bb_indirect.union(indirect_set)

                    if bb.instructions[-1].size == 0 and last_inst:
                        bb.instructions[-1].size = last_inst.size

                    parseBBType(bb, last_inst)

                else:
                    save_inst = None
                    for inst in bb.instructions:
                        inst_va = inst.va - disassembler_base_addr
                        inst_offset = get_file_offset(exec_secs, inst_va, IMAGE_BASE)
                        inst_end_offset = (inst_offset + 20) if (inst_offset + 20) < content_len else content_len
                        (call_sets, indirect_set, last_inst) = parseCallInsts(MD, content[inst_offset: inst_end_offset], inst.va, 1)

                        cur_bb_call = cur_bb_call.union(call_sets)
                        cur_bb_indirect = cur_bb_indirect.union(indirect_set)
                        save_inst = last_inst
                        if inst.size == 0 and last_inst:
                            inst.size = last_inst.size
                    parseBBType(bb, last_inst)

            else:
                # merge all call instructions into cfg
                last_inst_t = bb.instructions[-1]

                inst_va = last_inst_t.va - disassembler_base_addr
                inst_offset = get_file_offset(exec_secs, inst_va, IMAGE_BASE)
                inst_end_offset = (inst_offset + 20) if (inst_offset + 20) < content_len else content_len
                (call_sets, indirect_set, last_inst) = parseCallInsts(MD, content[inst_offset: inst_end_offset], last_inst_t.va, 1)
                cur_bb_call = cur_bb_call.union(call_sets)
                cur_bb_indirect = cur_bb_indirect.union(indirect_set)
                parseBBType(bb, last_inst)

                # update last instruction's size
                # we can't collect instrction's size of some tool
                # so we update here
                if last_inst != None and bb.instructions[-1].size == 0:
                    bb.instructions[-1].size = last_inst.size

                # collect all out edges block
                if bb.type not in {BlockType.DIRECT_CALL, BlockType.NON_RETURN_CALL, BlockType.RET, BlockType.INDIRECT_CALL}:
                    [all_successors.add(suc.va) for suc in bb.child]

            call_insts = call_insts.union(cur_bb_call)
            indirect_calls = indirect_calls.union(cur_bb_indirect)

            if bb.type == BlockType.NON_RETURN_CALL:
                collectNonRets(non_ret_funcs, bb, last_inst)
            elif bb.type == BlockType.DIRECT_BRANCH: 
                collectTailCalls(tail_calls, bb, all_identified_funcs)
            elif bb.type == BlockType.INDIRECT_CALL and len(bb.child) > 0 and last_inst != None:
                tmp_successors = list()
                fall_through_addr = last_inst.address + last_inst.size
                for suc in bb.child:
                    if suc.va != fall_through_addr:
                        tmp_successors.append(suc.va - disassembler_base_addr)
                if len(tmp_successors) > 0:
                    indirect_call_targets[last_inst.address - disassembler_base_addr] = tmp_successors 


        if not NORMAL_CFG:
            merge_call_edges(func, all_successors)

        for bb in func.bb:

            if bb.type in {BlockType.INVALID_BB, BlockType.NON_RETURN_CALL, BlockType.RET}:
                continue

            if not isInExecSecs(exec_secs, bb.va):
                logging.info("bb va is 0x%x, skip!" % bb.va)
                continue

            if len(bb.instructions) > 0:
                terminator_addr = bb.instructions[-1].va - disassembler_base_addr
                
                if terminator_addr not in jtable_jumps and len(bb.child) > 2:
                    # as these jump tables not in our ground truth,
                    # so we skip these edges
                    logging.debug("skip indirect jump at address 0x%x" % terminator_addr)
                    continue

            cur_hash = hash64(bb.va - disassembler_base_addr)
            # collect only FALL_THROUGH edge
            if bb.type == BlockType.DIRECT_CALL:
                last_inst = bb.instructions[-1]
                fall_through = last_inst.va + last_inst.size
                suc_hash = hash64(fall_through - disassembler_base_addr) >> 1
                hash_result = cur_hash ^ suc_hash
                edges[hash_result] = (bb.va - disassembler_base_addr, fall_through - disassembler_base_addr)
                continue

            if bb.type == BlockType.NON_RETURN_CALL:
                continue

            for suc in bb.child:
                if suc.va == 0xffffffffffffffff:
                    continue

                # edge = prev_bb ^ (suc_bb >> 1)
                suc_hash = hash64(suc.va - disassembler_base_addr) >> 1
                hash_result = cur_hash ^ suc_hash
                edges[hash_result] = (bb.va - disassembler_base_addr, suc.va - disassembler_base_addr)

    return (call_insts, indirect_calls, edges, non_ret_funcs, tail_calls, indirect_call_targets)

def compareDirectCall(call_truth, call_comp):
    false_neg = 0
    false_pos = 0
    for call in call_truth:
        if call not in call_comp:
            logging.error("[CG False Negative %d]: at 0x%x" % (false_neg, call))
            false_neg += 1

    for call in call_comp:
        if call not in call_truth:
            logging.error("[CG False Positive %d]: at 0x%x" % (false_pos, call))
            false_pos += 1

    true_pos = len(call_comp) - false_pos
    logging.info("[CG Result]: All direct edges in ground truth is %d" % len(call_truth))
    logging.info("[CG Result]: All direct edges in compared is %d" % len(call_comp))
    logging.info("[CG Result]: False positive number is %d" % false_pos)
    logging.info("[CG Result]: False Negative number is %d" % false_neg)
    logging.info("[CG Result]: Precison %f" % (true_pos / len(call_comp)))
    logging.info("[CG Result]: Recall %f" % (true_pos / len(call_truth)))

def outputIndirectCallInfo(indirect_calls, indirect_calls_comp, indirect_call_targets_comp):
    false_neg = 0
    false_pos = 0
    for indirect_call in indirect_calls:
        if indirect_call not in indirect_calls_comp:
            logging.error("[Indirect Call False Negative %d]: at 0x%x" % (false_neg, indirect_call))
            false_neg += 1

    for indirect_call in indirect_calls_comp:
        if indirect_call not in indirect_calls:
            logging.error("[Indirect Call False Positive %d]: at 0x%x" % (false_pos, indirect_call))
            false_pos += 1

    true_pos = len(indirect_calls_comp) - false_pos
    logging.info("[Indirect Call Result]: All indirect calls in ground truth is %d" % len(indirect_calls))
    logging.info("[Indirect Call Result]: All indirect calls in compared is %d" % len(indirect_calls_comp))
    logging.info("[Indirect Call Result]: False positive number is %d" % false_pos)
    logging.info("[Indirect Call Result]: False negative number is %d" % false_neg)
    if len(indirect_calls) > 0:
        logging.info("[Indirect Call Result]: Precision %f" % (true_pos / len(indirect_calls)))
    if len(indirect_calls_comp) > 0:
        logging.info("[Indirect Call Result]: Recall %f" % (true_pos / len(indirect_calls_comp)))

    solve_num = 0
    for (indirect, targets) in indirect_call_targets_comp.items():
        result = ", ".join(f"0x{x:x}" for x in targets)
        logging.info("[Tool Indirect call solve %d]: 0x%x: %s" % (solve_num, indirect, result))
        solve_num += 1

def compareCFG(cfg_ground, cfg_compared):
    false_neg = 0
    false_pos = 0

    for (hash_val, edge) in cfg_ground.items():
        if hash_val not in cfg_compared:
            logging.error("[CFG False Negative %d]: 0x%x -> 0x%x" % (false_neg, edge[0], edge[1]))
            false_neg += 1

    for (hash_val, edge) in cfg_compared.items():
        if hash_val not in cfg_ground:
            logging.error("[CFG False Positive %d]: 0x%x -> 0x%x" % (false_pos, edge[0], edge[1]))
            false_pos += 1

    true_pos = len(cfg_compared) - false_pos
    logging.info("[CFG Result]: All cfg edges in ground truth is %d" % len(cfg_ground))
    logging.info("[CFG Result]: All cfg edges in compared is %d" % len(cfg_compared))
    logging.info("[CFG Result]: False positive number is %d" % false_pos)
    logging.info("[CFG Result]: False negative number is %d" % false_neg)
    logging.info("[CFG Result]: Precision %f" % (true_pos / len(cfg_compared)))
    logging.info("[CFG Result]: Recall %f" % (true_pos / len(cfg_ground)))

def compareNonRetFuncs(nonret_ground, nonret_compared):
    false_neg = 0
    false_pos = 0
    for cur_func in nonret_ground:
        if cur_func not in nonret_compared:
            logging.error("[NonRet False Negative %d]: 0x%x" % (false_neg, cur_func))
            false_neg += 1

    for cur_func in nonret_compared:
        if cur_func not in nonret_ground:
            logging.error("[NonRet False Positive %d]: 0x%x" % (false_pos, cur_func))
            false_pos += 1

    true_pos = len(nonret_compared) - false_pos
    logging.info("[NonRet Result]: All non-rets in ground truth is %d" % len(nonret_ground))
    logging.info("[NonRet Result]: All non-rets in compared is %d" % len(nonret_compared))
    logging.info("[NonRet Result]: False positive number is %d" % false_pos)
    logging.info("[NonRet Result]: False negative number is %d" % false_neg)
    if len(nonret_compared) > 0:
        logging.info("[NonRet Result]: Precision %f" % (true_pos / len(nonret_compared)))
    if len(nonret_ground) > 0:
        logging.info("[NonRet Result]: Recall %f" % (true_pos / len(nonret_ground)))

def compareTailCalls(tailcall_ground, tailcall_compared):
    false_neg = 0
    false_pos = 0
    for cur_func in tailcall_ground:
        if cur_func not in tailcall_compared:
            logging.error("[TailCall False Negative %d]: 0x%x" % (false_neg, cur_func))
            false_neg += 1

    for cur_func in tailcall_compared:
        if cur_func not in tailcall_ground:
            logging.error("[TailCall False Positive %d]: 0x%x" % (false_pos, cur_func))
            false_pos += 1

    true_pos = len(tailcall_compared) - false_pos
    logging.info("[TailCall Result]: All tailcalls in ground truth is %d" % len(tailcall_ground))
    logging.info("[TailCall Result]: All tailcalls in compared is %d" % len(tailcall_compared))
    logging.info("[TailCall Result]: False positive number is %d" % false_pos)
    logging.info("[TailCall Result]: False negative number is %d" % false_neg)
    if len(tailcall_compared) > 0:
        logging.info("[TailCall Result]: Precision %f" % (true_pos / len(tailcall_compared)))
    if len(tailcall_ground) > 0:
        logging.info("[TailCall Result]: Recall %f" % (true_pos / len(tailcall_ground)))

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


    exec_secs = parsePEExecSecs(options.binaryFile)
    (IMAGE_BASE, ELFClasss) = parsePEFile(options.binaryFile)

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

    # confirm which tool we are handling
    confirmTools(options.comparedfile)

    (call_truth, indirect_calls, indirect_jumps, edges_truth, non_ret_funcs, tail_calls) =\
            readGroundCFG(mModule1, options.binaryFile, exec_secs)

    (call_comp, indirect_calls_comp, edges_comp, non_rets_comp, tail_calls_comp, indirect_call_targets_comp) =\
            readComparedCFG(mModule2, options.binaryFile, indirect_jumps, exec_secs)
    compareCFG(edges_truth, edges_comp)
    #compareNonRetFuncs(non_ret_funcs, non_rets_comp)
    #compareTailCalls(tail_calls, tail_calls_comp)
    #compareDirectCall(call_truth, call_comp)
    #outputIndirectCallInfo(indirect_calls, indirect_calls_comp, indirect_call_targets_comp)
