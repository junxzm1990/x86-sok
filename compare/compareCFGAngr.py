from deps import *
import optparse
import logging
import blocks_pb2
from elftools.elf.elffile import ELFFile
import bbinfoconfig as bbl
from BlockUtil import *

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

linker_libc_func = {
           "__x86.get_pc_thunk.bx", # glibc in i386 function
           "__libc_csu_init",
           "__libc_csu_fini",
           "deregister_tm_clones",
           "register_tm_clones",
           "__do_global_dtors_aux",
           "frame_dummy",
           "_start",
           "atexit",
           "_dl_relocate_static_pie",
           "__stat",
           "stat64",
           "fstat64",
           "lstat64",
           "fstatat64",
           "__fstat"
    }

def readGroundTruthFuncsRange(mModule):
    global groundTruthFuncRange
    for func in mModule.fuc:
        funcAddr = func.va
        for bb in func.bb:
            groundTruthFuncRange[bb.va] = bb.size

def getLinkerFunctionAddr(binary):
    global notIncludedLinkerFunc
    with open(binary, 'rb') as openFile:
        elffile = ELFFile(openFile)
        symsec = elffile.get_section_by_name('.symtab')
        get_pc_thunk_bx = 0x0
        global linkerFuncAddr
        if symsec == None:
            return
        for sym in symsec.iter_symbols():
            name = sym.name
            if 'STT_FUNC' != sym.entry['st_info']['type']:
                continue
            if name in linker_libc_func:
                logging.debug("linker: %s: %x" % (name, sym['st_value']))
                notIncludedLinkerFunc.add(sym['st_value'])

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
    call_insts = set()
    indirect_jumps = set()
    indirect_calls = set()
    edges = dict()
    non_ret_funcs = set()
    tail_calls = set()
    open_binary = open(binary, 'rb')
    content = open_binary.read()
    textEndOffset = textSize + textOffset
    tmpFuncSet = set()
    MD = init_capstone(ELFCLASS)
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

            last_call = 0x0
            # parse all call instructions
            for inst in bb.instructions:
                instructions.add(inst.va)
                if inst.call_type == 0x3: # direct call type
                    call_insts.add(inst.va)
                    last_call = inst.va
                elif inst.call_type == 0x2: # indirect call type
                    indirect_calls.add(inst.va)

            if last_call != 0 and bb.type == BlockType.NON_RETURN_CALL and len(bb.child) > 0:
                non_ret_edges[last_call] = bb.child[0].va
            
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
                if not isInTextSection(terminator_addr):
                    continue

                offset = terminator_addr - textAddr + textOffset
                endOffset = (offset + 20) if (offset + 20) < textEndOffset else textEndOffset
                disassemble_content = content[offset: endOffset]
                if checkTerminatorIsIndirectJump(MD, disassemble_content, terminator_addr):
                    indirect_jumps.add(terminator_addr);


        merge_call_edges(func, all_successors)

        for bb in func.bb:
            if isInExcludeRange(bb.va):
                continue
            if bb.type == BlockType.INVALID_BB:
                continue

            cur_hash = hash64(bb.va)

            # we only collect only FALL_THROUGH edge
            if bb.type == BlockType.DIRECT_CALL:
                fall_through = bb.va + bb.size
                suc_hash = hash64(fall_through) >> 1
                hash_result = cur_hash ^ suc_hash
                edges[hash_result] = (bb.va, fall_through)

                next_fall_through = bb.va + bb.size + bb.padding
                if bb.padding != 0:
                    cur_hash_tmp = hash64(fall_through)
                    next_hash = hash64(next_fall_through) >> 1
                    hash_result = cur_hash_tmp ^ next_hash
                    edges[hash_result] = (fall_through, next_fall_through)
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
            else:
                for suc in bb.child:
                    suc_hash = hash64(suc.va) >> 1
                    hash_result = cur_hash ^ suc_hash
                    edges[hash_result] = (bb.va, suc.va)

    return (call_insts, indirect_calls, indirect_jumps, edges, instructions)


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
        if suc.va in all_identified_funcs or isInPltSection(suc.va - disassembler_base_addr):
            bb.type = BlockType.TAIL_CALL
            cur_addr = bb.instructions[-1].va - disassembler_base_addr
            tail_calls.add(bb.instructions[-1].va - disassembler_base_addr)
            logging.debug("collect tail-call instruction 0x%x" % (cur_addr))


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
    edges = dict()
    call_insts = set()
    indirect_calls = set()
    indirect_call_targets = dict()
    non_ret_calls = set()
    non_ret_funcs = dict()
    tail_calls = set()
    insts = set()

    open_binary = open(binary, 'rb')
    content = open_binary.read()
    textEndOffset = textSize + textOffset
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

        if not isInTextSection(funcAddr) or isInPltSection(funcAddr):
            continue


        # first step, mark DIRECT_CALL Type of basic block
        fall_through_edges = dict()
        last_call_inst = None

        for bb in func.bb:
            if isInExcludeRange(bb.va - disassembler_base_addr):
                continue
            cur_bb_call = set()
            cur_bb_indirect = set()
            [insts.add(inst.va - disassembler_base_addr) for inst in bb.instructions]

            if len(bb.instructions) == 0:
                continue
            last_inst = None
            bb_va = bb.va - disassembler_base_addr

            if NORMAL_CFG:
                # parse all call instructions
                if bb.size > 0:
                    bb_offset = bb_va - textAddr + textOffset
                    bb_end_offset = bb_offset + bb.size 
                    (call_sets, indirect_set, last_inst) = parseCallInsts(MD, content[bb_offset: bb_end_offset], bb_va)
                    cur_bb_call = cur_bb_call.union(call_sets)
                    cur_bb_indirect = cur_bb_indirect.union(indirect_set)

                    if bb.instructions[-1].size == 0 and last_inst:
                        bb.instructions[-1].size = last_inst.size

                    parseBBType(bb, last_inst)

                else:
                    save_inst = None
                    for inst in bb.instructions:
                        inst_va = inst.va - disassembler_base_addr
                        inst_offset = inst_va - textAddr + textOffset
                        inst_end_offset = (inst_offset + 20) if (inst_offset + 20) < textEndOffset else textEndOffset
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
                inst_offset = inst_va - textAddr + textOffset
                inst_end_offset = (inst_offset + 20) if (inst_offset + 20) < textEndOffset else textEndOffset
                (call_sets, indirect_set, last_inst) = parseCallInsts(MD, content[inst_offset: inst_end_offset], inst_va, 1)
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

            if isInExcludeRange(bb.va - disassembler_base_addr):
                continue

            if isInPltSection(bb.va - disassembler_base_addr):
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
                if isInPltSection(suc.va - disassembler_base_addr):
                    continue

                if not isInTextSection(suc.va - disassembler_base_addr):
                    continue

                if bb.va == suc.va:
                    continue
                # edge = prev_bb ^ (suc_bb >> 1)
                suc_hash = hash64(suc.va - disassembler_base_addr) >> 1
                hash_result = cur_hash ^ suc_hash
                edges[hash_result] = (bb.va - disassembler_base_addr, suc.va - disassembler_base_addr)

    return (call_insts, indirect_calls, edges, indirect_call_targets, insts)

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

def compareTailCalls(tailcall_ground, tailcall_compared, neg_insts):
    false_neg = 0
    false_pos = 0
    exclude_num = 0
    for cur_func in tailcall_ground:
        if cur_func not in tailcall_compared:
            if cur_func in neg_insts:
                exclude_num += 1
            else:
                logging.error("[TailCall False Negative %d]: 0x%x" % (false_neg, cur_func))
                false_neg += 1

    for cur_func in tailcall_compared:
        if cur_func not in tailcall_ground:
            logging.error("[TailCall False Positive %d]: 0x%x" % (false_pos, cur_func))
            false_pos += 1

    true_pos = len(tailcall_compared) - false_pos
    logging.info("[TailCall Result]: All tailcalls in ground truth is %d" % (len(tailcall_ground) - exclude_num))
    logging.info("[TailCall Result]: All tailcalls in compared is %d" % len(tailcall_compared))
    logging.info("[TailCall Result]: False positive number is %d" % false_pos)
    logging.info("[TailCall Result]: False negative number is %d" % false_neg)
    if len(tailcall_compared) > 0:
        logging.info("[TailCall Result]: Precision %f" % (true_pos / len(tailcall_compared)))
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

    black_list = {'libv8', 'mysqld', 'nginx', 'libc', 'openssl'}
    for black in black_list:
        if black in options.binaryFile:
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

    # confirm which tool we are handling
    confirmTools(options.comparedfile)

    readGroundTruthFuncsRange(mModule1)

    getLinkerFunctionAddr(options.binaryFile)
    not_included = checkGroundTruthFuncNotIncluded(groundTruthFuncRange, options.binaryFile)
    if not_included != None:
        logging.info("Append the not included functions! {0}".format(not_included))
        notIncludedLinkerFunc |= not_included 

    getLinkerFunctionRange(options.binaryFile)

    (call_truth, indirect_calls, indirect_jumps, edges_truth, gt_insts) =\
            readGroundCFG(mModule1, options.binaryFile)

    (call_comp, indirect_calls_comp, edges_comp, indirect_call_targets_comp, com_insts) =\
            readComparedCFG(mModule2, options.binaryFile, indirect_jumps)

    neg_insts = gt_insts.difference(com_insts)
    compareCFG(edges_truth, edges_comp)
    #compareDirectCall(call_truth, call_comp)
    #outputIndirectCallInfo(indirect_calls, indirect_calls_comp, indirect_call_targets_comp)
