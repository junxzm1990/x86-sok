from deps import *
import optparse
import logging
import blocks_pb2
from elftools.elf.elffile import ELFFile
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
    return

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

def readFuncs(mModule):
    all_funcs = set()
    for func in mModule.fuc:
        all_funcs.add(func.va)
    return all_funcs

def readComparedCFG(mModule, binary):
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

            inst_va = bb.instructions[-1].va - disassembler_base_addr
            inst_offset = inst_va - textAddr + textOffset
            inst_end_offset = (inst_offset + 20) if (inst_offset + 20) < textEndOffset else textEndOffset
            (call_sets, indirect_set, last_inst) = parseCallInsts(MD, content[inst_offset: inst_end_offset], inst_va, 1)

            parseBBType(bb, last_inst)

            if bb.type == BlockType.NON_RETURN_CALL:
                collectNonRets(non_ret_funcs, bb, last_inst)
            elif bb.type == BlockType.DIRECT_BRANCH or bb.type == BlockType.COND_BRANCH: 
                collectTailCalls(tail_calls, bb, all_identified_funcs, funcAddr, last_inst)

    return (non_ret_funcs, tail_calls, insts)

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
                logging.error("[TailCall False Negative %d]: 0x%x, target: 0x%x" % (false_neg, cur_func, target))
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

def getBlockFile(com_file):
    if 'angrBlocksNorma' in com_file:
        return com_file.replace('angrBlocksNorma', 'angrBlocks')
    if 'dyninstBB' in com_file:
        return com_file.replace('dyninstBB', 'dyninstNoTailcall') 
    
    if 'ghidra' in com_file:
        tmp_file = com_file.replace('ghidraTailcall', 'ghidra')
        return '/data/testsuite/' + tmp_file
    return None

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

    #com_ano_file = getBlockFile(options.comparedfile)

    black_list = {'libv8', 'mysqld', 'nginx', 'libc', 'openssl'}
    '''
    for black in black_list:
        if black in options.binaryFile:
            exit(-1)
            '''

    pltRange(options.binaryFile)
    PIE = isPIE(options.binaryFile)
    if PIE:
        disassembler_base_addr = getPIEBaseOffset(options.comparedfile)

    readTextSection(options.binaryFile)

    ELFCLASS = readElfClass(options.binaryFile)

    mModule1 = blocks_pb2.module()
    mModule2 = blocks_pb2.module()
    #mModule3 = blocks_pb2.module()
    try:
        f1 = open(options.groundtruth, 'rb')
        mModule1.ParseFromString(f1.read())
        f1.close()
        f2 = open(options.comparedfile, 'rb')
        mModule2.ParseFromString(f2.read())
        f2.close()
        #f3 = open(com_ano_file, 'rb')
        #mModule3.ParseFromString(f3.read())
        #f3.close()
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

    (non_rets_truth, tail_calls, gt_insts) =\
            readGroundCFG(mModule1, options.binaryFile)

    (non_rets_comp, tail_calls_comp, com_insts) =\
            readComparedCFG(mModule2, options.binaryFile)

    neg_insts = gt_insts.difference(com_insts)
    pos_insts = com_insts.difference(gt_insts)

    compareTailCalls(tail_calls, tail_calls_comp, neg_insts, pos_insts)
