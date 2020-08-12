"""
date: 07/05/2019
author: binpang

get the functions and basic blocks from ccr tool
reference: https://github.com/kevinkoo001/CCR
"""

from deps import *
from reorderInfo import *
import optparse
import blocks_pb2
import constants as C
import reconstructInfo 
import logging
from capstone import x86
from elftools.elf.elffile import ELFFile
import ctypes
from BlockUtil import *

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)

KindList = ["C2C", "C2D", "D2C", "D2D"]

TERMINALSTR_LIST = ['leave', 'hlt', 'ud2']

jumpTableRange = list()
# jump table
jumpTable = dict()

# basic block list
# basic block addr => basic block object
bb_list = dict()

blk_list = set()

# sometimes, function has jump
# func list
# function addr => function object
func_list = dict()
BB_2_FUNCS = dict()

plt_start = 0
plt_end = 0

# .got.plt section address
GOT_PLT_ADDR = 0x0
TEXT_RANGE = (0, 0)

# if the executable is 32 bit or 64 bit
ELF_CLASS = 64

CURRENT_FUNC = 0x0

# store the valid loaded address range
LOAD_RANGE = list()

# Basic blocks address that not in our basic block list
# there are two situations:
# 1. For handwritten/inline code, we may can't get the correct basic block boundary,
# in this situation, we need split them
# 2. There may exists instruction overlappings.
#
# So we need to figure out which situation it belongs to
BB_NOT_INCLUDED = dict() # not included bb address => function belongs to
OVERLAPPINT_INSTS = list()

# gaps list: (range_start, range_end)
GAPS_LIST = list()
BB_GAPS_ADJACENT = dict() #(gap start addr => basic block above it)

# append gaps to existing basic block
# basic block that belongs to gaps
GAPS_BB_LIST = list() 
GAPS_BB_ADD_ELEMENT = dict()

BB_TYPE_MAP = dict() # we store the if the Blk is the inline/handwritten type
                     # 0 represents normal, 1 represents inline, 2 represents handwritten

# store the unsolved jump table solvers, we need hand it specifically

'''
    8209156:       e8 d5 f7 e4 ff          call   8058930 <__x86.get_pc_thunk.bx>
    820915b:       81 c3 99 de 19 00       add    $0x19de99,%ebx
    8209161:       83 ec 1c                sub    $0x1c,%esp
    8209164:       89 54 24 0c             mov    %edx,0xc(%esp)
    8209168:       3c 50                   cmp    $0x50,%al
    820916a:       74 54                   je     82091c0 <.L18+0x30>
    820916c:       89 c2                   mov    %eax,%edx
    820916e:       83 e2 0f                and    $0xf,%edx
    8209171:       80 fa 0c                cmp    $0xc,%dl
    8209174:       0f 87 91 bc e4 ff       ja     8054e0b <_ZL28read_encoded_value_with_basehjPKhPj.cold.4>
    820917a:       0f b6 d2                movzbl %dl,%edx
    820917d:       8b 8c 93 18 8f f2 ff    mov    -0xd70e8(%ebx,%edx,4),%ecx # jump table, the mode is complex
    8209184:       01 d9                   add    %ebx,%ecx
    8209186:       ff e1                   jmp    *%ecx
'''
# TODO, handle these fixups later
UNSOLVED_JBL_FIXUPS = set()

FIRST_BB_VA = 0x0
FIRST_BB_OFFSET_FROM_BASE = 0x0


################## Global variable to count the complex constructs ############

# DATA in CODE
PADDING_CNT = 0x0
HARDCODED_CNT = 0x0
HARDCODED_CNT_NUM = 0x0

# Indirect Jumps
INDIRECT_JMP_CNT = 0x0
INDIRECT_CALL = 0x0
INDIRECT_CALL_CNT = 0x0

# Overlapping instructions
OVERLAP_INS_CNT = 0x0

# Special Functions 
NONRET_CNT = 0x0
OVERLAP_FUNCS_CNT = 0x0
MULT_ENT_CNT = 0x0
NONRET_SET = set()
MULT_ENT_SET = set()

# Tail calls
TAIL_CALL_CNT = 0x0

################## End ####################################


## TODO add more terminator instructions
###########################################################

def getTerminator(blk, inslist):
    """
    get basic block's terminator

    args:
        blk:
        binary:

    rets:
        terminatorinst:
        lastinst:
    """
    terminatorinst = None
    lastinst = None
    viradr = blk.VA
    startadr = blk.start
    endadr = blk.end
    for i in inslist:
        # this is the instructions that capstone can't handle
        if i.id == 0:
            continue

        if isTerminator(i):
            terminatorinst = i
        lastinst = i


    if terminatorinst == None:
        if lastinst != None:
            logging.info("Terminator %s is not JUMP , RET or JUMP" % (getInstStr(lastinst)))
            terminatorinst = lastinst
        else:
            logging.warning("Basic block %x don't have instructions?" % (viradr))
            return (None, lastinst)

    # check if last instruction is terminator instruction
    if terminatorinst != lastinst:
        logging.warning("basic block %x - %x, its last instruction \
            is not terminator instruction" % (viradr, viradr + endadr - startadr))

    # set blk type
    blk.set_type(lastinst.groups, isIndirect(terminatorinst))
    if blk.type == 0 and x86.X86_GRP_CALL in terminatorinst.groups:
        logging.debug("Set non-return function call at 0x%x" % terminatorinst.address)
        lastinst = terminatorinst
        blk.type = BlockType.NON_RETURN_CALL

    return (terminatorinst, lastinst)



def getDirectCalledFunc(blk, binary, instList):
    """
    get called function that in blk
    """
    called_func = list()
    #insList = disassembleBB(blk, binary, ELF_CLASS)
    for ins in instList:
        if ins.id == 0:
            continue
        if x86.X86_GRP_CALL in ins.groups and isIndirect(ins) == False:
            # iter over the fixup that in the current basic block
            # get the called function reference
            for fixup in blk.parent.Fixups:
                # get the called function reference
                if fixup.VA >=ins.address and fixup.VA < ins.address + ins.size:
                    if inPltSection(fixup.refTo) == False and (fixup.refTo not in func_list):
                        logging.error("[Called Function]: The called function 0x%x in instruction 0x%x not in plt or defined func!" \
                                % (fixup.refTo, ins.address))
                    else:
                        called_func.append(fixup.refTo)
    return called_func


'''
get successors of basic block `curBB`
'''
def getSuccessors(blk, binary, inslist):
    global INDIRECT_CALL_CNT
    curBB = blk.parent
    (terminorInst, lastInst) = getTerminator(blk, inslist)

    if blk.type == BlockType.RET or \
            (terminorInst != None and \
            (terminorInst.op_str in TERMINALSTR_LIST or terminorInst.mnemonic in TERMINALSTR_LIST)):
        ## FIXME other terminator instructions
        logging.info("basic block %x end up with return/exit instruction!" % (blk.VA))
        return None

    successors = list()
    if blk.is_indirect_type():
        # check if the indirect instruction is a jump table
        if x86.X86_GRP_JUMP in terminorInst.groups:
            logging.warning("Indirect instruction %s is not a jump table!" % (getInstStr(terminorInst)))
            logging.info("[Statistics result: tail-indirect call]: at basic block 0x%x" % blk.VA)
            INDIRECT_CALL_CNT += 1

        if blk.fall_through:
            if blk.end == curBB.offsetFromBase + curBB.size - curBB.padding:
                successor_addr = curBB.VA + curBB.size - curBB.padding
            else:
                successor_addr = blk.VA + blk.end - blk.start
            
            if successor_addr not in bb_list and successor_addr not in blk_list:
                logging.error("successor addr %x not in basic block list" % (successor_addr))
                return None
            
            successors.append(successor_addr)
            return successors
        else:
            return None

    global MULT_ENT_CNT
    global OVERLAP_FUNCS_CNT
    if blk.is_direct_type():
        successors = getSuccessorsFromDirectInst(blk, terminorInst)

        # collect multiple entry functions
        # if this is a direct successor 
        # and the successor is not in current functions
        # and the successor is not functin start
        if successors != None:
            for successor in successors:
                if successor not in MULT_ENT_SET and\
                        successor in BB_2_FUNCS and CURRENT_FUNC != BB_2_FUNCS[successor] and\
                        successor != BB_2_FUNCS[successor]:
                    if x86.X86_GRP_CALL in lastInst.groups:
                        logging.info("[Statistics result: multi entry func]: at bb 0x%x" % successor)
                        MULT_ENT_CNT += 1
                    else:
                        logging.info("[Statistics result: overlapping func]: at bb 0x%x" % successor)
                        OVERLAP_FUNCS_CNT += 1
                    MULT_ENT_SET.add(successor)
    else:
    ## FIXME if the basic block does not end up with terminator instruction
    ## add its successor with next basic block
       # check if the basic block is fall through
       if blk.fall_through:
           if blk.end == curBB.offsetFromBase + curBB.size - curBB.padding:
               successor_addr = curBB.VA + curBB.size
           else:
               successor_addr = blk.VA + blk.end - blk.start
           # check if it is a overlapping basic block
           # if the current basic block is fall throuth
           # and its successor is the begining of a function
           #if successor_addr in func_list:
           #    logging.info("[Statistics result: overlapping basic block]: at bb address 0x%x" % successor_addr)
           #    OVERLAP_FUNCS_CNT += 1
           if successor_addr not in bb_list and successor_addr not in blk_list:
               logging.error("successor addr %x not in basic block list" % (successor_addr))
               return None
           successors.append(successor_addr)

       else:
           if lastInst != None and (x86.X86_GRP_CALL in lastInst.groups or x86.X86_GRP_RET in lastInst.groups):
               logging.warning("The basic block %x is the function's last basic block, and its last instuction is CALL!" % (curBB.VA))
           else:
               logging.error("The basic block %x-%x does not end of JUMP or RET, and is not FALLTHROUGH!. its instruction is %s" %
                       (blk.VA, blk.VA + blk.end - blk.start, getInstStr(terminorInst)))
           return None


    return successors

def inPltSection(addr):
    return isInRange(addr, [(plt_start, plt_end)])

'''
helper function:
    get successors from direct jump instruction
args:
    curBB: basic block object
    terminator_inst: terminator instruction
    fall_through: if the basic block is fall through
'''
def getSuccessorsFromDirectInst(blk, terminator_inst):
    global TAIL_CALL_CNT
    curBB = blk.parent
    inst_start = terminator_inst.address
    inst_end = terminator_inst.address + terminator_inst.size - 1;
    # get current basic block's fixups
    # and find the fixup that in terminator instruction
    successor_fixup = None
    for fixup in curBB.Fixups:
        if fixup.VA >= inst_start and fixup.VA <= inst_end:
            successor_fixup = fixup
            break

    if successor_fixup == None:
        logging.warning("Terminator inst of BasicBlock %x does not have a fixup?" % 
                (blk.VA))
        return None

    successors = list()
    successors.append(successor_fixup.refTo)

    if blk.fall_through:
        if blk.end == blk.parent.offsetFromBase + blk.parent.size - blk.parent.padding:
            successors.append(curBB.VA + curBB.size - blk.parent.padding)
        else:
            successors.append(blk.VA + blk.end - blk.start)

    # check if the successors' address is correct
    del_list = list()
    for addr in successors:
        # somtimes, it jumps to .plt section's entry
        if inPltSection(addr):
            logging.warning("the address %x in basic block %x - %x is a jump to plt function!" % 
                        (addr, blk.VA, blk.VA+ blk.end - blk.start))
            #del_list.append(addr)
            # deem this situation as tail call to external function
            if blk.is_jump:
                blk.type = BlockType.TAIL_CALL

        elif addr in bb_list or addr in blk_list:
            if addr in func_list:
                # del_list.append(addr)
                if blk.is_jump:
                    # the successor is the start of a function, deem it as a tail call
                    logging.warning("the address %x in basic block %x - %x is a jump to defined function, maybe a tail call?" % 
                        (addr, blk.VA, blk.VA+blk.end-blk.start))
                    blk.type = BlockType.TAIL_CALL
        else:
            logging.warning("the address %x in basic block %x is not a basic block list. Inst is %s" % \
                    (addr, blk.VA, getInstStr(terminator_inst)))

            global BB_NOT_INCLUDED
            if x86.X86_GRP_CALL in terminator_inst.groups:
                BB_NOT_INCLUDED[addr] = addr
            else:
                BB_NOT_INCLUDED[addr] = blk.parent.parent.VA
            logging.info("Put the bb target address 0x%x to BB_NOT_INCLUDED list, handle it later!" % (addr))

    if blk.type == BlockType.TAIL_CALL:
        logging.info("[Statistics result: Tail call]: at bb address 0x%x" % (blk.VA))
        TAIL_CALL_CNT += 1

    for del_ele in del_list:
        successors.remove(del_ele)

    if len(successors) == 0:
        return None

    return successors
        
def getInstsBeginFromAddr(addr, inst_list):
    result = list()
    added = False
    for inst in inst_list:
        if added or (addr >= inst.address and addr < inst.address + inst.size):
            added = True
            result.append(inst)
    return result

def findIndirectBB(fi, currentBB, binary):
    """
    get the first indirect jmp instruction from current basic block

    args:
        currentBB: current basic block
        binary: binary file path

    rets:
        fail return -1
        return the first indirect jmp instruction
    """
    
    queueList = list()
    queueList.append(currentBB)
    visited = set()
    cur_bb_num = 0

    # tainted registers from jump table fixup
    # we assume the relationship between jmptbl fixup to the indirect jump
    # only popluates between regs
    queue_tainted_regs = list()
    queue_tainted_regs.append(set())

    first = True

    while len(queueList) > 0:
        curBB = queueList.pop(0)
        cur_tainted_regs = queue_tainted_regs.pop(0)
        logging.debug("current taint regs is {}".format(cur_tainted_regs))

        if curBB == None:
            continue
        if curBB.VA in visited:
            continue
        cur_bb_num += 1

        logging.debug("current bb is 0x%x - 0x%x" % (curBB.VA, curBB.VA + curBB.size - curBB.padding))
        visited.add(curBB.VA)
        startAdr = curBB.offsetFromBase
        endAdr = curBB.size + startAdr - curBB.padding
        virAdr = curBB.VA
        tmp_blk = Blk(virAdr, startAdr, endAdr, curBB, curBB.hasFallThrough)

        inslist = disassembleBB(tmp_blk, binary, ELF_CLASS)

        if first:
            inslist = getInstsBeginFromAddr(fi, inslist)
            # the jmptbl is in indirect jump instruction
            if isJumpTable(inslist[0]):
                return curBB

        updated_tainted_regs = taintRegsCrossBB(inslist, cur_tainted_regs, first)
        first = False

        if len(updated_tainted_regs) == 0:
            logging.warning("don't have taint regs!")
            continue

        (terminorInst, _,) = getTerminator(tmp_blk, inslist)

        if tmp_blk.type == BlockType.INDIRECT_BRANCH:
            if isJumpTable(terminorInst) and \
                    instReadRegsIsTaint(terminorInst, updated_tainted_regs):
                return curBB
            elif curBB.VA in jumpTable:
                for successor_addr in jumpTable[curBB.VA]:
                    queueList.append(bb_list[successor_addr])
                    queue_tainted_regs.append(updated_tainted_regs.copy())
            else:
                continue


        if tmp_blk.type == BlockType.FALL_THROUGH:
            successor_addr = curBB.VA + curBB.size
            if successor_addr not in bb_list:
                logging.error("successor addr %x not in basic block list" % (successor_addr))
            else:
                queueList.append(bb_list[successor_addr])
                queue_tainted_regs.append(updated_tainted_regs.copy())
            continue


        if tmp_blk.is_direct_jump():
            successors = getSuccessorsFromDirectInst(tmp_blk, terminorInst)
            if successors != None:
                for successor_addr in successors:
                    if successor_addr not in bb_list:
                        logging.error("successor addr %x not in basic block list" % (successor_addr))
                    else:
                        queueList.append(bb_list[successor_addr])
                        queue_tainted_regs.append(updated_tainted_regs.copy())

        elif tmp_blk.fall_through:
            successor_addr = curBB.VA + curBB.size
            if successor_addr not in bb_list:
                logging.error("successor addr %x not in basic block list" % (successor_addr))
            else:
                queueList.append(bb_list[successor_addr])
                queue_tainted_regs.append(updated_tainted_regs.copy())
        elif tmp_blk.is_call == False and tmp_blk.type == BlockType.RET:
            logging.warning("The basic block %x-%x end up with ret!. its instruction is %s" %
                    (curBB.VA, curBB.VA + curBB.size - curBB.padding, getInstStr(terminorInst)))

    return None

'''
read jump table entries
'''
def readTableEntries(target, numEntries, szEntry, binary, added_base = 0x0):
    successors = list()
    binaryFile = open(binary, 'rb')
    content = binaryFile.read()
    elf = ELFFile(binaryFile)
    entryPoint = elf.header['e_entry']
    base = elf.get_segment(2)['p_vaddr']
    if entryPoint <= 0:
        base = 0
    offset = target - base
    endian = '>'
    if 'LSB' in elf.header['e_ident']['EI_DATA']:
        endian = '<'
    unpackType = ''
    if szEntry == 4:
        unpackType = 'I'
    elif szEntry == 8:
        unpackType = 'Q'
    else:
        log.warning("The entry size is %d, I can't handle" % (szEntry))

    unpackStr = endian + unpackType
    successorCnt = 0
    for idx in range(numEntries):
        addrSt = offset + idx * szEntry
        addrEnd = offset + (idx+1) * szEntry
        entry = content[addrSt:addrEnd]
        entryContent = struct.unpack(unpackStr, entry)
        entryAddr = entryContent[0] 
        # for 64-bit executable, if the jump table entry is 4 bits
        # its address computation is "table_base + entryContent"
        # FIXME. Here I only consider the executable is 64-bit for now.
        if szEntry == 4 and ELF_CLASS == 64:
            entryAddr = target + ctypes.c_int32(entryAddr).value

        # for 32-bit, the jump table targets may be added by the base address
        elif ELF_CLASS == 32 and added_base != 0:
            entryAddr = added_base + ctypes.c_int32(entryAddr).value

        logging.info("Entry#%d is %x" % (successorCnt, entryAddr))
        successorCnt += 1
        successors.append(entryAddr)


    binaryFile.close()
    return successors

def scanJumpTable(essInfo, binary):
    """
    scan the text section to get the jump table entry

    args:
        essInfo: essentialInfo that ccr define
        binary: the binary file
    returns:
        jumpTable: associated with the jump table information jumpTable[bb] = list(successors)
    """
    global INDIRECT_JMP_CNT
    global INDIRECT_CNT
    global jumpTable
    last_num = 0
    if not essInfo.hasFixupsInText():
        return dict()
    jmpcnt = 0

    for fi in essInfo.getFixupsText():
        UNSOLVED_JBL_FIXUPS.add(fi)

    ## Reach a fixpoint.
    ## until no new jump table solved.
    while last_num != len(UNSOLVED_JBL_FIXUPS):
        last_num = len(UNSOLVED_JBL_FIXUPS)
        saved_jbl_fixups = UNSOLVED_JBL_FIXUPS.copy()
        for fi in saved_jbl_fixups:
            if fi.numJTEntries > 0:
                jmpcnt += 1
                logging.debug("fi 0x%x, entry number is %d, its parent is 0x%x" % (fi.VA, fi.numJTEntries, fi.parent.VA))
                indirectBB = findIndirectBB(fi.VA, fi.parent, binary)
                if indirectBB == None:
                    logging.warning("current jump table fixup %x can't resolve the indirect jump basic block" % (fi.VA))
                    continue

                table_base = 0x0
                # for 32 bit, table entry added base size
                entry_added_base = 0x0 
                # check if the reference target is the valid address
                if isInRange(fi.refTo, LOAD_RANGE):
                    table_base = fi.refTo
                # FIXME: In 32-bit, the pic mode(such as 32 bit libraries), the JMPTable's base address is calculated by: fixp content + .got.plt addr
                elif 32 == ELF_CLASS and (isInRange(fi.refTo + GOT_PLT_ADDR, LOAD_RANGE)): 
                    table_base = fi.refTo + GOT_PLT_ADDR 
                    entry_added_base = GOT_PLT_ADDR

                logging.info("JMPTBL#%d: fixup addr %x, Table addr %x, table size %d, entry size %d" % 
                        (jmpcnt, fi.VA, table_base, fi.numJTEntries, fi.jtEntrySz))

                successors = readTableEntries(table_base, fi.numJTEntries, fi.jtEntrySz, binary, entry_added_base)
                # check the successor's address
                for suc in successors:
                    if isInRange(suc, [TEXT_RANGE]) == False:
                        logging.error("successor address 0x%x is not in .text section!" % (suc))

                # log the jump table information
                logging.info("[Statistics Result: JMP TBL]: find jmp table at address 0x%x" % indirectBB.VA)
                INDIRECT_JMP_CNT += 1
                # end log the jump table information
                jumpTable[indirectBB.VA] = successors
                UNSOLVED_JBL_FIXUPS.discard(fi)

    return jumpTable


def dumpGroundTruth(essInfo, pbModule, outFile, binary, split):
    """
    print the ground truth of the binary code,
    which mainly include the basicblocks and functions

    args:
        essInfo: essentialinfo that ccr define
        pbModule: proto buffer defined module definition
        outfile: log output
        binary: the binary file
        split: whether `call` instruction split basic block

    returns:
    """
    if outFile == None:
        outFile = '/tmp/ccrGroundTruth.log'
    out = open(outFile, 'w')
    constructInfo = essInfo.constructInfo
    bbList = constructInfo.BasicBlockLayout
    funcList = constructInfo.FunctionLayout
    jmp_targets = list()
    
    # handle gaps
    handleGapsFallThrough(bbList, binary)

    # update bb_list
    global FIRST_BB_VA, FIRST_BB_OFFSET_FROM_BASE
    global BB_2_FUNCS

    # complex result count
    global PADDING_CNT
    global NONRET_CNT
    global NONRET_SET
    # end complex result count

    FIRST_BB_VA = bbList[0].VA
    FIRST_BB_OFFSET_FROM_BASE = bbList[0].offsetFromBase

    global bb_list
    for bb in bbList:
        bb_list[bb.VA] = bb
        BB_2_FUNCS[bb.VA] = bb.parent.VA

    # update func_list
    global func_list
    for func in funcList:
        func_list[func.VA] = func

    global jumpTable
    jumpTable = scanJumpTable(essInfo, binary)
    blockNum = 0

    global plt_start, plt_end
    (plt_start, plt_end) = readSectionRange(binary, '.plt')
    logging.debug("The plt start addr is 0x%x, end addr is 0x%x" % (plt_start, plt_end))

    global BB_TYPE_MAP

    global CURRENT_FUNC

    for idx, func in enumerate(funcList):
        # add function into protobuf
        addedFunc = pbModule.fuc.add()
        pbModule.split_block = split
        addedFunc.va = func.VA
        CURRENT_FUNC = func.VA
        # Do we need to add function size?
        # addedFunc.size = 
        logging.debug("Found function#%d: %x" % (idx, func.VA))
        addedFunc.type = func.type
        for bbidx, bb in enumerate(func.BasicBlocks):
            logging.debug("Found basicblock#%d: %x to %x" % (bbidx, bb.VA, bb.VA+bb.size))
            if bb.padding > 0x0:
                logging.info("[Statistics Result: Padding]: find padding at basic block 0x%x" % bb.VA)
                PADDING_CNT += 1

            # if the basic block is in GAPS_BB_ADD_ELEMENT
            # we need to fix its basic block size and padding size
            if bb.VA in GAPS_BB_ADD_ELEMENT:
                tmp_blk = GAPS_BB_ADD_ELEMENT[bb.VA]
                logging.debug("[Fixing]: basic block size: %d -> %d" % 
                        (bb.size, tmp_blk.size + bb.padding + tmp_blk.padding))
                bb.size = tmp_blk.size + tmp_blk.padding + bb.padding
                bb.padding += tmp_blk.padding
                logging.debug("Fixing]: bb va 0x%x -> tmp va 0x%x" % (bb.VA, tmp_blk.VA))
                if bb.VA != tmp_blk.VA:
                    bb.offsetFromBase += tmp_blk.VA - bb.VA
                    bb.VA = tmp_blk.VA
                    logging.info("[Fixed]: basicblock#%d: %x to %x" % (bbidx, bb.VA, bb.VA+bb.size))

            # split the basic block
            splited_bbs = split_block(bb, binary, split, ELF_CLASS)
            bb_end_adr = bb.offsetFromBase + bb.size - bb.padding

            global blk_list
            for blk in splited_bbs:
                blk_list.add(blk.VA)
                BB_TYPE_MAP[blk.VA] = bb.assembleType

            for blk in splited_bbs:
                addedBB = addedFunc.bb.add()
                addedBB.va = blk.VA
                addedBB.parent = addedFunc.va
                addedBB.size = blk.end - blk.start
                
                # if the blk is the last basic block of bb
                if blk.end == bb_end_adr:
                    addedBB.padding = bb.padding
                    # we can't get the basic block in handwritten code 
                    # fall through or not.
                    # so we need to confirm it by its last instruction
                    if bb.assembleType != 2:
                        bb.fall_through = bb.hasFallThrough
                else:
                    addedBB.padding = 0

                # get instruction list
                inst_list = disassembleBB(blk, binary, ELF_CLASS)
                inst_idx = 0
                for inst in inst_list:
                    addedInst = addedBB.instructions.add()
                    addedInst.va = inst.address
                    addedInst.size = inst.size
                    try:
                        if x86.X86_GRP_CALL in inst.groups:
                            if isIndirect(inst):
                                addedInst.call_type = 2;
                            else:
                                addedInst.call_type = 3;

                        if inst.id == x86.X86_INS_UD2:
                            addedBB.terminate = True
                            logging.info("basic block 0x%x contains ud2 instruction!" % addedBB.va)
                    except:
                        continue

                non_ret = False
                # check if the called function is non-returning function
                if len(inst_list) > 0:

                    last_inst = inst_list[-1]
                    is_indirect = isIndirect(last_inst)
                    blk.set_type(last_inst.groups, is_indirect)
                    addedBB.type = blk.type
                    if last_inst.id != 0 and x86.X86_GRP_CALL in last_inst.groups and not blk.fall_through:
                        logging.info("[Non-return]: Instruction %s call a non-return function!" % 
                                                                    (getInstStr(last_inst)))
                        non_ret = True
                    

                # get direct called function
                called_func_list = getDirectCalledFunc(blk, binary, inst_list)
                for called_func in called_func_list:
                    added_called_func = addedFunc.calledFunction.add()
                    added_called_func.va = called_func
                    if non_ret and called_func not in NONRET_SET and inPltSection(called_func):
                        logging.info("[Statistics result: non-ret]: function 0x%x is non-return" % (called_func))
                        NONRET_CNT += 1
                        NONRET_SET.add(called_func)

                ## If the basic block's terminator is the indirect jump and it is jump table
                if blk.end == bb_end_adr and bb.VA in jumpTable:
                    successors = jumpTable[bb.VA]
                    logging.debug("The terminator of basic block %x is jump table!" % (addedBB.va))
                    logging.debug("The successor of basic block %x is %s" %
                        (addedBB.va, ' '.join([hex(element) for element in successors])))
                    for addr in successors:
                        child = addedBB.child.add()
                        child.va = addr
                    addedBB.type = BlockType.JUMP_TABLE

                else:
                    successors = getSuccessors(blk, binary, inst_list)
                 # we extend the successors if the basic block is in GAPS_BB_ADD_ELEMENT
                    if blk.end == bb_end_adr and bb.VA in GAPS_BB_ADD_ELEMENT:
                        if successors == None:
                            successors = list()
                        for suc in GAPS_BB_ADD_ELEMENT[bb.VA].successors:
                            successors.append(suc)

                    if successors == None:
                        continue

                    logging.info("The successor of basic block %x is %s" %
                        (addedBB.va, ' '.join([hex(element) for element in successors])))

                    for addr in successors:
                        child = addedBB.child.add()
                        child.va = addr
                    addedBB.type = blk.type
                    if addedBB.type == BlockType.OTHER:
                        logging.warning("can't get the basic block %x type\n" % (addedBB.va))
            logging.info("block 0x%x to 0x%x, type is %d" % (addedBB.va, addedBB.va + addedBB.size, addedBB.type))
    handleNotIncludedBB(pbModule)
    handleNotIncludedBBInGaps(binary)
    addBBInGaps(pbModule)

'''
add the basic block that in gaps to its related functions
'''
def addBBInGaps(pbModule):
    dummy_func_list = set()
    for blk in GAPS_BB_LIST:
        added = False
        for func in pbModule.fuc:
            if func.va == blk.function:
                logging.debug("[addBBInGaps]: add blk(0x%x - 0x%x) to function 0x%x" % 
                        (blk.VA, blk.VA + blk.end - blk.start, blk.function))
                addedBB = func.bb.add()
                addedBB.va = blk.VA
                addedBB.parent = blk.function
                addedBB.size = blk.end - blk.start
                addedBB.type = blk.type
                added = True

                for inst in blk.ins_list:
                    addedInst = addedBB.instructions.add()
                    addedInst.va = inst.address
                    addedInst.size = inst.size
                for suc in blk.successors:
                    child = addedBB.child.add()
                    child.va = suc
        if not added:
            dummy_func_list.add(blk)

        # dummy function
    for blk in dummy_func_list:
        func = pbModule.fuc.add()
        func.va = 0x0
        logging.debug("add basic block of 0x%x to dummy function" % blk.VA)
        bb = func.bb.add()
        bb.va = blk.VA
        bb.parent = 0x0
        addedSize = blk.end - blk.start
        bb.type = blk.type
        for inst in blk.ins_list:
            addedInst = bb.instructions.add()
            addedInst.va = inst.address
            addedInst.size = inst.size
        for suc in blk.successors:
            child = addedBB.child.add()
            child.va = suc


'''
handle the not included basic block target address
These basic blocks are not identified as 
we did't handle the jump/call targets in assemble file before.
So we need to split the basic blocks here.
'''
def handleNotIncludedBB(pbModule):
    if len(BB_NOT_INCLUDED) == 0:
        return

    global OVERLAP_INS_CNT
    find_num = 0
    for func in pbModule.fuc:
        for bb in func.bb:
            # we only focus on inline/handwritten code
            if bb.va not in BB_TYPE_MAP or BB_TYPE_MAP[bb.va] == 0:
                continue
            #TODO handle the logic code
            del_bb = list()
            
            # split point index
            split_point = list()
            overlapping = False
            overlapping_target = None
            for not_bb_va in BB_NOT_INCLUDED.keys():
                if not_bb_va >= bb.va and not_bb_va < (bb.va + bb.size):
                    del_bb.append(not_bb_va)
                    logging.info("Find the not included bb#%d 0x%x in bb 0x%x" % 
                            (find_num, not_bb_va, bb.va))
                    find_num += 1
                    for (idx, inst) in enumerate(bb.instructions):
                        if inst.va == not_bb_va:
                            logging.debug('[Split block]: from inst address 0x%x' % 
                                    (inst.va))
                            split_point.append(idx)
                        # find overlapping instructions
                        if not_bb_va > inst.va and not_bb_va < inst.va + inst.size:
                            # check if inst is the fist instruction
                            overlapping = True
                            overlapping_target = not_bb_va
                            

                # sometimes, there exists `jmp padding_addr`
                if not_bb_va >= (bb.va + bb.size) and \
                        not_bb_va < (bb.va + bb.size + bb.padding):
                    logging.info("Find the not included bb#%d 0x%x in padding 0x%x" % 
                            (find_num, not_bb_va, bb.va + bb.size))
                    del_bb.append(not_bb_va)
                    find_num += 1

            # split the basic block according to the split index
            last_bb = None
            saved_successors = list()
            if len(split_point) > 0:
                saved_type = bb.type
                for suc in bb.child:
                    saved_successors.append(suc.va)
                del bb.child[:]

            prevBB = bb
            for (idx, split_idx) in enumerate(split_point):
                if idx == len(split_point) - 1:
                    next_idx = len(bb.instructions)
                else:
                    next_idx = split_point[idx + 1]
                addedBB = func.bb.add()
                addedBB.va = bb.instructions[split_idx].va
                addedBB.parent = func.va
                addedBB.size = 0
                prevBB.type = BlockType.FALL_THROUGH
                last_bb = addedBB
                for i in range(split_idx, next_idx):
                    addedInst = addedBB.instructions.add()
                    addedInst.va = bb.instructions[i].va
                    addedInst.size = bb.instructions[i].size
                    addedBB.size += addedInst.size
                if addedBB.va not in [successor.va for successor in prevBB.child]:
                    child = addedBB.child.add()
                    child.va = addedBB.va

            if last_bb != None:
                last_bb.padding = bb.padding
                bb.padding = 0
                last_bb.type = saved_type
                for suc in saved_successors:
                    child = last_bb.child.add()
                    child.va = suc
            
            if len(split_point) > 0:
                del bb.instructions[split_point[0]:]
  
            for not_bb_va in del_bb:
                BB_NOT_INCLUDED.pop(not_bb_va, None)

            # handle overlapping instructions
            # we treat the overlapping instruction as single basic block
            if overlapping:
                logging.info("[Statistics Result: Overlap Ins]: find overlapping instruction at 0x%x" % overlapping_target)
                OVERLAP_INS_CNT += 1
                if len(bb.instructions) > 1:
                    addedBB1 = func.bb.add()
                    addedBB1.va = bb.instructions[0].va
                    addedBB1.parent = func.va
                    bb.size = bb.instructions[0].size
                    inst1 = addedBB1.instructions.add()
                    inst1.va = bb.instructions[0].va
                    inst1.size = bb.instructions[0].size
                    child = addedBB1.child.add()
                    child.va = bb.instructions[1].va
                    addedBB2 = func.bb.add()
                    addedBB2.va = overlapping_target
                    addedBB2.parent = func.va
                    addedBB2.size = bb.instructions[0].va + bb.instructions[0].size - overlapping_target
                    logging.debug("overlapping instruction addr 0x%x, size %d" % 
                            (addedBB2.va, addedBB2.size))
                    inst2 = addedBB2.instructions.add()
                    inst2.va = addedBB2.va
                    inst2.size = addedBB2.size
                    child = addedBB2.child.add()
                    child.va = bb.instructions[1].va
                    del bb.instructions[0]
                
    if len(BB_NOT_INCLUDED) != 0:
        logging.warning("The BB_NOT_INCLUDED is not NULL, please check it manually!")
        logging.info("The un-handled bb target is:")
        for (bb_idx, bb_addr) in enumerate(BB_NOT_INCLUDED.keys()):
            logging.warning("Un-handled basic block num#%d: addr 0x%x" % (bb_idx, bb_addr))
        logging.debug("Check the unhandled basic block in gaps!")

'''
check whether the target address is in gaps
'''
def handleNotIncludedBBInGaps(binary):
    if len(BB_NOT_INCLUDED) == 0:
        return
    handleIdx = 0
    for (not_included_va, function) in BB_NOT_INCLUDED.items():
        for (gap_start, gap_end) in GAPS_LIST:
            if not_included_va >= gap_start and not_included_va < gap_end:
                logging.debug("[HandleNotIncludedBBInGaps]#%d: the target address 0x%x is in the range of gap(0x%x - 0x%x)" % 
                        (handleIdx, not_included_va, gap_start, gap_end))
                handleIdx += 1
                gap_start_off = FIRST_BB_OFFSET_FROM_BASE + gap_start - FIRST_BB_VA
                gap_end_off = gap_start_off + gap_end - gap_start
                result_bbl_list = recursiveDisassembleInRange(binary, gap_start, \
                        gap_start_off, gap_end_off, not_included_va - gap_start, \
                        ELF_CLASS, function)
                for idx in range(0, len(result_bbl_list)):
                    logging.debug("[handleNotIncludedBBInGaps] add bbl list!" )
                    GAPS_BB_LIST.append(result_bbl_list[idx])
'''
For some reasons, there may exist some paddings that emitted by .byte in assemble code or inline code
example in glibc/sysdeps/x86_64/strcmp.S
ENTRY2 (__strcasecmp)
    movq    __libc_tsd_LOCALE@gottpoff(%rip),%rax
    mov     %fs:(%rax),%RDX_LP

    // XXX 5 byte should be before the function
    /* 5-byte NOP.  */
    .byte   0x0f,0x1f,0x44,0x00,0x00
    // fallthrough
END2 (__strcasecmp)
'''
def handleGapsFallThrough(bblist, binary):
    global GAPS_BB_ADD_ELEMENT
    global GAPS_BB_LIST
    global blk_list
    bb_end_list = dict()
    bb_start_list = dict()
    for bb in bblist:
        bb_end_list[bb.VA + bb.size] = bb
        bb_start_list[bb.VA] = bb
    for (gap_start, gap_end) in GAPS_LIST:
        if gap_start in bb_end_list:
            gap_size = gap_end - gap_start
            # case 0: some gap due to the prefix by handwritting
            if gap_size < 4 and gap_end in bb_start_list:
                bb_case0 = bb_start_list[gap_end]
                logging.info("Find the gap(0x%x - 0x%x) before basic block(0x%x - 0x%x)" % 
                        (gap_start, gap_end, bb_case0.VA, bb_case0.VA + bb_case0.size))
                bb_start_adr_case0 = bb_case0.offsetFromBase
                bb_end_adr_case0 = bb_case0.size + bb_start_adr_case0 - bb_case0.padding
                blk_case0 = Blk(bb_case0.VA - gap_size, bb_start_adr_case0 - gap_size, bb_end_adr_case0, bb_case0, bb_case0.hasFallThrough)
                ins_list = disassembleBB(blk_case0, binary, ELF_CLASS, one_inst = True)
                ins = ins_list[-1] if len(ins_list) > 0 else None
                if ins != None and checkInsPrefix(ins):
                    logging.debug("lalal, we can handle case 0!")
                    GAPS_BB_ADD_ELEMENT[bb_case0.VA] = blk_case0
                    logging.debug("lalal, case0 bb va is 0x%x" % blk_case0.VA)
                    blk_list.add(blk_case0.VA)
                    continue
            bb = bb_end_list[gap_start]
            if bb == None:
                continue
            bb_start_adr = bb.offsetFromBase
            bb_end_adr = bb.size + bb_start_adr - bb.padding
            bb_va_end_adr = bb.size + bb.VA - bb.padding
            blk = Blk(bb.VA, bb_start_adr, bb_end_adr, bb, bb.hasFallThrough)
            logging.info("Find the gap(0x%x - 0x%x) behind basic block 0x%x, size is %d, padding is %d" 
                    % (gap_start, gap_end, bb.VA, bb.size, bb.padding))
            ins_list = disassembleBB(blk, binary, ELF_CLASS)

            last_inst = ins_list[-1]
            case_one = False
            # check if the basic block disassemble all the instructions
            # 
            # case 1:
            # Special case: in libc/sysdeps/unix/sysv/linux/x86/arch-pkey.h:pkey_get(void)
            # inline code may emit bytes by .byte, which is deemed as instructions
            # __asm__ volatile (".byte 0x0f, 0x01, 0xee"
            #       : "=a" (result) : "c" (0) : "rdx"); #rdpkru
            if (last_inst.address + last_inst.size != bb_va_end_adr) and \
                    (bb.assembleType == 1): # the basic block contains inline assemble
                # we put the gap bytes size to code size
                blk_tmp = Blk(bb.VA, bb_start_adr, bb_end_adr + gap_size, bb, bb.hasFallThrough)
                logging.debug("lalal, we find case 1!")
                ins_list = disassembleBB(blk_tmp, binary, ELF_CLASS)
                last_inst = ins_list[-1]
                logging.debug("last instruction is %s" % getInstStr(last_inst))
                logging.debug("last instruction end addr %d, bb end addr %d" % 
                                        (last_inst.address + last_inst.size, bb_va_end_adr + gap_size))
                if (last_inst.address + last_inst.size == bb_va_end_adr + gap_size):
                    logging.debug("lalal, we can handle case 1!")
                    logging.debug("emmm, extend the bb size. %d -> %d" % 
                            (blk.size, blk.size + gap_size))
                    blk.size += gap_size
                    GAPS_BB_ADD_ELEMENT[bb.VA] = blk

            elif (last_inst.address + last_inst.size == bb_va_end_adr) and \
                    (bb.assembleType == 1) and isFallThrough(last_inst) \
                    and bb.padding > 0:
                logging.debug("lalal, we find case 1-2!")
                case_one = True
                # we put the gap bytes size to code size
                blk_tmp = Blk(bb.VA + bb.size - bb.padding, bb_end_adr , bb_end_adr + gap_size, bb, bb.hasFallThrough)
                ins_list = disassembleBB(blk_tmp, binary, ELF_CLASS)
                last_inst = ins_list[-1]
                logging.debug("last instruction is %s" % getInstStr(last_inst))
                if (last_inst.address + last_inst.size == bb_va_end_adr + gap_size):
                    logging.debug("lalal, we can handle case 1-2!")
                    logging.debug("emmm, extend the bb size. %d -> %d" % 
                            (blk.size, blk.size + gap_size))
                    blk.size += gap_size
                    GAPS_BB_ADD_ELEMENT[bb.VA] = blk

            # case 2:
            # The last instruction is a fall through instruction:
            if not case_one and (last_inst.address + last_inst.size == bb_va_end_adr) and \
                        isFallThrough(last_inst):
                logging.debug("lalal, we find case 2!")
                gap_start_off_from_base = bb_start_adr + gap_start - bb.VA - bb.padding
                gap_end_off_from_base = gap_start_off_from_base + gap_end - gap_start - bb.padding
                disassemble_entry = 0
                result_bbl_list = recursiveDisassembleInRange(binary, gap_start - bb.padding, \
                                gap_start_off_from_base, gap_end_off_from_base, \
                                0, ELF_CLASS, bb.parent)
                if len(result_bbl_list) > 0:
                    logging.debug("lalal, we can handle case 2!")
                    for result_bbl in result_bbl_list:
                        for inst in result_bbl.ins_list:
                            logging.debug("emmm, add valid instruction. %s" % 
                                                (getInstStr(inst)))
                            blk.size += inst.size
                    for successor in result_bbl_list[-1].successors:
                        blk.add_successor(successor)

                    # check if the last instruction of last basic block
                    # is a terminator instruction
                    #if not isTerminator(result_bbl_list[-1].ins_list[-1]):
                    #    if len(result_bbl_list) == 1:
                    GAPS_BB_ADD_ELEMENT[bb.VA] = blk

                    #TODO: if the last basic block's instruction  is not terminator, we need to merge them.
                    for idx in range(1, len(result_bbl_list)):
                        GAPS_BB_LIST.append(result_bbl_list[idx])
        else:
            logging.error("Can't find basic block above gap 0x%x!" % (gap_start))

def countGaps(final_gaps_list):
    global HARDCODED_CNT
    global HARDCODED_CNT_NUM
    for (gap_start, gap_end) in final_gaps_list:
        if (gap_end - gap_start) > 0x50:
            HARDCODED_CNT += (gap_end - gap_start)
            HARDCODED_CNT_NUM += 1
            logging.info("[Statistics result: Hand-coded bytes at 0x%x - 0x%x, size %d" % (gap_start, gap_end, gap_end - gap_start))

def dumpSummary():
    logging.info("=======================================================")
    logging.info("[Summary]: padding cnt is %d" % PADDING_CNT)
    logging.info("[Summary]: handcoded bytes is %d" % HARDCODED_CNT)
    logging.info("[Summary]: handcoded number is %d" % HARDCODED_CNT_NUM)
    logging.info("[Summary]: Jump tables is %d" % INDIRECT_JMP_CNT)
    logging.info("[Summary]: Tail indirect call is %d" % INDIRECT_CALL_CNT)
    logging.info("[Summary]: overlapping instructions is %d" % OVERLAP_INS_CNT)
    logging.info("[Summary]: Non-returning function is %d" % NONRET_CNT)
    logging.info("[Summary]: Multi-entry function is %d" % MULT_ENT_CNT)
    logging.info("[Summary]: overlapping functions is %d" % OVERLAP_FUNCS_CNT)
    logging.info("[Summary]: tail call count is is %d" % TAIL_CALL_CNT)

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-b", "--binary", dest = "binary", action="store", type="string", help="input elf binary path", default=None)
    parser.add_option("-m", "--metadata", dest = "metadata", action="store", type="string", help="metadata file path", default=None)
    parser.add_option("-l", "--log", dest = "log", action="store", type="string", help="log file of the program", default="/tmp/ccr_basicblocks.log")
    parser.add_option("-o", "--output", dest = "output", action = "store", type = "string", help = "output of the jump table proto buf", default = "/tmp/ccr_basicblocks.pb")
    parser.add_option("-s", dest = "split", action = "store_true", help = "split the basic block by call inst", default = False)
    (options, args) = parser.parse_args()
    if options.binary == None:
        print('Please input the elf file')
        exit(-1)

    shuffleInfoBin = None
    if options.metadata == None:
        shuffleInfoBin = options.binary + C.METADATA_POSTFIX
    else:
        shuffleInfoBin = options.metadata

    rData = None
    raw_protobuf_buffer = None
    if os.path.exists(shuffleInfoBin):
        rData = reconstructInfo.read(shuffleInfoBin, False, options.binary)
        raw_protobuf_buffer = reconstructInfo.readRawBufferInfo(shuffleInfoBin, False)
    elif os.path.exists(C.METADATA_PATH):
        rData = reconstructInfo.read(C.METADATA_PATH, True, options.binary)
        raw_protobuf_buffer = reconstructInfo.readRawBufferInfo(C.METADATA_PATH, True)
    else:
        print("Error: No metadata file\n")
        exit(-1)

    outFile = options.log

    module = blocks_pb2.module()

    ELF_CLASS = readElfClass(options.binary)
    LOAD_RANGE= getLoadAddressRange(options.binary)
    (GOT_PLT_ADDR, _) = readSectionRange(options.binary, '.got.plt')
    TEXT_RANGE = readSectionRange(options.binary, '.text')
    logging.debug("ELF_CLASS is %d", ELF_CLASS)
    logging.debug("LOAD RANGE is {0}".format(LOAD_RANGE))
    logging.debug("GOT_PLT_ADDR is 0x%x" % (GOT_PLT_ADDR))
    logging.debug(".text section range is 0x%x to 0x%x" % (TEXT_RANGE[0], TEXT_RANGE[1]))

    rData['bin_info']['bin_path'] = options.binary
    essInfo = EssentialInfo(rData)

    # get the gaps in .text.xxx
    # bbl_layout = fixOneBytePadding(raw_protobuf_buffer.layout)
    # bbl_layout = fixFunctionStartInGaps(bbl_layout, options.binary)
    #bbl_layout = raw_protobuf_buffer.layout
    textsec_info = get_textsec_info(options.binary)
    GAPS_LIST = checkGaps(essInfo.constructInfo.BasicBlockLayout, TEXT_RANGE[1])

    dumpGroundTruth(essInfo, module, outFile, options.binary, options.split)
    pbOut = open(options.output, "wb")
    pbOut.write(module.SerializeToString())
    pbOut.close()

    final_gaps_list = checkGapsAtEnd(module, TEXT_RANGE[1])
    countGaps(final_gaps_list)
    dumpSummary()
