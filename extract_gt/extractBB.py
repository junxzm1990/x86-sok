"""
date: 07/05/2019
author: binpang

get the functions and basic blocks from ccr tool
reference: https://github.com/kevinkoo001/CCR
"""

import logging
from .deps import *
from reorderInfo import *
import optparse
import blocks_pb2
import constants as C
import reconstructInfo
import capstone as cs
from capstone import x86 ## Change capstone from x86 to arm
from capstone import arm64
from capstone import arm
from capstone import mips
from elftools.elf.elffile import ELFFile
import ctypes
from BlockUtil import *
import bbinfoconfig as bbl


logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)
KindList = ["C2C", "C2D", "D2C", "D2D"]

TERMINALSTR_LIST = ['leave', 'hlt', 'ud2']

jumpTableRange = list()
# jump table
jumpTable = dict()


# function name => function addr
func_address = dict()
# basic block list
# basic block addr => basic block object
bb_list = dict()

blk_list = set()

# sometimes, function has jump
# func list
# function addr => function object
func_list = dict()
BB_2_FUNCS = dict()

fixup2Target = dict()

plt_start = 0
plt_end = 0

# .got.plt section address
GOT_PLT_ADDR = 0x0
TEXT_RANGE = (0, 0)

# if the executable is 32 bit or 64 bit
ELF_CLASS = 64
ELF_LITTLE_ENDIAN = True

CURRENT_FUNC = 0x0



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

POST_ANA_NEW_INSTRS = 0
POST_ANA_NEW_FUNCS = 0
POST_ANA_CODE_EMBEDED_AS_DATA = 0
POST_ANA_JMPTBLS = 0

DISABLE_POST_AA = False

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

    logging.debug(getInstStr(lastinst))
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
            is not terminator instruction,last is %s, ter is %s" % (viradr, viradr + endadr - startadr,getInstStr(lastinst),getInstStr(terminatorinst)))

    # set blk type
    # blk.set_type(lastinst.groups, isIndirect(terminatorinst))
    if terminatorinst != None:
        blk.set_type(terminatorinst.groups, isIndirect(terminatorinst))
    else:
        blk.set_type(lastinst.groups, isIndirect(terminatorinst))

    if(bbl.BB_RET_FLAG == -1):
        blk.type_special_handle(terminatorinst)
    if blk.type == 0 and bbl.BB_CALL_FLAG in terminatorinst.groups:
        logging.debug("Set non-return function call at 0x%x" % terminatorinst.address)
        lastinst = terminatorinst
        blk.type = BlockType.NON_RETURN_CALL

    return (terminatorinst, lastinst)

def get_func_address(binary):
    func_address_t = dict()
    with open(binary, 'rb') as openFile:
        elffile = ELFFile(openFile)
        section = elffile.get_section_by_name('.symtab')
        if(section):
            for symbol in section.iter_symbols():
                func_address_t[symbol.name] = symbol.entry['st_value']
    return func_address_t
def mips_get_direct_calls(ins_list):
    targets_map = dict()
    for ins in ins_list:
        if ins.address in mips_galr_targets:
            target = mips_galr_targets[ins.address]
            logging.info(target)
            if target[0] != 0:
                targets_map[ins.address] = target[0]
            else:
                targets_map[ins.address] = func_address[target[1]]
                #TODO(ztt) need to change func name to address
    return targets_map

def getDirectCalledFunc(blk, instList):
    """
    get called function that in blk
    """
    called_func = dict()
    for ins in instList:
        if ins.id == 0:
            continue
        if bbl.BB_CALL_FLAG in ins.groups and isIndirect(ins) == False:
        #if x86.X86_GRP_CALL in ins.groups and isIndirect(ins) == False:
            # iter over the fixup that in the current basic block
            # get the called function reference
            for fixup in blk.parent.Fixups:
                # get the called function reference
                if fixup.VA >=ins.address and fixup.VA < ins.address + ins.size:
                    if inPltSection(fixup.refTo) == False and not isInRange(fixup.VA, [TEXT_RANGE]):
                        logging.error("[Called Function]: The called function 0x%x in instruction 0x%x not in plt or defined func!" \
                                % (fixup.refTo, ins.address))
                        logging.debug("find fixup is 0x%x" %fixup.VA)
                        logging.debug("0x%x:\t%s\t%s" %(ins.address, ins.mnemonic, ins.op_str))
                    else:
                        #called_func.append(fixup.refTo)
                        called_func[ins.address] = fixup.refTo
    if bbl.BB_ARCH == 'MIPS':
        # called_func_tmp = mips_evaluate_direct_calls(instList)
        called_func_tmp = mips_get_direct_calls(instList)
        for (key, v) in called_func_tmp.items():
            called_func[key] = v
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
        if bbl.BB_JUMP_FLAG in terminorInst.groups:
        #if x86.X86_GRP_JUMP in terminorInst.groups:
            logging.warning("Indirect instruction %s is not a jump table!" % (getInstStr(terminorInst)))
            logging.info("[Statistics result: tail-indirect call]: at basic block 0x%x" % blk.VA)
            INDIRECT_CALL_CNT += 1

        if blk.fall_through:
            if blk.end == curBB.offsetFromBase + curBB.size - curBB.padding:
                # successor_addr = curBB.VA + curBB.size - curBB.padding
                successor_addr = curBB.VA + curBB.size
            else:
                # successor_addr = blk.VA + blk.end - blk.start
                successor_addr = blk.VA + blk.end - blk.start + curBB.padding

            if successor_addr not in bb_list and successor_addr not in blk_list:
                logging.error("245:successor addr %x not in basic block list" % (successor_addr))
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
                    if bbl.BB_CALL_FLAG in lastInst.groups:
                    #if x86.X86_GRP_CALL in lastInst.groups:
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
               successor_addr = blk.VA + blk.end - blk.start + curBB.padding
           # check if it is a overlapping basic block
           # if the current basic block is fall throuth
           # and its successor is the begining of a function
           #if successor_addr in func_list:
           #    logging.info("[Statistics result: overlapping basic block]: at bb address 0x%x" % successor_addr)
           #    OVERLAP_FUNCS_CNT += 1
           if successor_addr not in bb_list and successor_addr not in blk_list:
               logging.error("291:successor addr %x not in basic block list" % (successor_addr))
               return None
           successors.append(successor_addr)

       else:
            #TODO(ztt) arm have no ret
            if lastInst != None and (bbl.BB_CALL_FLAG in lastInst.groups or bbl.BB_RET_FLAG in lastInst.groups or \
                (bbl.BB_RET_FLAG == - 1 and (archRelatedRet(lastInst) or armCheck(lastInst)))):
            #if lastInst != None and (x86.X86_GRP_CALL in lastInst.groups or x86.X86_GRP_RET in lastInst.groups):
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

    logging.info("[debug successors]: successor va is %x, refto is %x" % (successor_fixup.VA, successor_fixup.refTo))

    if blk.fall_through:
        logging.debug("Find fall through")
        if blk.end == blk.parent.offsetFromBase + blk.parent.size - blk.parent.padding:
            # successors.append(curBB.VA + curBB.size - blk.parent.padding)
            successors.append(curBB.VA + curBB.size)
        else:
            successors.append(blk.VA + blk.end - blk.start + blk.parent.padding)

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
            if bbl.BB_CALL_FLAG in terminator_inst.groups:
            #if x86.X86_GRP_CALL in terminator_inst.groups:
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

def load_data(binary_content, address, size):
    readed_data = None
    if not isInRange(address, LOAD_RANGE):
        return None

    idx = 0
    for (start, end) in LOAD_RANGE:
        if address >= start and address < end:
            base = LOAD_OFFSET[idx]
            file_offset = base + address - start
            readed_data = binary_content[file_offset: file_offset + size]
            break
        idx += 1
    return readed_data

def get_stack_offset(inst, op):
    if op.type == bbl.BB_OP_MEM and \
        op.value.mem.base != 0 and \
            inst.reg_name(op.value.mem.base) in {'sp', 'fp'} and \
                op.value.mem.disp != 0:
        if inst.reg_name(op.value.mem.base) == 'sp':
            shift_v = 12
        else:
            shift_v = 18
        mem_offset = op.value.mem.disp + (1 << shift_v)
        return mem_offset
    return None

def mips_evaluate_direct_calls(ins_list, content):
    '''
    perform value evaluation inside basic block

        @args: instruction list
        @ret: dicts of inst-> callee
    '''
    callees = dict()
    content_lists = dict()
    mips_load_size = {mips.MIPS_INS_LB: 1,
                    mips.MIPS_INS_LW: 4,
                    mips.MIPS_INS_LD: 8
                }
    mips_store_size = {mips.MIPS_INS_SB: 1,
                       mips.MIPS_INS_SW: 4,
                        mips.MIPS_INS_SD: 8}
    for ins in ins_list:
        if ins.id in mips_load_size:
            reg = ins.operands[0].reg
            if reg in content_lists:
                del content_lists[reg]
            if ins.address in fixup2Target:
                loaded_bytes = load_data(content, fixup2Target[ins.address], mips_load_size[ins.id])
                if loaded_bytes != None:
                    v = int.from_bytes(loaded_bytes, byteorder = 'little')
                    content_lists[reg] = v
                    #logging.info("[mips evaluation]: %s, reg %s -> %x" % (getInstStr(ins), ins.reg_name(reg), v))
            else:
                offset = get_stack_offset(ins, ins.operands[1])
                if offset is not None and offset in content_lists:
                    content_lists[reg] = content_lists[offset]

        elif ins.id in mips_store_size:
            reg = ins.operands[0].reg
            if reg not in content_lists:
                continue

            offset = get_stack_offset(ins, ins.operands[1])
            if offset is not None and offset in content_lists:
                content_lists[offset] = content_lists[reg]
        elif ins.id == mips.MIPS_INS_MOVE:
            dst_reg = ins.operands[0].reg
            src_reg = ins.operands[1].reg
            if src_reg in content_lists:
                content_lists[dst_reg] = content_lists[src_reg]
        elif ins.id == mips.MIPS_INS_JALR:
            reg = ins.operands[0].reg
            if reg in content_lists:
                v = content_lists[reg]
                if isInRange(v, LOAD_RANGE):
                #logging.info("[mips evaluation]: get target of %s: 0x%x" % (getInstStr(ins), v))
                    callees[ins.address] = v
    return callees

def getInstsBeginFromAddr(addr, inst_list):
    result = list()
    added = False
    logging.info("The begin Addr is 0x%x" %addr)
    for inst in inst_list:
        logging.info("Now instruction is from 0x%x to 0x%x" %(inst.address,inst.size))
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
    def find_bbl_include(addr):
        for bb in bb_list.values():
            if addr >= bb.VA and addr < bb.VA + bb.size:
                return bb
        return None

    queueList = list()
    queueList.append((currentBB,currentBB.VA))
    visited = set()
    cur_bb_num = 0

    # tainted registers from jump table fixup
    # we assume the relationship between jmptbl fixup to the indirect jump
    # only popluates between regs
    queue_tainted_regs = list()
    queue_tainted_regs.append(set())

    first = True
    while len(queueList) > 0:
        (curBB,addr) = queueList.pop(0)
        cur_tainted_regs = queue_tainted_regs.pop(0)
        logging.debug("current taint regs is {}".format(cur_tainted_regs))

        if curBB == None:
            continue
        if addr in visited:
            continue
        cur_bb_num += 1

        logging.debug("current bb is 0x%x - 0x%x" % (addr, curBB.VA + curBB.size - curBB.padding))
        visited.add(addr)
        startAdr = curBB.offsetFromBase
        endAdr = curBB.size + startAdr - curBB.padding
        virAdr = curBB.VA
        tmp_blk = Blk(virAdr, startAdr, endAdr, curBB, curBB.hasFallThrough)

        tmp_inslist = disassembleBB(tmp_blk, binary, ELF_CLASS)
        inslist = list()
        for inst in tmp_inslist:
            if(inst.address >= addr):
                inslist.append(inst)


        (terminorInst, _,) = getTerminator(tmp_blk, inslist)
        if first:
            inslist = getInstsBeginFromAddr(fi, inslist)
            # the jmptbl is in indirect jump instruction
            if len(inslist) > 0 and isJumpTable(inslist[0]):
                return curBB


        updated_tainted_regs = taintRegsCrossBB(inslist, cur_tainted_regs, first)
        first = False

        if len(updated_tainted_regs) == 0:
            logging.warning("don't have taint regs!")
            continue


        if tmp_blk.type == BlockType.INDIRECT_BRANCH:
            logging.debug("BlockType.INDIRECT_BRANCH")
            if isJumpTable(terminorInst):
                if instReadRegsIsTaint(terminorInst, updated_tainted_regs):
                    return curBB
                elif curBB.VA in jumpTable:
                    logging.debug("Jumptable Now")
                    for successor_addr in jumpTable[curBB.VA]:
                        if successor_addr in bb_list: # TODO(ztt): handle this
                            logging.info("add successor 0x%x of jump table 0x%x" % (successor_addr, curBB.VA))

                            queueList.append((bb_list[successor_addr],successor_addr))
                            suc_bb = bb_list[successor_addr]
                            logging.debug("Add successor 0x%x - 0x%x" %(successor_addr,suc_bb.VA + suc_bb.size - suc_bb.padding))
                            queue_tainted_regs.append(updated_tainted_regs.copy())
            else:
                continue

        if tmp_blk.type == BlockType.FALL_THROUGH:
            successor_addr = curBB.VA + curBB.size
            logging.debug("BlockType.FALL_THROUGH")
            if successor_addr not in bb_list:
                suc_bb = find_bbl_include(successor_addr)
                if suc_bb != None:
                    logging.debug("Add successor 0x%x - 0x%x" %(successor_addr,suc_bb.VA + suc_bb.size - suc_bb.padding))
                    queueList.append((suc_bb,successor_addr))
                    queue_tainted_regs.append(updated_tainted_regs.copy())
                else:
                    logging.error("472:successor addr %x not in basic block list" % (successor_addr))
            else:
                queueList.append((bb_list[successor_addr],successor_addr))
                suc_bb = bb_list[successor_addr]
                logging.debug("Add successor 0x%x - 0x%x" %(successor_addr,suc_bb.VA + suc_bb.size - suc_bb.padding))
                queue_tainted_regs.append(updated_tainted_regs.copy())
            continue

        if tmp_blk.is_direct_jump():
            logging.debug("is_direct_jump")
            successors = getSuccessorsFromDirectInst(tmp_blk, terminorInst)
            if successors != None:
                for successor_addr in successors:
                    if successor_addr not in bb_list:
                        logging.debug("Strange successor is 0x%x" %successor_addr)
                        suc_bb = find_bbl_include(successor_addr)
                        if suc_bb != None:
                            logging.debug("Add successor 0x%x - 0x%x" %(successor_addr,suc_bb.VA + suc_bb.size - suc_bb.padding))
                            queueList.append((suc_bb,successor_addr))
                            queue_tainted_regs.append(updated_tainted_regs.copy())
                    else:
                        logging.debug("Orignal is 0x%x" %successor_addr)
                        queueList.append((bb_list[successor_addr],successor_addr))
                        suc_bb = bb_list[successor_addr]
                        logging.debug("Add successor 0x%x - 0x%x" %(successor_addr,suc_bb.VA + suc_bb.size - suc_bb.padding))
                        queue_tainted_regs.append(updated_tainted_regs.copy())

        elif tmp_blk.fall_through:
            successor_addr = curBB.VA + curBB.size
            logging.debug("tmp_blk.fall_through")
            if successor_addr not in bb_list:
                suc_bb = find_bbl_include(successor_addr)
                if suc_bb != None:
                    logging.debug("Add successor 0x%x - 0x%x" %(successor_addr,suc_bb.VA + suc_bb.size - suc_bb.padding))
                    queueList.append((suc_bb,successor_addr))
                    queue_tainted_regs.append(updated_tainted_regs.copy())
                else:
                    logging.error("494:successor addr %x not in basic block list" % (successor_addr))
            else:
                queueList.append((bb_list[successor_addr],successor_addr))
                suc_bb = bb_list[successor_addr]
                logging.debug("Add successor 0x%x - 0x%x" %(successor_addr,suc_bb.VA + suc_bb.size - suc_bb.padding))
                queue_tainted_regs.append(updated_tainted_regs.copy())
        elif tmp_blk.is_call == False and tmp_blk.type == BlockType.RET:
            logging.warning("The basic block %x-%x end up with ret!. its instruction is %s" %
                    (curBB.VA, curBB.VA + curBB.size - curBB.padding, getInstStr(terminorInst)))
            if isJumpTable(terminorInst) and instReadRegsIsTaint(terminorInst, updated_tainted_regs):
                    return curBB

    return None


# TODO(binpang). Implement symbolic to read the jump tables.
def tryReadTableEntriesARM(target, numEntries, szEntry, binary,type,instr_addr,padding,next_instr_addr = 0x0):

    def get_unpackType(sz):
        unpackType = ''
        if sz == 4:
            unpackType = 'I'
        elif sz == 8:
            unpackType = 'Q'
        elif sz == 2:
            unpackType = 'H'
        elif sz == 1:
            unpackType = 'B'
        else:
            logging.warning("The entry size is %d, I can't handle" % (sz))
        return unpackType
    def get_shift_bits(sz):
        shift_bits = 0
        if sz == 4 or sz == 3:
            shift_bits = 2
        elif sz == 8:
            shift_bits = 3
        elif sz == 2:
            shift_bits = 2
        elif sz == 1:
            shift_bits = 2
        else:
            logging.warning("The entry size is %d, I can't handle" % (sz))
        return shift_bits
    def sign_extend(value, bits):
        sign_bit = 1 << (bits - 1)
        return (value & (sign_bit - 1)) - (value & sign_bit)
    successors = list()
    binaryFile = open(binary, 'rb')
    content = binaryFile.read()
    elf = ELFFile(binaryFile)
    entryPoint = elf.header['e_entry']
    base = elf.get_segment(2)['p_vaddr']
    if entryPoint <= 0 :
        base = 0
    offset = target - base
    logging.info("target is 0x%x,base is 0x%x,offset is 0x%x,szEntry is 0x%x,instr_addr is 0x%x,next_instr_addr is 0x%x,numEntry is %d" %(target,base,offset,szEntry,instr_addr,next_instr_addr,numEntries))

    endian = '>'
    if 'LSB' in elf.header['e_ident']['EI_DATA']:
        endian = '<'
    if szEntry == 3:
        szEntry = 4
    unpackType = get_unpackType(szEntry)
    shift_bits = get_shift_bits(szEntry)
    unpackStr = endian + unpackType

    def getEntries(base_addr,shift=0,added = 0):
        successors = list()
        offsetlist = list()
        #logging.debug("New try 0x%x" % base_addr)
        for idx in range(numEntries):
            addrEnd = offset + (idx+1) * szEntry + added * szEntry
            addrSt = offset + idx * szEntry + added * szEntry

            entry = content[addrSt:addrEnd]
            entryContent = struct.unpack(unpackStr, entry)
            entryAddr = (sign_extend(entryContent[0], szEntry * 8) << shift)

            offsetlist.append(entryAddr)
            entryAddr += base_addr
            successors.append(entryAddr)
        return successors


    def inBBStarts(succs):
        for succ in succs:
            if succ not in bb_list:
                return False
        return True

    # first try, read the raw data
    succ1 = getEntries(0)
    if inBBStarts(succ1):
        logging.debug("Pattern1")
        return succ1

     # for debug.
    for succ in succ1:
        if target == 0x6e7100:
            logging.info("Aha?? 0x%x Not in bb_list" % succ)

    # second try, read the raw data + table base address
    succ2 = getEntries(target)
    if inBBStarts(succ2):
        logging.debug("Pattern2")
        return succ2

    # third try, read the raw data + next instr address
    succ3 = getEntries(next_instr_addr)
    if inBBStarts(succ3):
        logging.debug("Pattern3")
        return succ3
    # fourth try
    succ4 = getEntries(next_instr_addr, shift_bits)
    if inBBStarts(succ4):
        logging.debug("Pattern4")
        return succ4


    # tmp = unpackStr
    # tmp1 = szEntry
    # szEntry = 1
    # unpackStr = endian + 'B'
    # succX = getEntries(next_instr_addr, shift_bits)
    # if inBBStarts(succX):
    #     logging.info("PatternX")
    #     return succX
    # unpackStr = tmp
    # szEntry = tmp1

    # for suc in succX:
    #     if suc not in bb_list:
    #         print("suc is 0x%x" % suc)
    #     else:
    #         print("succeed suc is 0x%x" % suc)

    #fifth try
    # ztt add from table base added at least 1 * tablesize and don't need add base addr
    succ5 = getEntries(0,0,1)
    if inBBStarts(succ5):
        logging.debug("Pattern5")
        return succ5

    if bbl.BB_RET_FLAG != -1:
        return list()
    succ6 = list()
    for idx in range(numEntries):
        addrSt = next_instr_addr - base + idx * szEntry
        addrEnd = next_instr_addr - base + (idx+1) * szEntry
        entry = content[addrSt:addrEnd]
        entryContent = struct.unpack(unpackStr, entry)
        entryAddr = (sign_extend(entryContent[0], szEntry * 8))
        succ6.append(entryAddr)
        #logging.debug("0x%x" %entryAddr)
    if inBBStarts(succ6):
        logging.debug("Pattern6")
        return succ6

    succ6_ = list()
    for idx in range(numEntries):
        addrSt = next_instr_addr - base + idx * szEntry
        addrEnd = next_instr_addr - base + (idx+1) * szEntry
        entry = content[addrSt:addrEnd]
        entryContent = struct.unpack(unpackStr, entry)
        entryAddr = (sign_extend(entryContent[0], szEntry * 8))
        succ6_.append(entryAddr - 1)
        # logging.debug("0x%x" %entryAddr)
    if inBBStarts(succ6_):
        logging.debug("Pattern6_")
        return succ6_

    succ6s = list()
    for idx in range(numEntries):
        addrSt = next_instr_addr - base + idx * szEntry
        addrEnd = next_instr_addr - base + (idx+1) * szEntry
        entry = content[addrSt:addrEnd]
        entryContent = struct.unpack(unpackStr, entry)
        entryAddr = (sign_extend(entryContent[0], szEntry * 8))
        succ6s.append(entryAddr - 1 + next_instr_addr)
        # logging.debug("0x%x" %entryAddr)
    if inBBStarts(succ6s):
        logging.debug("Pattern6s")
        return succ6s

    succ7 = list()
    for idx in range(numEntries):
        addrSt = next_instr_addr - base + idx * szEntry
        addrEnd = next_instr_addr - base + (idx+1) * szEntry
        entry = content[addrSt:addrEnd]
        entryContent = struct.unpack(unpackStr, entry)
        entryAddr = (sign_extend(entryContent[0], szEntry * 8)) + next_instr_addr
        succ7.append(entryAddr)
    if inBBStarts(succ7):
        logging.debug("Pattern7")
        return succ7

    now_inst = content[offset - szEntry:offset]
    mem_flag = False
    pc_flag = False
    md = Cs(bbl.BB_CS_MODE_1, bbl.BB_CS_MODE_2 + bbl.BB_ENDIAN)
    md.detail = True

    if(type & (1 << 6) == 64):
        md.mode = bbl.BB_CS_MODE_3
    else:
        md.mode = bbl.BB_CS_MODE_2

    for insn in md.disasm(now_inst, offset - szEntry):
        if len(insn.operands) > 0:
            #print("\tNumber of operands: %u" %len(insn.operands))
            for i in insn.operands:
                if i.type == bbl.BB_OP_MEM:
                    #print("\t\toperands[%u].type: MEM" %c)
                    if i.value.mem.index != 0:
                        mem_flag = True
                if i.type == bbl.BB_OP_REG and insn.reg_name(i.value.reg) == "pc":
                    pc_flag = True
    if(pc_flag and not mem_flag):
        successors = list()
        for idx in range(numEntries):
            entryAddr = target + idx * szEntry
            successors.append(entryAddr)
        if inBBStarts(successors):
            logging.debug("Pattern8")
            return successors
    successors = list()
    for idx in range(0,numEntries):
        entryAddr = target + idx * szEntry
        successors.append(entryAddr)
    if inBBStarts(successors):
        logging.debug("Pattern8+")
        return successors
    now_inst = content[instr_addr - base:next_instr_addr -base]
    logging.debug(now_inst)
    for insn in md.disasm(now_inst,instr_addr):
        logging.debug("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))
        flag = False
        if insn.mnemonic == "tbb":
            flag = True
            szEntry = 1
            unpackType = get_unpackType(szEntry)
            shift_bits = get_shift_bits(szEntry)
            unpackStr = endian + unpackType
        if insn.mnemonic == "tbh":
            flag = True
            for i in insn.operands:
                if i.type == bbl.BB_OP_MEM and i.shift.type != bbl.BB_OP_SFT:
                    szEntry = 1 << (i.shift.value)
                    unpackType = get_unpackType(szEntry)
                    shift_bits = get_shift_bits(szEntry)
                    unpackStr = endian + unpackType
        if flag:
            successors = list()
            for idx in range(numEntries):
                addrSt = target - base + idx * szEntry
                addrEnd = target - base + (idx + 1) * szEntry
                entry = content[addrSt:addrEnd]
                entryContent = struct.unpack(unpackStr, entry)
                entryAddr = (entryContent[0]) * 2 + next_instr_addr - padding
                successors.append(entryAddr)
                logging.info("tb* successor is 0x%x, entryContent is 0x%x, base is 0x%x" %(entryAddr,entryContent[0],next_instr_addr - padding))
                if entryAddr not in bb_list:
                    logging.info("tb* successor not in bb_list")
            if inBBStarts(successors):
                logging.debug("Pattern9")
                return successors
            elif target == 0x0:
                successors = list()
                successors.append(0x0)
                return successors

    return list()

def readJumpTableEntriesMips(table_base, entry_sz, size, fixups):
    targets = list()
    for i in range(size):
        cur_fix = table_base + i * entry_sz
        if cur_fix not in fixups:
            logging.error("Table fixup 0x%x is not found!" % cur_fix)
        targets.append(fixups[cur_fix])
    return targets

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
        logging.info(entryContent)
        entryAddr = entryContent[0]
        # for 64-bit executable, if the jump table entry is 4 bits
        # its address computation is "table_base + entryContent"
        # FIXME. Here I only consider the executable is 64-bit for now.
        if szEntry == 4 and ELF_CLASS == 64:
            entryAddr = target + ctypes.c_int32(entryAddr).value

        # for 32-bit, the jump table targets may be added by the base address
        elif ELF_CLASS == 32 and added_base != 0:
            entryAddr = added_base + ctypes.c_int32(entryAddr).value

        elif not isInRange(entryAddr, LOAD_RANGE):
            entryAddr = target + ctypes.c_int32(entryAddr).value

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
    # T : essInfo need to fix up with arm
    global INDIRECT_JMP_CNT
    global INDIRECT_CNT
    global jumpTable
    last_num = 0
    jumpTableCnt = dict()
    # jumpTableDebug = dict()
    global fixup2Target

    T1 = dict()
    if not essInfo.hasFixupsInText():
        return dict()

    fixup2Size = dict()

    if essInfo.getFixupsRodata() is not None:
        for fi in essInfo.getFixupsRodata():
            if fi.numJTEntries > 0 and fi.jtEntrySz != 0:
                fixup2Size[fi.VA] = fi.jtEntrySz
            else:
                fixup2Size[fi.VA] = fi.derefSz
            fixup2Target[fi.VA] = fi.refTo

    if essInfo.getFixupsText() is not None:
        for fi in essInfo.getFixupsText():
            if fi.numJTEntries > 0 and fi.jtEntrySz != 0:
                fixup2Size[fi.VA] = fi.jtEntrySz
            else:
                fixup2Size[fi.VA] = fi.derefSz
            fixup2Target[fi.VA] = fi.refTo

        for fi in essInfo.getFixupsText():
            UNSOLVED_JBL_FIXUPS.add(fi)

    jmpcnt = 0
    ## Reach a fixpoint.
    ## until no new jump table solved.
    while last_num != len(UNSOLVED_JBL_FIXUPS):
        last_num = len(UNSOLVED_JBL_FIXUPS)
        saved_jbl_fixups = UNSOLVED_JBL_FIXUPS.copy()
        for fi in saved_jbl_fixups:
            if fi.numJTEntries > 0:
                jmpcnt += 1
                logging.info("fi%d: 0x%x, entry number is %d, its parent is 0x%x" % (jmpcnt,fi.VA, fi.numJTEntries, fi.parent.VA))
                # TODO(ztt). Implement the arm of findIndirectBB
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

                logging.info("Jump table base is 0x%x" %table_base)

                if bbl.BB_ARCH not in {'x86', 'x64'} and \
                    (jumpTableCnt.get(table_base,-1) != -1 and table_base != 0x0 and table_base != 0x8):
                    logging.info("Duplicate: fi 0x%x, entry number is %d, its parent is 0x%x ,its refTo is 0x%x" % (fi.VA, fi.numJTEntries, fi.parent.VA,table_base))
                    # jumpTableCnt[table_base] += 1
                    continue
                indirectBB = findIndirectBB(fi.VA, fi.parent, binary)
                if indirectBB == None:
                    logging.warning("current jump table fixup %x can't resolve the indirect jump basic block" % (fi.VA))
                    continue

                '''
                gcc aarch64:
                    adrp    x1, .L7
                    add     x1, x1, :lo12:.L7
                    ldrb    w0, [x1,w0,uxtw]
                    adr     x1, .Lrtx7
                    add     x0, x1, w0, sxtb #2
                    br      x0
                    .Lrtx7:

                llvm aarch64 pic:
                    adrp    x9, .LJTI1_0
                    add     x9, x9, :lo12:.LJTI1_0
                    ldrsw   x8, [x9, x8, lsl #2]
                    add     x8, x8, x9
                    br      x8

                llvm aarch64 non-pic:
                    adrp    x9, .LJTI1_0
                    add     x9, x9, :lo12:.LJTI1_0
                    ldrsw   x8, [x9, x8, lsl #2]
                    br      x8
                '''
                tbl_size = fixup2Size[fi.VA]
                if table_base not in fixup2Size:
                    logging.error("Table base 0x%x not in fixups, please check!" % table_base)
                else:
                    tbl_size = fixup2Size[table_base]
                logging.info("entry size is 0x%x" % (fi.jtEntrySz))

                if bbl.BB_ARCH == 'ARM' or bbl.BB_ARCH == 'AArch64':
                    successors = tryReadTableEntriesARM(table_base, fi.numJTEntries, tbl_size, binary,indirectBB.type,fi.VA,indirectBB.padding,indirectBB.VA + indirectBB.size)
                elif bbl.BB_ARCH == 'MIPS':
                    successors = readJumpTableEntriesMips(table_base, fi.jtEntrySz, fi.numJTEntries, fixup2Target)
                else:
                    successors = readTableEntries(table_base, fi.numJTEntries, tbl_size, binary, entry_added_base)

                if len(successors) == 0:
                    # FIXME: if the length of successors is null, please check the jmptbl manually.
                    logging.error("Can't find the tbl entries of 0x%x" % (fi.VA))
                    continue
                if len(successors) == 1 and successors[0] == 0x0:
                    logging.warning("The tbl entries of 0x%x may have visited" % (fi.VA))
                    continue
                # successors = readTableEntries(table_base, fi.numJTEntries, tbl_size, binary, entry_added_base)
                # check the successor's address
                for (idx, suc) in enumerate(successors):
                    if isInRange(suc, [TEXT_RANGE]) == False:
                        logging.error("successor address 0x%x is not in .text section!" % (suc))

                    logging.info("JMPTBL entry #%d, 0x%x" % (idx, suc))

                # jumpTableDebug[fi.VA - 0x403528] = table_base
                jumpTableCnt[table_base] = 1
                # log the jump table information
                logging.info("[Statistics Result: JMP TBL]: find jmp table at address 0x%x" % indirectBB.VA)
                INDIRECT_JMP_CNT += 1
                #logging.info("JMPTBL#%d: fixup addr 0x%x, Table addr %x, table size %d, entry size %d, indirectBB.va 0x%x" %
                        #(INDIRECT_JMP_CNT, fi.VA, table_base, fi.numJTEntries, tbl_size, indirectBB.VA))
                # end log the jump table information
                #logging.info("Now fixup address is 0x%x" %fi.VA)
                jumpTable[indirectBB.VA] = successors
                logging.debug("Add jumptable 0x%x" %indirectBB.VA)
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
    # tmp_f = open(binary, 'rb')
    # b_content = tmp_f.read()
    # tmp_f.close()
    post_ana_added_funcs = set()


    # handle gaps
    if ELF_ARCH in {'x86', 'x64'} and not DISABLE_POST_AA:
        handleGapsFallThrough(bbList, binary)

    # update bb_list
    global FIRST_BB_VA, FIRST_BB_OFFSET_FROM_BASE
    global BB_2_FUNCS
    global POST_ANA_NEW_FUNCS

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
                logging.debug("[Fixing]: bb va 0x%x -> tmp va 0x%x" % (bb.VA, tmp_blk.VA))
                if bb.VA != tmp_blk.VA:
                    bb.offsetFromBase += tmp_blk.VA - bb.VA
                    bb.VA = tmp_blk.VA
                    logging.info("[Fixed]: basicblock#%d: %x to %x" % (bbidx, bb.VA, bb.VA+bb.size))
            # split the basic block
            splited_bbs = split_block(bb, binary, split, ELF_CLASS,ELF_ARCH)
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
                # inst_idx = 0
                called_func_list = getDirectCalledFunc(blk, inst_list)
                for call in called_func_list.values():
                    #logging.info(call)
                    if call not in func_list and isInRange(call, [TEXT_RANGE]) and call not in post_ana_added_funcs:
                        post_ana_added_funcs.add(call)
                        logging.info("[Post analysis]: found new function start 0x%x" % call)

                for inst in inst_list:
                    logging.debug("[inst]: 0x%x" % inst.address)
                    addedInst = addedBB.instructions.add()
                    addedInst.va = inst.address
                    addedInst.size = inst.size
                    try:
                        if bbl.BB_CALL_FLAG in inst.groups:
                        #if x86.X86_GRP_CALL in inst.groups:
                            if isIndirect(inst) or addedInst.va in called_func_list:
                                addedInst.call_type = 2
                            else:
                                addedInst.call_type = 3

                        if inst.address in called_func_list:
                            target = called_func_list[addedInst.va]
                            if isinstance(target, int):
                                addedInst.callee = target
                            else:
                                addedInst.callee_name = target

                        #TODO(ztt),non-return instruction
                        #if inst.id == arm64.ARM64_INS_UDF:
                        if bbl.BB_CALL_FLAG == x86.X86_GRP_CALL:
                            if inst.id == x86.X86_INS_UD2:
                                addedBB.terminate = True
                                logging.info("basic block 0x%x contains ud2 instruction!" % addedBB.va)
                    except Exception as e:
                        logging.error("Error in added Basic block to protobuf %s" % e)
                        continue

                non_ret = False
                # check if the called function is non-returning function
                if len(inst_list) > 0:

                    last_inst = get_last_instr(inst_list)
                    is_indirect = (isIndirect(last_inst) and last_inst not in called_func_list)

                    if not invalidInst:
                        blk.set_type(last_inst.groups, is_indirect)

                    if(bbl.BB_RET_FLAG == -1):
                        blk.type_special_handle(last_inst)
                    addedBB.type = blk.type
                    if last_inst.id != 0 and bbl.BB_CALL_FLAG in last_inst.groups and not blk.fall_through:
                    #if last_inst.id != 0 and x86.X86_GRP_CALL in last_inst.groups and not blk.fall_through:
                        logging.info("[Non-return]: Instruction %s call a non-return function!" %
                                                                    (getInstStr(last_inst)))
                        non_ret = True


                # get direct called function
                # called_func_list = getDirectCalledFunc(blk, binary, inst_list)
                for (_, called_func) in called_func_list.items():
                    if not isinstance(called_func, int):
                        continue
                    added_called_func = addedFunc.calledFunction.add()
                    added_called_func.va = called_func
                    if non_ret and called_func not in NONRET_SET and inPltSection(called_func):
                        logging.info("[Statistics result: non-ret]: function 0x%x is non-return" % (called_func))
                        NONRET_CNT += 1
                        NONRET_SET.add(called_func)

                ## If the basic block's terminator is the indirect jump and it is jump table
                if blk.end == bb_end_adr and bb.VA in jumpTable:
                    successors = jumpTable[bb.VA]
                    logging.info("The terminator of basic block %x is jump table!" % (addedBB.va))
                    logging.info("The successor of basic block %x is %s" %
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

    if not DISABLE_POST_AA:
        POST_ANA_NEW_FUNCS = len(post_ana_added_funcs)
        for func_va in post_ana_added_funcs:
            addedFunc = pbModule.fuc.add()
            addedFunc.va = func_va
            addedFunc.type = 1 # dummy one.

    if(bbl.BB_RET_FLAG != -1) and not DISABLE_POST_AA:
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
            child = bb.child.add()
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
                    child = prevBB.child.add()
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
            if overlapping and not DISABLE_POST_AA:
                logging.info("[Statistics Result: Overlap Ins]: find overlapping instruction at 0x%x" % overlapping_target)
                OVERLAP_INS_CNT += 1
                if len(bb.instructions) > 1:
                    tmp_sz = bb.instructions[0].va + bb.instructions[0].size - overlapping_target
                    if tmp_sz > 0:
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
                        logging.info("overlapping instruction addr 0x%x, size %d" %
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
    global POST_ANA_NEW_INSTRS
    global POST_ANA_CODE_EMBEDED_AS_DATA

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

                new_instrs = 0
                for bb in result_bbl_list:
                    new_instrs += len(bb.ins_list)

                POST_ANA_NEW_INSTRS += new_instrs
                POST_ANA_CODE_EMBEDED_AS_DATA += 1

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
    global POST_ANA_CODE_EMBEDED_AS_DATA
    global POST_ANA_NEW_INSTRS
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
            if len(ins_list) == 0:
                continue

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

                    POST_ANA_NEW_INSTRS += len(ins_list)
                    POST_ANA_CODE_EMBEDED_AS_DATA += 1

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

                    POST_ANA_NEW_INSTRS += len(ins_list)
                    POST_ANA_CODE_EMBEDED_AS_DATA += 1

                    GAPS_BB_ADD_ELEMENT[bb.VA] = blk

            # case 2:
            # The last instruction is a fall through instruction:
            if not case_one and (last_inst.address + last_inst.size == bb_va_end_adr) and \
                        isFallThrough(last_inst):

                gap_start_off_from_base = bb_start_adr + gap_start - bb.VA - bb.padding
                gap_end_off_from_base = gap_start_off_from_base + gap_end - gap_start - bb.padding
                result_bbl_list = recursiveDisassembleInRange(binary, gap_start - bb.padding, \
                                gap_start_off_from_base, gap_end_off_from_base, \
                                0, ELF_CLASS, bb.parent)
                new_instrs = 0
                for bb in result_bbl_list:
                    new_instrs += len(bb.ins_list)

                POST_ANA_NEW_INSTRS += new_instrs
                POST_ANA_CODE_EMBEDED_AS_DATA += 1

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
    logging.info("[Summary]: Non-returning function is %d" % NONRET_CNT)
    logging.info("[Summary]: Multi-entry function is %d" % MULT_ENT_CNT)
    logging.info("[Summary]: overlapping functions is %d" % OVERLAP_FUNCS_CNT)
    logging.info("[Summary]: tail call count is is %d" % TAIL_CALL_CNT)
    logging.info("[Summary]: Newly founded instructions by post analysis is %d" % POST_ANA_NEW_INSTRS)
    logging.info("[Summary]: Newly founded instructions encoded as data by post analysis is %d" % POST_ANA_CODE_EMBEDED_AS_DATA)
    logging.info("[Summary]: Newly founded overlapping instructions by post analysis is %d" % OVERLAP_INS_CNT)
    logging.info("[Summary]: Newly founded functions by post analysis is %d" % POST_ANA_NEW_FUNCS)
    logging.info("[Summary]: Newly founded jump tables by post analysis is %d" % POST_ANA_JMPTBLS)

def heuristicSearchingJmptbl(essInfo):
    def toSigned32(n):
        n = n & 0xffffffff
        return n | (-(n & 0x80000000))

    global POST_ANA_JMPTBLS
    jmptbl_min_size = 2
    jmptbls = []
    jmptbls.append([])

    if essInfo.getFixupsText() is None or \
        essInfo.getFixupsRodata() is None:
        return

    # collect handwritten regions
    handwritten_ranges = list()
    start_va = 0
    end_va = 0
    for bb in essInfo.constructInfo.BasicBlockLayout:
        if bb.assembleType == 2:
            if end_va != bb.VA:
                start_va = bb.VA
                if end_va != 0:
                    handwritten_ranges.append((start_va, end_va))
                end_va = start_va
            end_va += bb.size

    handwritten_ranges.append((start_va, end_va))

    def _is_in_handwritten_ranges(fi):
        if isInRange(fi.refTo, handwritten_ranges) or \
            isInRange(toSigned32(fi.refTo) + fi.VA, handwritten_ranges):
            return True
        return False

    # first step: search continuous fixups point into text region
    prev_size = 0
    next_addr = 0
    for fi in essInfo.getFixupsRodata():
        if _is_in_handwritten_ranges(fi):
            if not (prev_size == 0 or prev_size == fi.derefSz) or \
                not (next_addr == 0 or next_addr == fi.VA) and len(jmptbls[-1]) > 0:
                jmptbls.append([])
            jmptbls[-1].append(fi)
            prev_size = fi.derefSz
            next_addr = fi.VA + fi.derefSz
        else:
            if len(jmptbls[-1]) > 0:
                jmptbls.append([])
            prev_size = 0
            next_addr = 0

    next_addr = 0
    for fi in essInfo.getFixupsText():
        if _is_in_handwritten_ranges(fi):
            if not (prev_size == 0 or prev_size == fi.derefSz) or \
                not (next_addr == 0 or next_addr == fi.VA) and len(jmptbls[-1]) > 0:
                jmptbls.append([])
            jmptbls[-1].append(fi)
            prev_size = fi.derefSz
            next_addr = fi.VA + fi.derefSz
        else:
            if len(jmptbls[-1]) > 0:
                jmptbls.append([])
            prev_size = 0
            next_addr = 0

    jmptbls = [tbl for tbl in jmptbls if len(tbl) >= jmptbl_min_size]
    jmptbl_entries = set()
    for jmptbl in jmptbls:
        [jmptbl_entries.add(entry.VA) for entry in jmptbl]

    # split jmptbls
    potential_fis = list()
    for fi in essInfo.getFixupsText():
        if fi.refTo in jmptbl_entries:
            logging.info("potential fi is 0x%x, to 0x%x" % (fi.VA, fi.refTo))
            potential_fis.append(fi)
        elif bbl.BB_ARCH == 'x86' and (not fi.isRela and (fi.refTo + fi.VA - 2) in jmptbl_entries):
            logging.info("potential fi is 0x%x, to 0x%x" % (fi.VA, fi.refTo + fi.VA - 2))
            fi.refTo = fi.refTo + fi.VA - 2
            potential_fis.append(fi)


    for fi in potential_fis:
        idx = 0
        fi_va = fi.refTo
        for tbl in jmptbls:
            start_va = tbl[0].VA
            end_va = tbl[0].VA + tbl[0].derefSz * len(tbl)
            if fi_va >= start_va and fi_va < end_va:
                break
            idx += 1

        if idx < len(jmptbls):
            jmptbl = jmptbls[idx]
            del jmptbls[idx]
            pre_jmptbls = list()
            post_jmptbls = list()
            for entry in jmptbl:
                if entry.VA < fi_va:
                    pre_jmptbls.append(entry)
                else:
                    post_jmptbls.append(entry)

            if len(pre_jmptbls) >= jmptbl_min_size:
                jmptbls.append(pre_jmptbls)
            if len(post_jmptbls) >= jmptbl_min_size:
                jmptbls.append(post_jmptbls)

    for fi in potential_fis:
        fi_va = fi.refTo
        for tbl in jmptbls:
            if fi_va == tbl[0].VA:
                fi.jtEntrySz = tbl[0].derefSz
                fi.numJTEntries = len(tbl)
                POST_ANA_JMPTBLS += 1
                logging.info("Found jump table at 0x%x: its jt entries is 0x%x" % \
                    (fi_va, fi.numJTEntries))

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-b", "--binary", dest = "binary", action="store", type="string", help="input elf binary path", default=None)
    parser.add_option("-d", "--disable-postaa", dest = "disable_postaa", action = "store_true", default = False, help = "Disable post analysis")
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

    ELF_CLASS = readElfClass(options.binary)
    ELF_ARCH = readElfArch(options.binary)
    ELF_LITTLE_ENDIAN = readElfEndian(options.binary)

    bbl.init(ELF_ARCH, ELF_CLASS, ELF_LITTLE_ENDIAN)

    if bbl.BB_ARCH == "MIPS":
        import mipsRelocs
        mips_galr_targets = mipsRelocs.read_mips_jalr_relos(options.binary)


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

    readElfRelocation(options.binary)
    func_address = get_func_address(options.binary)
    LOAD_RANGE = getLoadAddressRange(options.binary)
    LOAD_OFFSET = getLoadOffset(options.binary)
    (GOT_PLT_ADDR, _) = readSectionRange(options.binary, '.got.plt')
    TEXT_RANGE = readSectionRange(options.binary, '.text')
    logging.debug("ELF_CLASS is %d", ELF_CLASS)
    logging.info("ELF_ARCH is %s", ELF_ARCH)
    logging.info("LOAD RANGE is {0}".format(LOAD_RANGE))
    logging.debug("GOT_PLT_ADDR is 0x%x" % (GOT_PLT_ADDR))
    logging.debug(".text section range is 0x%x to 0x%x" % (TEXT_RANGE[0], TEXT_RANGE[1]))

    rData['bin_info']['bin_path'] = options.binary
    logging.debug(bbl.BB_CS_MODE_1)
    essInfo = EssentialInfo(rData)

    # get the gaps in .text.xxx
    # bbl_layout = fixOneBytePadding(raw_protobuf_buffer.layout)
    # bbl_layout = fixFunctionStartInGaps(bbl_layout, options.binary)
    #bbl_layout = raw_protobuf_buffer.layout
    # textsec_info = get_textsec_info(options.binary)
    GAPS_LIST = checkGaps(essInfo.constructInfo.BasicBlockLayout, TEXT_RANGE[1])
    if not options.disable_postaa:
        heuristicSearchingJmptbl(essInfo)
    DISABLE_POST_AA = options.disable_postaa

    dumpGroundTruth(essInfo, module, outFile, options.binary, options.split)
    pbOut = open(options.output, "wb")
    pbOut.write(module.SerializeToString())
    pbOut.close()

    final_gaps_list = checkGapsAtEnd(module, TEXT_RANGE[1])
    countGaps(final_gaps_list)
    dumpSummary()
