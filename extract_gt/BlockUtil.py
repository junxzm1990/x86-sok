"""
python3.7
file: BlockUtil.py
date: 07/19/2019
author: binpang

Block utils
"""

import capstone as cs
import capstoneCallback

from capstone import x86
from elftools.elf.elffile import ELFFile 
from util import *
import random
import string
import traceback
import os

def randomString(stringLength=10):
    """Generate a random string of fixed length """

    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

# hash a 64 bit integer
def hash64(x):
    x = (x ^ (x >> 30)) * (0xbf58476d1ce4e5b9)
    x = (x ^ (x >> 27)) * (0x94d049bb133111eb)
    x = x ^ (x >> 31)
    return x

'''
read function information from .eh_frame section
'''
def readFuncsFromEhFrame(binary):
    logging.debug("strip binary is %s" % binary)
    try:
        result = dict()
        tmp_path = randomString()
        shell_command = "readelf --debug-dump=frames %s | grep 'pc=' | cut -f3 -d = | awk '{print $1}' > /tmp/%s" %\
            (binary, tmp_path)
        logging.debug(shell_command)
        os.system(shell_command)
        tmp_file = open('/tmp/%s' % tmp_path, 'r+')
        for line in tmp_file:
            splited_line = line.strip().split('.')
            func_start = int(splited_line[0], 16)
            func_end = int(splited_line[2], 16)
            #logging.info("[Find Func Start From EH_FRAME]: address 0x%x, size is 0x%x" % (func_start, func_end - func_start))
            result[func_start] = func_end - func_start
        os.system('rm /tmp/%s' % (tmp_path))
    except Exception as e:
        traceback.print_exc()
        return None
    return result

def isPureIndirect(inst):
    """
    judge if the inst is a indirect jump

    args:
        inst:
        jmp: True: already judge the instruction is the jmp instruction

    rets: True of False
    """
    if inst.id == 0:
        return False

    black_list = {"rip", "RIP", "eip", "EIP"}
    if x86.X86_GRP_JUMP not in inst.groups and \
            x86.X86_GRP_CALL not in inst.groups and \
            "loop "not in inst.mnemonic.lower():
        return False

    for i in inst.operands:
        if i.type == x86.X86_OP_REG:
             reg_name = inst.reg_name(i.reg)
             if reg_name in black_list:
                 continue
             logging.info("[indirect instruction] 0x%x:\t%s\t%s" % (inst.address, inst.mnemonic, inst.op_str))
             return True
        if i.type == x86.X86_OP_MEM:
            '''
            for jmp base[index, scale, displacement]
            '''
            if i.mem.index != 0:
                logging.info("[indirect instruction] 0x%x:\t%s\t%s" % (inst.address, inst.mnemonic, inst.op_str))
                return True
    return False

def checkTerminatorIsIndirect(MD, disassemble_content, current_addr):
    disasm_ins = MD.disasm(disassemble_content, current_addr, count = 1)
    try:
        cur_inst = next(disasm_ins)
    except StopIteration:
        return False 
    if cur_inst != None and (x86.X86_GRP_JUMP in cur_inst.groups or x86.X86_GRP_CALL in cur_inst.groups):
        if isPureIndirect(cur_inst):
            return True
    return False

def checkTerminatorIsIndirectJump(MD, disassemble_content, current_addr):
    disasm_ins = MD.disasm(disassemble_content, current_addr, count = 1)
    try:
        cur_inst = next(disasm_ins)
    except StopIteration:
        return False 
    try:
        if cur_inst != None and x86.X86_GRP_JUMP in cur_inst.groups and isPureIndirect(cur_inst):
            return True
    except:
        return False
    return False

def checkTerminatorIsIndirectCall(MD, disassemble_content, current_addr):
    disasm_ins = MD.disasm(disassemble_content, current_addr, count = 1)
    try:
        cur_inst = next(disasm_ins)
    except StopIteration:
        return False
    try:
        if cur_inst != None and x86.X86_GRP_CALL in cur_inst.groups and isIndirect(cur_inst):
            return True
    except:
        return False
    return False

'''
check if the ground truth function not included by symbol information

params:
    funcSet: function sets
    binary: binary file
'''
def checkGroundTruthFuncNotIncluded(groundTruthRange, binary):
    result = set()
    with open(binary, 'rb') as openFile:
        elffile = ELFFile(openFile)
        symsec = elffile.get_section_by_name('.symtab')
        if symsec == None:
            logging.error("binary %s does not contain .symtab section!" % binary)
            return None
        for sym in symsec.iter_symbols():
            if 'STT_FUNC' != sym.entry['st_info']['type']:
                continue
            func_addr = sym['st_value']
            func_name = sym.name
            if func_addr != 0 and sym['st_size'] != 0 and func_addr not in groundTruthRange:
                logging.warning("[check ground truth function:] function %s in address 0x%x not in ground truth" % 
                        (func_name, func_addr))
                result.add(func_addr)
    return result

def checkGroundTruthRangeNotIncluded(groundTruthRange, binary):
    result = set()
    with open(binary, 'rb') as openFile:
        elffile = ELFFile(openFile)
        symsec = elffile.get_section_by_name('.symtab')
        if symsec == None:
            logging.error("binary %s does not contain .symtab section!" % binary)
            return None
        for sym in symsec.iter_symbols():
            if 'STT_FUNC' != sym.entry['st_info']['type']:
                continue
            func_addr = sym['st_value']
            func_name = sym.name
            if func_addr != 0 and func_addr not in groundTruthRange:
                logging.warning("[check ground truth function:] function %s in address 0x%x not in ground truth" % 
                        (func_name, func_addr))
                result.add(func_addr)
    return result

'''
get all functions range from ground truth
params:
    binary: binary file
'''
def getFuncRanges(binary):
    result = list()
    with open(binary, 'rb') as openFile:
        elffile = ELFFile(openFile)
        symsec = elffile.get_section_by_name('.symtab')
        if symsec == None:
            logging.error("binary %s does not contain .symtab section!" % binary)
            return None
        for sym in symsec.iter_symbols():
            if 'STT_FUNC' != sym.entry['st_info']['type']:
                continue
            func_addr = sym['st_value']
            func_size = sym['st_size']
            func_name = sym.name
            if func_addr != 0 and func_size != 0:
                result.append((func_addr, func_addr + func_size))
    return result

# merge call edges into normal cfg
# for some tools, such as angr, bap, dyninst
# they split the basic block by direct call instructions
# we merge these edges into cfg
def merge_call_edges(func, all_successors):
    not_balance = True
    bb_dict = dict()
    for bb in func.bb:
        bb_dict[bb.va] = bb
    while not_balance:
        not_balance = False
        for bb in func.bb:
            if bb.type == BlockType.INVALID_BB:
                continue


            if bb.type == BlockType.DIRECT_CALL or bb.type == BlockType.INDIRECT_CALL or\
                    bb.type == BlockType.FALL_THROUGH:

                
                if bb.size > 0:
                    fallthrough_suc = bb.size + bb.padding + bb.va
                else:
                    fallthrough_suc = bb.instructions[-1].va + bb.instructions[-1].size


                # check no incoming edges except this fall through edge
                if fallthrough_suc in all_successors:
                    continue


                fallthrough_bb = bb_dict.get(fallthrough_suc, None)
                if not fallthrough_bb:
                    logging.warning("can't find fallthrough bb 0x%x" % fallthrough_suc)
                    continue


                logging.debug("merging fallthrough bb 0x%x to bb 0x%x", fallthrough_suc, bb.va)
                # replace successor
                del bb.child[:]
                for suc in fallthrough_bb.child:
                    add_suc = bb.child.add()
                    add_suc.va = suc.va

                # add instructions
                for ins in fallthrough_bb.instructions:
                    add_inst = bb.instructions.add()
                    add_inst.va = ins.va
                    add_inst.size = ins.size

                # discard bb
                bb.type = fallthrough_bb.type
                bb.size = bb.size + fallthrough_bb.size + bb.padding
                bb.padding = fallthrough_bb.padding
                fallthrough_bb.type = BlockType.INVALID_BB
                not_balance = True



TERMINAL_LIST = ['leave', 'hlt', 'ud2']
# define block terminator type
class BlockType:
    OTHER = 0 # other type
    DIRECT_CALL = 1 # direct call instruction 
    INDIRECT_CALL = 2 # indirect call instruction 
    RET = 3 #  ret instruction 
    COND_BRANCH = 4 # conditional jump(direct)
    DIRECT_BRANCH = 5 # direct jump 
    INDIRECT_BRANCH = 6 # indirect jump
    JUMP_TABLE = 7 # jump table
    NON_RETURN_CALL = 8 # non-return function all
    FALL_THROUGH = 9 # fall_through
    #OVERLAPPING_INST = 10 # overlapping instruction
    TAIL_CALL = 11 # tail call
    FALLTHROUGH_TOFUNC = 12 #fall through to another function. these two functin share some code
    JUMP_TOFUNC = 13#jump to another function start, but in current functin range. that is                       these two function share some codes
    DUMMY_JMP_TABLE = 14# dummy jump table
    INVALID_BB = 15 # discardd the basic block

class Inst():
    def __init__(self, va, size):
        self.VA = va
        self.size = size

def isFallThrough(inst):
    if inst.id == 0:
        return True

    if x86.X86_GRP_RET in inst.groups or \
            inst.op_str in TERMINAL_LIST or inst.mnemonic in TERMINAL_LIST:
                return False
    if x86.X86_GRP_JUMP in inst.groups:
        if 'jmp' in inst.mnemonic:
            return False
        return True
        
    return True

def tryGetDirectTarget(MD, content, va, group_type, iat_targets):

    disasm_ins = MD.disasm(content, va, count = 1)
    try:
        cur_inst = next(disasm_ins)
    except StopIteration:
        return (None, None, None)

    if group_type not in cur_inst.groups:
        return (None, cur_inst, None)

    if isPureIndirect(cur_inst):
        return (None, cur_inst, None)

    (ret_type, target) = getDirectTargetAndMem(cur_inst)

    logging.debug("direct instruction is %s" % getInstStr(cur_inst))

    if ret_type == 2:
        cur_ip = cur_inst.address + cur_inst.size
        try_target = cur_ip + target
        try_suc = False
        if try_target in iat_targets:
            target = try_target
            try_suc = True

        if not try_suc  and target not in iat_targets:
            return (None, cur_inst, None)

    return (target, cur_inst, ret_type)

def isTerminator(inst):
    if inst.id == 0:
        return False

    if x86.X86_GRP_JUMP in inst.groups or \
            x86.X86_GRP_RET in inst.groups or \
            x86.X86_GRP_CALL in inst.groups or \
            "loop "in inst.mnemonic.lower() or \
            inst.op_str in TERMINAL_LIST or inst.mnemonic in TERMINAL_LIST:
        return True
    return False


# splited basic block, we may split the basic block by `call` instruction
class Blk():
    # vir_addr: basic block's virtual address
    # start: basic block start offset from binary file
    # end: basic block end offset from binary file
    # parent: blk's parent is baiscblock type from `util.py`
    # function: parent function address
    def __init__(self, vir_addr, start, end, parent, fall_through, function = None):
        self.VA = vir_addr
        self.start = start
        self.end = end
        self.parent = parent
        self.type = 0 
        self.fall_through = fall_through 
        self.is_jump = False
        self.is_call = False

        # store the successors
        self.successors = list()

        # parent function adress
        self.function = function

        # capstone instruction list
        self.ins_list = list()

        self.size = end - start
        self.padding = 0
    
    def set_type(self, groups, indirect):
        """
        set blk type
        args:
            groups: instruction groups
            indirect: bool
        """

        if x86.X86_GRP_RET in groups:
            self.type = BlockType.RET
            return

        jump = False
        call = False
        if x86.X86_GRP_JUMP in groups:
            jump = True
            self.is_jump = True
        elif x86.X86_GRP_CALL in groups:
            self.is_call = True
            call = True

        if jump:
            if indirect:
                self.type = BlockType.INDIRECT_BRANCH
            elif self.fall_through:
                self.type = BlockType.COND_BRANCH
            else:
                self.type = BlockType.DIRECT_BRANCH

        elif call:
            if indirect:
                self.type = BlockType.INDIRECT_CALL
            elif self.fall_through:
                self.type = BlockType.DIRECT_CALL
            else:
                self.type = BlockType.NON_RETURN_CALL

        elif self.fall_through == True:
            self.type = BlockType.FALL_THROUGH
        else:
            self.type = BlockType.OTHER

    def insert_instruction(self, ins):
        self.ins_list.append(ins)

    def is_indirect_type(self):
        if self.type == BlockType.INDIRECT_BRANCH or self.type == BlockType.INDIRECT_CALL:
            return True
        return False

    def is_direct_type(self):
        if self.type == BlockType.COND_BRANCH or self.type == BlockType.DIRECT_BRANCH or \
                self.type == BlockType.DIRECT_CALL or self.type == BlockType.NON_RETURN_CALL:
            return True
        return False

    def is_direct_jump(self):
        if self.type == BlockType.COND_BRANCH or self.type == BlockType.DIRECT_BRANCH:
            return True
        return False

    def add_successor(self, blk):
        self.successors.append(blk)

'''
capstone initialization

args:
    elf_class: 64 or 32
'''
def init_capstone(elf_class):
    md = None
    if elf_class == 64:
        md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    elif elf_class == 32:
        md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
    else:
        logging.error("Architecture {} bits not supported yet!".format(elf_class)) 
        exit(-1)

    if md == None:
        return None
    # capstone4.0.1 can't handle some instructions. such as wrpkru and rdpkru
    # so we write the handler to handle these instructions
    md.skipdata_setup = (".unhandled", capstoneCallback.mycallback, None)
    md.skipdata = True
    md.detail = True
    return md

def split_block(bb, binary, split, elf_class):
    """
    split the type `basicblock` into `Blk`s
    args:
        bb: basicblock
        binary: binary file
        split: bool type. split the basicblock by `call` instruction or not
        elf_class: 32 or 64 bit
    """
    result = list()
    start_adr = bb.offsetFromBase
    end_adr = bb.size + start_adr - bb.padding
    if split == False and bb.assembleType == 0:
        # some bug that in ccr
        jmp_inst = list()
        with open(binary, 'rb') as infile:
            readdata = infile.read(end_adr)
            bbdata = readdata[start_adr:]
            md = init_capstone(elf_class)
            inslist = md.disasm(bbdata, bb.VA)
            block_start = start_adr
            block_end = end_adr
            last_inst = None
            inst_idx = 0
            for i in inslist:
                if x86.X86_GRP_JUMP in i.groups:
                    inst_idx += 1
                    jmp_inst.append(i)

            current_addr = bb.VA
            current_start_addr = start_adr
            if len(jmp_inst) > 0:
                for jmp in jmp_inst:
                    end_addr = jmp.address + jmp.size - bb.VA + bb.offsetFromBase
                    fall_through = False if 'jmp' in jmp.mnemonic.lower() else True
                    result.append(Blk(current_addr, current_start_addr, end_addr, bb, fall_through))
                    logging.info("hello, current start 0x%x - 0x%x" % (current_start_addr, end_addr))
                    current_addr = jmp.address + jmp.size
                    current_start_addr = end_addr
            if current_start_addr != block_end:
                logging.info("hello, current start 0x%x - 0x%x" % (current_start_addr, block_end))
                result.append(Blk(current_addr, current_start_addr, block_end, bb, bb.hasFallThrough))
        return result

    jmp_targets = list()
    # Here we split the basic block in two situations:
    #   S1: we split the basic block by `call` instruction, that is split == True
    #   S2: if the basic block is `dummy`, that is the basic block contains inline
    #       assemble code or the `basic block` is in handwritten assemble file
    with open(binary, 'rb') as infile:
        readdata = infile.read(end_adr)
        bbdata = readdata[start_adr:]
        md = init_capstone(elf_class)
        inslist = md.disasm(bbdata, bb.VA)
        block_start = start_adr
        block_end = start_adr
        last_inst = None
        for i in inslist:
            last_inst = i
            block_end += i.size
            if i.id == 0:
                continue
            if split == True and x86.X86_GRP_CALL in i.groups:
                # block offset from binary file,
                # We deem call instruction fall through
                result.append(Blk(bb.VA + block_start - start_adr, block_start, block_end, bb, True))
                logging.info("[Split block]: new block is split by call: addr %x, offset is %x - %x" % \
                        (bb.VA + block_start-start_adr, block_start, block_end))
                block_start = block_end

            # for inline assemble and handwritten assemble file,
            # the `basic block` is not the real basic block
            elif isTerminator(i):
                fall_through = True
                # FIXME: if the jump instruction is fall through
                if 'jmp' in i.mnemonic.lower() or x86.X86_GRP_RET in i.groups:
                    fall_through = False
                result.append(Blk(bb.VA + block_start - start_adr, block_start, block_end, bb, fall_through))
                logging.info("[Split block]: `dummy` block is split by jmp: addr %x, offset is %x - %x" % \
                        (bb.VA + block_start - start_adr, block_start, block_end))
                block_start = block_end


        if block_end != end_adr:
            logging.error("Basic block split Error: bb %x-%x. Last instruction is %s"
                    % (bb.VA, bb.VA + bb.size - bb.padding, getInstStr(last_inst)))

        if block_end != block_start:
            result.append(Blk(block_start - start_adr + bb.VA, block_start, end_adr, bb, bb.hasFallThrough))
            logging.info("[Split block]: new block addr %x, offset is %x - %x" % \
                        (bb.VA + block_start-start_adr, block_start, end_adr))
        # For handwritten assemble code,
        # we need to confirm the FALLTHROUGH or not manuanlly
        if last_inst != None and bb.assembleType == 2 \
                and not isTerminator(i):
            # set the last basic block as FALLTHROUGH
            result[-1].fall_through = True

    return result
'''
readelf class: 32 bit or 64 bit
'''
def readElfClass(binary):
    result = 64
    with open(binary, 'rb') as openFile:
        elffile = ELFFile(openFile)
        result = elffile.elfclass
    return result

def getLoadAddressRange(binary):
    load_range = list()
    with open(binary, 'rb') as openFile:
        elffile = ELFFile(openFile)
        for seg in elffile.iter_segments():
            if seg['p_type'] != 'PT_LOAD':
                continue
            load_range.append((seg['p_vaddr'], seg['p_vaddr'] + seg['p_memsz']))
    return load_range

def enlargeRange(load_range, append_range=0x1024):
    new_range = list()
    for (start, end) in load_range:
        new_range.append((start - append_range, end + append_range))
    return new_range


def isInRange(addr, range_list):
    for (start, end) in range_list:
        if addr >= start and addr < end:
            return True
    return False

def checkInRange(addr, addressSet, accurate):
    if accurate:
        return addr in addressSet
    else:
        for (cur_addr, size) in addressSet.items():
            if addr >= cur_addr and addr < cur_addr + size:
                return True
        return False

def isInRangeDict(addr, range_list):
    for (start, end) in range_list.items():
        if addr >= start and addr <= end:
            return True
    return False
'''
args:
    binary: binary file path
    sec: section name
rets:
    section range: (start, end) 
'''
def readSectionRange(binary, sec):
    sec_start = 0x0
    sec_end = 0x0
    with open(binary, 'rb') as openFile:
        elf = ELFFile(openFile)
        elf_sec = elf.get_section_by_name(sec)
        if elf_sec:
            sec_start = elf_sec['sh_addr']
            sec_end = sec_start + elf_sec['sh_size']
    return (sec_start, sec_end)
        
"""
in openssl, some function start with some .byte(s)
so there may omit some function start
we fix this corner case according to the symbol table

.globl  bn_gather5
.type   bn_gather5,@function
.align  32
bn_gather5:
.LSEH_begin_bn_gather5:

.byte   0x4c,0x8d,0x14,0x24
.byte   0x48,0x81,0xec,0x08,0x01,0x00,0x00
        leaq    .Linc(%rip),%rax
        andq    $-16,%rsp
"""
def fixFunctionStartInGaps(bblLayout, binary):
    func_from_symbols = set()
    text_base_addr = None
    (text_start, text_end) = readSectionRange(binary, ".text")
    with open(binary, 'rb') as openFile:
        elf = ELFFile(openFile)
        sym_sec = elf.get_section_by_name('.symtab')
        if sym_sec == None:
            return bblLayout
        for sym in sym_sec.iter_symbols():
            addr = sym['st_value']
            if 'STT_FUNC' == sym.entry['st_info']['type'] and (addr >= text_start and addr < text_end):
                func_from_symbols.add(sym['st_value'])

        for sec in elf.iter_sections():
            if '.text' == sec.name:
               text_base_addr = sec['sh_addr']
               break
    # we only collect .text information for now
    if text_base_addr == None:
        logging.warning("[fixFunctionStartInGaps]: This function only works with executable/libs!")
        return bblLayout

    bb_dict_index = dict()
    bb_list = dict()
    for idx in range(len(bblLayout)):
        sz = bblLayout[idx].bb_size
        offset = bblLayout[idx].offset
        bb_list[offset] = sz
        bb_dict_index[offset] = idx
        sec_name = bblLayout[idx].section_name

    sorted_bb_list = sorted(bb_list.items())

    range_not_included = list()
    idx_num = 0
    length = len(sorted_bb_list)
    for (bb_offset, size) in sorted_bb_list:
        idx_num += 1
        if idx_num < length:
            next_offset = bb_offset + size
            if next_offset not in bb_list: #and (next_offset - 1) not in bb_list and (next_offset + 1) not in bb_list:
                range_not_included.append((next_offset, sorted_bb_list[idx_num][0]))

    func_idx = 0
    for func in func_from_symbols:
        func_offset = func - text_base_addr
        if func_offset not in bb_list:
            logging.warning("Function start#%d 0x%x not in bb list" % (func_idx, func))
            func_idx += 1
            # check the if the function between a gap
            for (start, end) in range_not_included:
                if func_offset >= start and func_offset < end:
                    logging.debug("[fixFunctionStartInGaps]: found function start 0x%x between gaps(0x%x - 0x%x)!" % 
                            (func, text_base_addr + start, text_base_addr + end))
                    # we assume the handwritten .byte is not toooo much
                    if end - func_offset < 0x20 and end in bb_dict_index:
                        logging.debug("lalal, we find .byte(s) before function start!")
                        idx = bb_dict_index[end]
                        added_size = end - func_offset
                        old_start = bblLayout[idx].offset + text_base_addr
                        new_start = old_start - added_size
                        bblLayout[idx].bb_size += added_size
                        bblLayout[idx].offset -= added_size
                        logging.debug("[fixFunctionStartInGaps]: change bb from 0x%x to 0x%x" % 
                                (old_start, new_start))
    return bblLayout


    
# For some special cases(we found it in mysql 5.7.27) compiled by gcc.
# fix this bug here.
"""
    nop
    .bb_bbinfo // basic block start mark
    xxxxx
    xxxxxxx
    xxxx
    .be_bbinfo // basic block end mark

The above example shows that nop instruction was not included in the right basic block

args:
    layout: basic block layout list

rets:
    the fixed basic block layout list
"""
def fixOneBytePadding(layout):
    bblLayout = layout
    layout_map = dict() # basic block begining address => index
    for idx in range(len(bblLayout)):
        layout_map[bblLayout[idx].offset] = idx
    current_idx = 0
    
    miss_1_byte_map = set()
    additional_1_byte_map = set()
    for (address, idx) in layout_map.items():
        layout = bblLayout[idx] 
        current_idx += 1
        next_bb_addr = address + layout.bb_size
        # the address is continuous
        if next_bb_addr in layout_map:
            continue

        # the last basic block
        if current_idx == len(bblLayout):
            continue

        # the basic block may lack 1 byte
        if (next_bb_addr + 1) in layout_map:
            miss_1_byte_map.add(layout_map[next_bb_addr+1])

        # the basic block may have addition 1 byte
        if (next_bb_addr - 1) in layout_map:
            additional_1_byte_map.add(idx)

    # double check
    # for every basic block which has additional 1 byte
    # we check if its next basic block lacks 1 byte
    for addi_idx in additional_1_byte_map:
        if (addi_idx + 1) in miss_1_byte_map:
            # fix the basic block size
            bblLayout[addi_idx].bb_size -= 1

            # update the address and size of basic block which lacks 1 byte
            bblLayout[addi_idx+1].bb_size += 1
            bblLayout[addi_idx+1].offset -= 1

    return bblLayout

"""
check if the instruction have prefix
"""
def checkInsPrefix(ins):
    if ins.id == 0:
        return False
    prefix = sum(ins.prefix)
    return prefix != 0


'''
check .text.xxx sections gap, these gap may contains data

args:
    rand_info: basic block layout list

rets:
    gaps list
'''
def checkGaps(bbl_layout, sec_end_addr):
    bb_list = dict()
    for bb in bbl_layout:
        sz = bb.size
        va = bb.VA
        bb_list[va] = sz
        
    sorted_bbs = sorted(bb_list.items())

    range_not_included = list()
    gaps_num = 0
    length = len(sorted_bbs)
    idx_num = 0
    logging.debug("section end address is 0x%x" % (sec_end_addr))
    for (bb_offset, sz) in sorted_bbs:
        idx_num += 1
        next_offset = bb_offset + sz
        if idx_num < length:
            if next_offset not in bb_list:
                start_addr = next_offset
                end_addr = sorted_bbs[idx_num][0]
                range_not_included.append(
                        (start_addr, end_addr))
                logging.info("Found Gaps#%d in section %s, between 0x%x - 0x%x, size: %d" % 
                        (gaps_num, ".text", start_addr, end_addr, end_addr - start_addr))
                gaps_num += 1
        # gaps between last basic block and section end
        elif next_offset != sec_end_addr:
            range_not_included.append((next_offset, sec_end_addr))
            logging.info("Found Gaps#%d in section %s, between 0x%x - 0x%x"%
                        (gaps_num, ".text", next_offset, sec_end_addr))
            gaps_num += 1
    return range_not_included

def checkGapsAtEnd(module, sec_end_addr):
    bb_list = dict()
    for func in module.fuc:
        for bb in func.bb:
            sz = bb.size + bb.padding
            va = bb.va
            bb_list[va] = sz

    sorted_bbs = sorted(bb_list.items())

    range_not_included = list()
    gaps_num = 0
    length = len(sorted_bbs)
    idx_num = 0
    logging.debug("section end address is 0x%x" % (sec_end_addr))
    for (bb_offset, sz) in sorted_bbs:
        idx_num += 1
        next_offset = bb_offset + sz
        if idx_num < length:
            if next_offset not in bb_list:
                start_addr = next_offset
                end_addr = sorted_bbs[idx_num][0]
                range_not_included.append(
                        (start_addr, end_addr))
                if (end_addr > start_addr):
                    logging.info("Found Gaps#%d in section %s, between 0x%x - 0x%x, size: %d" % 
                        (gaps_num, ".text", start_addr, end_addr, end_addr - start_addr))
                    gaps_num += 1
        # gaps between last basic block and section end
        elif next_offset != sec_end_addr:
            range_not_included.append((next_offset, sec_end_addr))
            logging.info("Found Gaps#%d in section %s, between 0x%x - 0x%x"%
                        (gaps_num, ".text", next_offset, sec_end_addr))
            gaps_num += 1
    return range_not_included

def disassembleBB(blk, binary, elf_class, one_inst = False):
    """
    disassemble the binary code from the startadr to endadr.

    args:
        blk:
        binary:
        elf_class: 32 or 64 bits
        one_inst: only disassemble one instruction and return

    rets:
        instruction list
    """
    viradr = blk.VA
    startadr = blk.start
    endadr = blk.end
    inslist = None
    with open(binary, 'rb') as infile:
        readdata = infile.read(endadr)
        bbdata = readdata[startadr:]
        md = init_capstone(elf_class)
        current_addr = viradr
        end_vir_addr = viradr + endadr - startadr
        inslist = list()
        while current_addr < end_vir_addr:
            disasm_result = md.disasm(bbdata, current_addr, count = 1)
            try:
                cur_inst = next(disasm_result)
            except StopIteration:
                break


            if cur_inst.id == 0:
                logging.info("Instructions that capstone can't handled. 0x%x" % 
                        (cur_inst.address))

            current_addr += cur_inst.size
            bbdata = bbdata[cur_inst.size:]
            inslist.append(cur_inst)
            
            if one_inst:
                return inslist

        # check if the basic block is disassembled correctlly
        if current_addr < end_vir_addr:
            logging.error("OMG, The basic block 0x%x - 0x%x is not correctly handled" % 
                    (blk.VA, blk.VA + blk.end - blk.start))
    return inslist

# helper function
# get instruction string
def getInstStr(i):
    if i == None or i.id == 0:
        return "" 
    return "0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str)

def recursiveDisassembleInRange(binary, gap_start, 
                        start, end, entry, elf_class):
    # store visited instruction address
    visited = set()
    # store (next disassemble address, function that this address belongs to)
    task = list() 
    # the result of blk list
    blk_list = list()
    current_blk = None
    current_offset = None
    current_function = None
    gap_end = gap_start + end - start

    task.append((entry, function))
    open_file = open(binary, 'rb')
    read_data = open_file.read(end)
    open_file.close()
    gap_data = read_data[start:]
    logging.debug("[recursive disassembling instruction]: current offset is 0x%x" % entry)

    # capstone initialization
    md = init_capstone(elf_class)

    # recursive disassemble begins
    while True:
        if len(task) == 0:
            if current_blk != None:
                blk_list.append(current_blk)
            break

        (current_offset , current_function) = task.pop(-1)

        if current_offset in visited:
            continue

        if current_blk == None:
            current_blk = Blk(gap_start + current_offset, 
                            current_offset + start, current_offset + start,
                            None, False, current_function)
        visited.add(current_offset)
        current_data = gap_data[current_offset:]
        disasm_result = md.disasm(current_data, current_offset + gap_start, count = 1)
        try:
            cur_inst = next(disasm_result)
        except StopIteration:
            continue
        logging.debug("[recursive disassembling instruction]: %s" % getInstStr(cur_inst))
        current_blk.insert_instruction(cur_inst)
        current_blk.end += cur_inst.size

        # add fallthrough target address
        if isFallThrough(cur_inst):
            if (current_offset + cur_inst.size) not in visited and \
                isInRange(current_offset + cur_inst.size, [(0, end-start)]):
                task.append((current_offset + cur_inst.size, current_function))

        if isTerminator(cur_inst):
            blk_list.append(current_blk)
            if isFallThrough(cur_inst):
                current_blk.add_successor(current_offset + cur_inst.size + gap_start)
                current_blk.type = BlockType.FALL_THROUGH

            if isIndirect(cur_inst):
                logging.warning("[Recursive disassembling in Gaps]: there exists indirect instructions in .byte 0x%x: %s" % 
                        (cur_inst.address, getInstStr(cur_inst)))
                if x86.X86_GRP_CALL in cur_inst.groups:
                    current_blk.type = BlockType.INDIRECT_CALL
                else:
                    current_blk.type = BlockType.INDIRECT_BRANCH
            else:
                # add jump/call target address
                target = getDirectAddress(cur_inst)
                if target != None:
                    if target in visited:
                        current_blk = None
                        continue
                    # It is the case that target address is not in the range of gap
                    # as we disassemble the .byte/.quard/.long regions,
                    # it only knows the offset inside this region
                    # so it may be the error of the disassembling
                    # we need to double check here manually
                    if target >= gap_end and target < gap_start:
                        logging.error("[Recursive disassembling in Gaps]: the jump/call target address is out of range! instruction is 0x%x: %s" % 
                                (cur_inst, getInstStr(cur_inst)))
                        current_blk = None
                        continue
                    # get the target address offset from the gap start
                    target_offset = target - gap_start
                    current_blk.add_successor(target)
                    if x86.X86_GRP_CALL in cur_inst.groups:
                        task.append((target_offset, target))
                        current_blk.type = BlockType.DIRECT_CALL
                    else:
                        task.append((target_offset, current_function))
                        current_blk.type = BlockType.DIRECT_BRANCH
            current_blk = None
    return blk_list

'''
As we can't identify .byte/.long/.quard directives as instructions by gcc/clang toolchains, so we will try recursive disassemble these bytes based on some heuristics.

H1: if these bytes is behind with basic block that is confirmed as FALLTHROUGH
H2: if these bytes are targets of jmp/call instructions

Args:
    binary: binary file path
    gap_start: gap start virtual address
    start: gap start offset from the file
    end: gap end offset form the file
    entry: disassemble entry point. offset from the gap
    function: function address it belongs to

Rets:
   list of Blks 
'''
def recursiveDisassembleInRange(binary, gap_start, 
                        start, end, entry, elf_class, function):
    # store visited instruction address
    visited = set()
    # store (next disassemble address, function that this address belongs to)
    task = list() 
    # the result of blk list
    blk_list = list()
    current_blk = None
    current_offset = None
    current_function = None
    gap_end = gap_start + end - start

    task.append((entry, function))
    open_file = open(binary, 'rb')
    read_data = open_file.read(end)
    open_file.close()
    gap_data = read_data[start:]
    logging.debug("[recursive disassembling instruction]: current offset is 0x%x" % entry)

    # capstone initialization
    md = init_capstone(elf_class)

    # recursive disassemble begins
    while True:
        if len(task) == 0:
            if current_blk != None:
                blk_list.append(current_blk)
            break

        (current_offset , current_function) = task.pop(-1)

        if current_offset in visited:
            continue

        if current_blk == None:
            current_blk = Blk(gap_start + current_offset, 
                            current_offset + start, current_offset + start,
                            None, False, current_function)
        visited.add(current_offset)
        current_data = gap_data[current_offset:]
        disasm_result = md.disasm(current_data, current_offset + gap_start, count = 1)
        try:
            cur_inst = next(disasm_result)
        except StopIteration:
            continue
        logging.debug("[recursive disassembling instruction]: %s" % getInstStr(cur_inst))
        current_blk.insert_instruction(cur_inst)
        current_blk.end += cur_inst.size

        # add fallthrough target address
        if isFallThrough(cur_inst):
            if (current_offset + cur_inst.size) not in visited and \
                isInRange(current_offset + cur_inst.size, [(0, end-start)]):
                task.append((current_offset + cur_inst.size, current_function))

        if isTerminator(cur_inst):
            blk_list.append(current_blk)
            if isFallThrough(cur_inst):
                current_blk.add_successor(current_offset + cur_inst.size + gap_start)
                current_blk.type = BlockType.FALL_THROUGH

            if isIndirect(cur_inst):
                logging.warning("[Recursive disassembling in Gaps]: there exists indirect instructions in .byte 0x%x: %s" % 
                        (cur_inst.address, getInstStr(cur_inst)))
                if x86.X86_GRP_CALL in cur_inst.groups:
                    current_blk.type = BlockType.INDIRECT_CALL
                else:
                    current_blk.type = BlockType.INDIRECT_BRANCH
            else:
                # add jump/call target address
                target = getDirectAddress(cur_inst)
                if target != None:
                    if target in visited:
                        current_blk = None
                        continue
                    # It is the case that target address is not in the range of gap
                    # as we disassemble the .byte/.quard/.long regions,
                    # it only knows the offset inside this region
                    # so it may be the error of the disassembling
                    # we need to double check here manually
                    if target >= gap_end and target < gap_start:
                        logging.error("[Recursive disassembling in Gaps]: the jump/call target address is out of range! instruction is 0x%x: %s" % 
                                (cur_inst, getInstStr(cur_inst)))
                        current_blk = None
                        continue
                    # get the target address offset from the gap start
                    target_offset = target - gap_start
                    current_blk.add_successor(target)
                    if x86.X86_GRP_CALL in cur_inst.groups:
                        task.append((target_offset, target))
                        current_blk.type = BlockType.DIRECT_CALL
                    else:
                        task.append((target_offset, current_function))
                        current_blk.type = BlockType.DIRECT_BRANCH
            current_blk = None
    return blk_list
        

# get target address from jump/call instruction
def getDirectAddress(inst):
    if inst.id == 0:
        return None

    if x86.X86_GRP_JUMP not in inst.groups and \
            x86.X86_GRP_CALL not in inst.groups and \
            "loop" not in inst.mnemonic.lower():
        return None
    target_addr = None
    for op in inst.operands:
        if op.type == x86.X86_OP_IMM:
            target_addr = op.value.imm

    return target_addr


def isDirect(inst):
    """
    judge if the inst is a direct jump/call

    args:
        inst:
        jmp: True: already judge the instruction is the jmp instruction

    rets: True of False
    """
    if inst.id == 0:
        return False

    black_list = {"rip", "RIP", "eip", "EIP"}
    if x86.X86_GRP_JUMP not in inst.groups and \
            x86.X86_GRP_CALL not in inst.groups and \
            "loop "not in inst.mnemonic.lower():
        return False

    for i in inst.operands:
        if i.type == x86.X86_OP_REG:
             reg_name = inst.reg_name(i.reg)
             if reg_name in black_list:
                 continue
             logging.info("[indirect instruction] 0x%x:\t%s\t%s" % (inst.address, inst.mnemonic, inst.op_str))
             return False
        if i.type == x86.X86_OP_MEM:
            '''
            for jmp base[index, scale, displacement]
            '''
            if i.mem.index != 0:
                logging.info("[indirect instruction] 0x%x:\t%s\t%s" % (inst.address, inst.mnemonic, inst.op_str))
                return False

    if 'ptr' in inst.op_str:
        logging.warning("[indirect call instruction] 0x%x:\t%s\t%s" % (inst.address, inst.mnemonic, inst.op_str))
        return False

    return True

def getDirectTarget(inst):
    result = None
    for i in inst.operands:
        if i.type == x86.X86_OP_IMM:
            result = i.imm
    return result

def getDirectTargetAndMem(inst):
    result = None
    ret_type = 0
    for i in inst.operands:
        if i.type == x86.X86_OP_IMM:
            result = i.imm
            ret_type = 1
        if i.type == x86.X86_OP_MEM:
            if i.mem.disp != 0:
                ret_type = 2
                result = i.mem.disp
    return (ret_type, result)

## TODO add more terminator instructions
###########################################################
def isIndirect(inst):
    """
    judge if the inst is a indirect jump

    args:
        inst:
        jmp: True: already judge the instruction is the jmp instruction

    rets: True of False
    """
    if inst.id == 0:
        return False

    black_list = {"rip", "RIP", "eip", "EIP"}
    if x86.X86_GRP_JUMP not in inst.groups and \
            x86.X86_GRP_CALL not in inst.groups and \
            "loop "not in inst.mnemonic.lower():
        return False

    for i in inst.operands:
        if i.type == x86.X86_OP_REG:
             reg_name = inst.reg_name(i.reg)
             if reg_name in black_list:
                 continue
             logging.debug("[indirect instruction] 0x%x:\t%s\t%s" % (inst.address, inst.mnemonic, inst.op_str))
             return True
        if i.type == x86.X86_OP_MEM:
            '''
            for jmp base[index, scale, displacement]
            '''
            if i.mem.index != 0:
                logging.debug("[indirect instruction] 0x%x:\t%s\t%s" % (inst.address, inst.mnemonic, inst.op_str))
                return True

    if 'ptr' in inst.op_str:
        logging.debug("[indirect instruction] 0x%x:\t%s\t%s" % (inst.address, inst.mnemonic, inst.op_str))
        return True

    return False
    
def instReadRegsIsTaint(inst, tainted_regs):
    (regs_read, _) = inst.regs_access()
    for r in regs_read:
        if r in tainted_regs:
            return True
    return False

# TODO: RAX and ax and al should deem as same register!
def taintRegsCrossBB(ins_lists, tainted_regs, first = False):

    # initialize the tainted_regs
    if first:
        first_inst = ins_lists[0]
        (regs_read, regs_write) = first_inst.regs_access()
        for r in regs_write:
            reg_name = first_inst.reg_name(r)
            logging.debug("[taint initialize]: reg write is %s " % (reg_name))
            if 'ip' in reg_name:
                continue
            tainted_regs.add(r)
            logging.debug("[taint initialize]: reg name is %s " % (reg_name))
        first = False
        ins_lists.pop(0)

    for inst in ins_lists:

        (regs_read, regs_write) = inst.regs_access()
        taint_read = False

        for r in regs_read:
            if r in tainted_regs:
                taint_read = True
                break

        # taint the write regs
        if taint_read:
            for r in regs_write:
                reg_name = inst.reg_name(r)
                if 'ip' in reg_name:
                    continue
                tainted_regs.add(r)
                logging.debug("[taint propogation]: reg name is %s " % reg_name)
        # clear the taint regs
        else:
            for r in regs_write:
                reg_name = inst.reg_name(r)
                if r in tainted_regs:
                    tainted_regs.remove(r)
                    logging.debug("[taint clear]: reg name is %s " % reg_name)

    logging.debug("[updated regs]: {}".format(tainted_regs))
    return tainted_regs



def isJumpTable(inst):
    """
    judge if the inst is a indirect jump

    args:
        inst:
        jmp: True: already judge the instruction is the jmp instruction

    rets: True of False
    """
    if inst.id == 0:
        return False

    black_list = {"rip", "RIP", "eip", "EIP"}
    if x86.X86_GRP_JUMP not in inst.groups and \
            x86.X86_GRP_CALL not in inst.groups and \
            "loop "not in inst.mnemonic.lower():
        return False

    for i in inst.operands:
        if i.type == x86.X86_OP_REG:
             reg_name = inst.reg_name(i.reg)
             if reg_name in black_list:
                 continue
             logging.info("[indirect instruction] 0x%x:\t%s\t%s" % (inst.address, inst.mnemonic, inst.op_str))
             return True
        if i.type == x86.X86_OP_MEM:
            '''
            for jmp base[index, scale, displacement]
            '''
            if i.mem.index != 0:
                logging.info("[indirect instruction] 0x%x:\t%s\t%s" % (inst.address, inst.mnemonic, inst.op_str))
                return True
    return False

def get_textsec_info(binary_path):
    text_sections = dict()
    with open(binary_path, 'rb') as open_file:
        elffile = ELFFile(open_file)
        for sec in elffile.iter_sections():
            if '.text' in sec.name:
                text_sections[sec.name] = (sec['sh_addr'], sec['sh_size'])
    return text_sections

'''
get loaded segments range
'''
def get_loaded_info(binary):
    loaded_segs = list()
    with open(binary, 'rb') as open_file:
        elffile = ELFFile(open_file)
        for seg in elffile.iter_segments():
            if seg['p_type'] == 'PT_LOAD':
                vaddr = seg['p_vaddr']
                size = seg['p_memsz']
                logging.debug("loaded segment: 0x%x - 0x%x" % (vaddr, vaddr + size))
                loaded_segs.append((vaddr, vaddr + size))
    return loaded_segs


"""
check if the binary is pie/pic
reference: https://stackoverflow.com/questions/53484093/check-if-pie-is-enable-in-python
"""
def isPIE(binary_path):
    with open(binary_path, 'rb') as open_file:
        elffile = ELFFile(open_file)
        base_address = next(seg for seg in elffile.iter_segments() if seg['p_type'] == "PT_LOAD")['p_vaddr']
        return elffile['e_type'] == 'ET_DYN'

