from deps import *
import optparse
import logging
import blocks_pb2
from elftools.elf.elffile import ELFFile
from BlockUtil import *
import bbinfoconfig as bbl

from pwnlib.elf import elf

logging.basicConfig(level=logging.DEBUG)

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
               "__fstat",
               "call_weak_fn",
               "__udivsi3",
               "__aeabi_uidivmod",
               "__divsi3",
               ".divsi3_skip_div0_test",
               "__aeabi_idivmod",
               "__aeabi_idiv0",
               "__aeabi_ldivmod",
               "__udivmoddi4",
               "__aeabi_drsub",
               "__aeabi_dsub",
               "__adddf3",
               "__aeabi_ui2d",
               "__aeabi_i2f",
               "__aeabi_ul2f",
               "__aeabi_l2f",
               "__aeabi_i2d",
               "__aeabi_f2d",
               "__arm_set_fast_math",
               "__divsc3",
               "__mulsc3",
               "__aeabi_ul2d",
               "__aeabi_l2d",
               "__aeabi_frsub",
               "__aeabi_fsub",
               "__addsf3",
               "__aeabi_ui2f",
               "__aeabi_uldivmod",
               "hlt",
               "__start",
               "__addtf3",
               "__divtf3",
               "__multf3",
               "__floatunditf",
               # libc static
               "ns_name_pton",
               "__cxa_rethrow",
               "_Znwm",
               "__cxa_guard_abort",
               "__cxa_guard_release",
               "__cxa_throw_bad_array_new_length",
               "_ZSt7getlineIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RNSt7__cxx1112basic_stringIS4_S5_T1_EE",
               "_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC1Ev",
               "_ZNSt14basic_ifstreamIcSt11char_traitsIcEE4openEPKcSt13_Ios_Openmode",
               "_ZNSt14basic_ifstreamIcSt11char_traitsIcEED1Ev",
               "_Unwind_Resume",
               "_ZNKSt8__detail20_Prime_rehash_policy11_M_next_bktEm",
               "_ZSt24__throw_out_of_range_fmtPKcz",
               "_ZSt20__throw_length_errorPKc",
               "_ZSt17__throw_bad_allocv",
               "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6substrEmm",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructIPKcEEvT_S8_St20forward_iterator_tag",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructIPcEEvT_S7_St20forward_iterator_tag",
               "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7compareEmmPKc",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_appendEPKcm",
               "__subtf3",
               "__aeabi_d2ulz",
               "__aeabi_d2lz",
               "lstat64",
               "fstat64",
               "stat64",
               "__fixtfdi",
               "__cxx_global_var_init.8",
               "__mknod",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructEmc",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEaSERKS4_",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7reserveEm",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEpLEc",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5eraseEmm",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE14_M_replace_auxEmmmc",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE10_M_replaceEmmPKcm",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6assignEPKc",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEaSEPKc",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6appendERKS4_mm",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6appendEPKcm",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEpLEPKc"
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
    if invalid_count / len(compared.fuc) > 0.1:
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
    try:
        cur_inst = next(disasm_ins)
    except StopIteration:
        return (result, indirect_results, last_inst)

    last_inst = None
    if cur_inst != None:
        last_inst = cur_inst
        print(cur_inst.groups)
        if bbl.BB_CALL_FLAG in cur_inst.groups:
            if isIndirect(cur_inst):
                logging.debug("indirect call instruction is 0x%x" % cur_inst.address)
                indirect_result.add(cur_inst.address - disassembler_base_addr)
            else:
                logging.debug("call instruction is 0x%x" % cur_inst.address)
                result.add(cur_inst)
   

    return result, indirect_result, last_inst

def readGroundNonRet(mModule, binary):
    instructions = set()
    non_ret_edges = dict()

    open_binary = open(binary, 'rb')
    tmpFuncSet = set()

    for func in mModule.fuc:
        funcAddr = func.va
        if funcAddr not in tmpFuncSet:
            tmpFuncSet.add(funcAddr)
        else:
            logging.warning("repeated handle the function in address %x" % func.va)
            continue

        all_successors = set()
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

    return (non_ret_edges, instructions)

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

def readComparedNonRet(mModule, binary):
    non_ret_funcs = dict()
    ret_funcs = set()
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

            non_ret_site = 0x0
            if bb.type == BlockType.NON_RETURN_CALL:
                collectNonRets(non_ret_funcs, bb, last_inst)
                non_ret_site = last_inst

            for inst in call_sets:
                if inst.address == non_ret_site:
                    continue
                result = getDirectTarget(inst)
                if not result:
                    ret_funcs.add(result)
                
    return (non_ret_funcs, insts, ret_funcs)

def compareNonRetFuncs(nonret_ground, nonret_compared, neg_insts, mModule, ret_funcs):

    funcs_set_truth = dict()
    funcs_set_cmp = set()
    false_pos_candidate = set()

    for (call, target) in nonret_ground.items():
        if target not in funcs_set_truth:
            funcs_set_truth[target] = set()
        funcs_set_truth[target].add(call)

    for (call, target) in nonret_compared.items():
        funcs_set_cmp.add(target)

    funcs_set_cmp = funcs_set_cmp.union(BLACK_ADDRS)

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
    filted_funcs = ret_funcs.intersection(false_pos_candidate)

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
            v_addr = sym['st_value']
            if v_addr % 4 == 1 and arm:
                v_addr = v_addr - 1

            funcSet.add(v_addr)
            if v_addr in notIncludedLinkerFunc:
                size = sym['st_size']
                linkerExcludeFunction[v_addr] = size

        logging.info("linker exclude function is {}".format(linkerExcludeFunction))
        prev_func = None
        for func in sorted(funcSet):
            if prev_func != None and prev_func in linkerExcludeFunction:
                if not isInTextSection(prev_func):
                    # logging.info("function 0x%x not in text section!" % prev_func)
                    prev_func = func
                    continue
                if linkerExcludeFunction[prev_func] != 0:
                    # update the linker function paddings
                    end_addr = prev_func + linkerExcludeFunction[prev_func]
                    padding_size = func - prev_func - linkerExcludeFunction[prev_func]
                    # logging.info("padding size of function 0x%x is 0x%x" % (prev_func, padding_size))
                    # assert padding_size >= 0, "[getLinkerFunctionRange]: padding size < 0"
                    # if padding_size < 0x30 and padding_size > 0x0:
                    #     paddingMap[end_addr] = padding_size
                    if padding_size > 0x0:
                        linkerExcludeFunction[prev_func] += padding_size
                else:
                    linker_func_size = func - prev_func
                    # check the function size.
                    # if the size is too large, we need to comfirm it manually!
                    # assert linker_func_size > 0 and linker_func_size < 0x80, '[getLinkerFunctionRange]: linker function at 0x%x size seems unnormal, please check it manually!' % (prev_func)
                    linkerExcludeFunction[prev_func] = linker_func_size
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

def getAngrBlackAddrs(binary):
    global BLACK_ADDRS

    e = elf.ELF(binary)

    for (sym, addr) in e.plt.items():
        if sym in angr_black_plt:
            BLACK_ADDRS.add(addr)

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

    ELF_CLASS = readElfClass(options.binaryFile)
    ELF_ARCH = readElfArch(options.binaryFile)
    ELF_LITTLE_ENDIAN = readElfEndian(options.binaryFile)
    # print(ELF_LITTLE_ENDIAN)

    bbl.init(ELF_ARCH, ELF_CLASS, ELF_LITTLE_ENDIAN)

    if isAngr:
        getAngrBlackAddrs(options.binaryFile)

    readGroundTruthFuncsRange(mModule1)

    getLinkerFunctionAddr(options.binaryFile)
    not_included = checkGroundTruthFuncNotIncluded(groundTruthFuncRange, options.binaryFile)
    if not_included != None:
        logging.info("Append the not included functions! {0}".format(not_included))
        notIncludedLinkerFunc |= not_included 

    getLinkerFunctionRange(options.binaryFile)

    (non_rets_truth, gt_insts) =\
            readGroundNonRet(mModule1, options.binaryFile)

    (non_rets_comp, com_insts, ret_funcs) =\
            readComparedNonRet(mModule2, options.binaryFile)

    neg_insts = gt_insts.difference(com_insts)
    pos_insts = com_insts.difference(gt_insts)

    compareNonRetFuncs(non_rets_truth, non_rets_comp, neg_insts, mModule1, ret_funcs)
