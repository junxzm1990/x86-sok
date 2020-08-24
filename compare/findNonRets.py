'''
This file finds all non-return functions


we use the algorithm similar to BAP(with-no-return pass) based on
our known non-return functions and and non-return functions provided by compiler. 
'''

from deps import *

from NoRetStruct import *
from BlockUtil import *
from pwnlib.elf import elf
import blocks_pb2
import optparse
import logging
from PEUtil import *
import pepy

logging.basicConfig(level = logging.INFO)
CYCLIC_THRESHOLD = 100

IS_PE = False
textSize = 0x0
textAddr = 0x0
textOffset = 0x0

ELFCLASS = 64

PE_IMAGE_BASE = 0x0
PE_SECS = None

# conditional non-return, we can't handle it yet
Black_LIST = {"error", "_gfortran_st_write_done"}
Black_ADDRS = set()

KNOWN_NON_RETS = {"exit", "abort", "__f90_stop", "fancy_abort", "__stack_chk_fail",
        "__assert_fail", "ExitProcess", "_ZSt17__throw_bad_allocv", 
        "_ZSt20__throw_length_errorPKc", "_Unwind_Resume", "longjmp", "__longjmp", 
        "siglongjmp", "_ZSt16__throw_bad_castv", "_ZSt19__throw_logic_errorPKc", 
        "_ZSt20__throw_out_of_rangePKc", "__cxa_rethrow", "__cxa_throw", 
        "_ZSt21__throw_runtime_errorPKc", "_ZSt9terminatev", "_gfortran_os_error",
        "_gfortran_runtime_error", "_gfortran_stop_numeric", "_gfortran_runtime_error_at",
        "_gfortran_stop_string", "_gfortran_abort", "_gfortran_exit_i8", 
        "_gfortran_exit_i4", "for_stop_core", "__sys_exit", "_Exit", "ExitThread", "FatalExit", "RaiseException", "RtlRaiseException",
        "TerminateProcess" 
        }

def parseDirectCall(MD, content, va, call_type):
    disasm_ins = MD.disasm(content, va)

    try:
        cur_inst = next(disasm_ins)
    except StopIteration:
        return None

    if x86.X86_GRP_CALL not in cur_inst.groups:
        return None

    if call_type == 1 and isIndirect(cur_inst):
        return None

    return getDirectTarget(cur_inst)

def is_direct_call_type(inst):
    if not IS_PE:
        return inst.call_type == 0x3

    offset = get_file_offset(PE_SECS, inst.address, PE_IMAGE_BASE)



def reconstructStructs(mModule, known_non_rets, binary):
    visited = set()

    bb_map = dict()
    func_map = dict()
    called_edges = dict()
    contains_terminate_funcs = set()

    open_binary = open(binary, 'rb')
    content = open_binary.read()
    content_len = len(content)

    MD = init_capstone(ELFCLASS)

    # first step, collect all non-return functions based on compiler
    for func in mModule.fuc:

        if func.va in visited:
            continue

        visited.add(func.va)

        for bb in func.bb:
            if bb.type == BlockType.NON_RETURN_CALL:
                if bb.child[0].va in Black_ADDRS:
                    continue
                logging.debug("adding non-return from compiler. 0x%x" % bb.child[0].va)
                known_non_rets.add(bb.child[0].va)

    # second step: reconstruct basicblocks struct
    visited.clear()
    for func in mModule.fuc:
        
        if func.va in visited:
            continue
        visited.add(func.va)

        if func.va in known_non_rets:
            continue

        root_bb = None

        for bb in func.bb:
            if bb.va == func.va:
                root_bb = bb.va
                break

        if not root_bb:
            logging.warning("Function %s can't find root bb!" % func.va)
            continue

        cur_func = Function(func.va, RetStatus.UNKNOWN, func)
        func_map[func.va] = cur_func

        for bb in func.bb:
            cons_bb = BasicBlock(bb.va, func.va, bb)

            if bb.terminate:
                logging.debug("Terminate bb at 0x%x" % bb.va)
                contains_terminate_funcs.add(cur_func)
                cons_bb.setTerminate()

            if bb.va == root_bb:
                cur_func.root = cons_bb

            cons_bb.setType(bb.type)

            for inst in bb.instructions:
                # collect all direct call targets
                # do not consider the indirect call
                # as we do not have the indirect call targets
                if inst.call_type != 1 and inst.call_type != 3:
                    continue

                offset = getOffset(inst.va)
                end_offset = offset + inst.size
                target = parseDirectCall(MD, content[offset: end_offset], inst.va, inst.call_type)

                if not target:
                    continue

                if target not in called_edges:
                    called_edges[target] = list()

                called_edges[target].append(cur_func)

                logging.debug("call instruction is 0x%x -> 0x%x" % (inst.va, target))
                cons_bb.addCalledFunc((inst.va, target))

            bb_map[bb.va] = cons_bb

            exclude_target = -1

            if bb.type in {BlockType.DIRECT_CALL, BlockType.TAIL_CALL}:
                max_dis = -1
                for suc in bb.child:
                    if abs(suc.va - bb.va) > max_dis:
                        exclude_target = suc.va
                        max_dis = abs(suc.va - bb.va)

            if bb.type == BlockType.TAIL_CALL:
                cons_bb.addCalledFunc((bb.instructions[-1].va, exclude_target))
                if exclude_target not in called_edges:
                    called_edges[exclude_target] = list()
                logging.debug("This is tail call! 0x%x -> 0x%x" % (bb.instructions[-1].va, exclude_target))
                called_edges[exclude_target].append(cur_func)

            for suc in bb.child:
                if suc.va == exclude_target:
                    continue
                cons_bb.addSuc(suc.va)
    return (func_map, bb_map, called_edges, contains_terminate_funcs)

def getNonRetFuncsFromImportObjs(binary, known_non_ret):
    p = pepy.parse(binary)
    for iobj in p.get_imports():
        if iobj.sym in KNOWN_NON_RETS:
            logging.debug("Adding known non-ret %s at 0x%x" % (iobj.sym, iobj.addr))
            known_non_ret.add(iobj.addr)

def getNonRetFuncsFromSymbols(binary, known_non_ret):
    global Black_ADDRS
    e = elf.ELF(binary)
    for (sym, addr) in e.symbols.items():
        if sym in KNOWN_NON_RETS:
            logging.debug("Adding known non-ret %s at 0x%x" % (sym, addr))
            known_non_ret.add(sym)
        if sym in Black_LIST:
            Black_ADDRS.add(addr)

    for (sym, addr) in e.plt.items():
        if sym in KNOWN_NON_RETS:
            logging.debug("Adding known non-ret %s at 0x%x" % (sym, addr))

        if sym in Black_LIST:
            Black_ADDRS.add(addr)

def getOffset(inst_va):
    if not IS_PE:
        return inst_va - textAddr + textOffset

    # PEFILE
    return get_file_offset(PE_SECS, inst_va, PE_IMAGE_BASE)

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

def getCallerFuncs(called_edges, non_ret_funcs):
    to_handle = set()
    for func_addr in non_ret_funcs:
        all_callers = called_edges.get(func_addr, None)
        if all_callers:
            [to_handle.add(caller) for caller in all_callers]
    return to_handle

def recursivelyFindNonRets(added_noret_funcs, func, \
        func_map, bb_map, known_nonret_funcs, visited_funcs, func_cnt):

    # iterate all path from start node to exit node
    queue = list()
    visited_bb = set()
    queue.append(func.root)
    noret = True

    func_cnt[func.va] = func_cnt[func.va] + 1 if func.va in func_cnt else  1

    visited_funcs.add(func.va)
    logging.debug("recursively find nonret function 0x%x" % func.va)
    cyclic_dep = False

    while len(queue) != 0:
        cur_bb = queue.pop(-1)
        if cur_bb.va in visited_bb:
            continue
        visited_bb.add(cur_bb.va)
        

        isExitNode = True if len(cur_bb.successors_addr) == 0 else False
        cur_called_funcs = cur_bb.called_funcs

        has_called_non_ret = False
        # quickly check
        if cur_bb.type == BlockType.NON_RETURN_CALL or cur_bb.terminate == True:
            continue

        # check every called function if they are non-return function
        for (cur_addr, called_func_addr) in cur_called_funcs:
            # call a non-return function
            if called_func_addr in known_nonret_funcs:
                logging.debug("cur address is 0x%x, call a non return 0x%x" % (cur_addr, called_func_addr))
                has_called_non_ret = True
                break

            # this path has contains func.va, skip
            # there exists cyclic dependency
            if called_func_addr in visited_funcs:
                cyclic_dep = True
                continue

            called_func = func_map.get(called_func_addr, None)
            # deems it can return
            if not called_func:
                continue

            if called_func.status == RetStatus.UNKNOWN:
                (cy_dep, has_called_non_ret) = recursivelyFindNonRets(added_noret_funcs, called_func, func_map, \
                        bb_map, known_nonret_funcs, visited_funcs, func_cnt)

                if cy_dep:
                    cyclic_dep = cy_dep

                if has_called_non_ret:
                    break

        logging.debug("current basic block is 0x%x, called non-return function %d, is exitnode %d" % 
                (cur_bb.va, has_called_non_ret, isExitNode))
        

        # it can return
        if isExitNode and (not has_called_non_ret or len(cur_called_funcs) == 0): 
            noret = False
            break


        # this basic block has called a non-return function
        if has_called_non_ret:
            if not (cur_bb.type == BlockType.TAIL_CALL and len(cur_bb.successors_addr) > 0):
                continue

        if has_called_non_ret:
           cur_bb.type = BlockType.NON_RETURN_CALL

        for suc in cur_bb.successors_addr:
            bb = bb_map.get(suc, None)

            if not bb:
                successor_addr = cur_bb.bb.size + cur_bb.bb.va + cur_bb.bb.padding
                if successor_addr - suc < 0x10:
                    bb = bb_map.get(successor_addr, None)
                    # we can't find the successor, deems it as Return
                    if not bb:
                        func.setStatus(RetStatus.RET)
                        return(cyclic_dep, False)

            if not bb:
                return(cyclic_dep, False)

            # tail call
            if bb.va in known_nonret_funcs:
                continue
            if bb.va in visited_bb:
                continue
            logging.debug("append to queue 0x%x" % bb.va)
            queue.append(bb)

    if noret:
        added_noret_funcs.add(func.va)
        func.setStatus(RetStatus.NORET)
        logging.debug("Find non-return function at 0x%x" % func.va)
    
    # this function is certainly RETURN
    # or it has cyclic dependency and readches the THRESHOLD
    elif not cyclic_dep or func_cnt[func.va] > CYCLIC_THRESHOLD:
        func.setStatus(RetStatus.RET)
        return (cyclic_dep, False)

    return (cyclic_dep, noret)


def findNonRets(func_map, bb_map, called_edges, known_nonret_funcs, contains_terminate_funcs):
    to_handle = getCallerFuncs(called_edges, known_nonret_funcs)
    to_handle = to_handle.union(contains_terminate_funcs)
    # record the count that recursively handling this function
    # if the function is handled toooo many times,
    # it may meet cyclic dependency
    func_cnt = dict()
    all_added_funcs = set()
    while True:
        added_noret_funcs = set()
        for func in to_handle:

            if not func:
                continue
            func_addr = func.va
            logging.debug("to handle function is 0x%x" % func_addr)
            if func_addr in known_nonret_funcs:
                continue

            # we already known this function's status
            if not func or func.status != RetStatus.UNKNOWN:
                continue

            recursivelyFindNonRets(added_noret_funcs, func, func_map, bb_map, known_nonret_funcs, set(), func_cnt)

            known_nonret_funcs = known_nonret_funcs.union(added_noret_funcs)
            all_added_funcs = all_added_funcs.union(added_noret_funcs)


        # reaches balance, no new added non-return functions
        if len(added_noret_funcs) == 0:
            break

        to_handle = getCallerFuncs(called_edges, added_noret_funcs)

    called_funcs = set()
    [called_funcs.add(cur_target) for (cur_target, _) in called_edges.items()]
    logging.debug("called function length is %d" % len(called_funcs))
    valid_nonret_funcs = called_funcs.intersection(all_added_funcs)

    logging.info("Summary: appended function number is %d" % len(all_added_funcs))
    logging.info("Summary: valid non-ret function number is %d" % len(valid_nonret_funcs))
    for func in valid_nonret_funcs:
        logging.info("Newly found non-ret function is 0x%x" % func)

    return (valid_nonret_funcs, all_added_funcs)


def rewriteGroundTruth(valid_nonret_funcs, output, module, called_edges, bb_map):

    for func in valid_nonret_funcs:
        cur_edges = called_edges.get(func, None)
        if not cur_edges:
            continue

        for caller_func in cur_edges:
            func_pb = caller_func.func

            #iterate over all basic block
            for bb_pb in func_pb.bb:
                cur_bb = bb_map.get(bb_pb.va, None)
                if not cur_bb:
                    continue

                # rewrite the protobuf bb's type
                for (inst_va, called_func) in cur_bb.called_funcs:
                    # alright we found it
                    if called_func in valid_nonret_funcs:
                        # split the basic block
                        inst_cnt = 0
                        for instr in cur_bb.bb.instructions:
                            inst_cnt += 1
                            # alright, we found it
                            if instr.va == inst_va:
                                del cur_bb.bb.instructions[inst_cnt:]
                        del cur_bb.bb.child[:]
                        logging.debug("Rewrite the basic block 0x%x, call a non-ret function 0x%x" % (cur_bb.bb.va, called_func))
                        cur_bb.bb.type = BlockType.NON_RETURN_CALL
                        cur_child = cur_bb.bb.child.add()
                        cur_child.va = called_func

                # TODO. rewrite the whole cfg

    with open(output, 'wb') as output_pb:
        output_pb.write(module.SerializeToString())


def init_elf(binary):
    global ELFCLASS
    readTextSection(binary)
    ELFCLASS = readElfClass(options.binaryfile)

def init_pe(binary):
    global ELFCLASS
    global PE_IMAGE_BASE
    global PE_SECS
    PE_SECS = parsePEExecSecs(binary)
    (PE_IMAGE_BASE, ELFCLASS) = parsePEFile(binary)

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option('-g', '--groundtruth', dest = 'groundtruth', action = 'store', \
            type = 'string', help = 'find other non ret functions', default = None)
    parser.add_option('-b', '--binaryfile', dest = 'binaryfile', action = 'store', \
            type = 'string', help = 'binary file path', default = None)
    parser.add_option('-o', '--output', dest = 'output', action = 'store', \
            type = 'string', help = 'output file', default = '/tmp/gtBlock_noret.pb')
    parser.add_option('-p', '--ispe', dest = 'ispe', action = 'store_true', \
            help = 'is pe file', default = False)

    (options, args) = parser.parse_args()
    assert options.groundtruth != None, "Please input the ground truth file"
    assert options.binaryfile != None, "Please input the binary file"

    if options.ispe:
        IS_PE = True

    if not IS_PE:
        init_elf(options.binaryfile)
    else:
        init_pe(options.binaryfile)

    module = blocks_pb2.module()
    try:
        f1 = open(options.groundtruth, 'rb')
        module.ParseFromString(f1.read())
        f1.close()
    except IOError:
        logging.error("Could not open the file %s" % options.groundtruth)
        exit(-1)

    known_nonret_funcs = set()

    if not IS_PE:
        getNonRetFuncsFromSymbols(options.binaryfile, known_nonret_funcs)
    else:
        getNonRetFuncsFromImportObjs(options.binaryfile, known_nonret_funcs)

    (func_map, bb_map, called_edges, contains_terminate_funcs) = \
            reconstructStructs(module, known_nonret_funcs, options.binaryfile)

    (valid_nonret_funcs, all_added_funcs) = findNonRets(func_map, bb_map, called_edges, known_nonret_funcs, contains_terminate_funcs)

    rewriteGroundTruth(valid_nonret_funcs, options.output, module, called_edges, bb_map)

    #TODO. add all non return fuctions to ground truth
