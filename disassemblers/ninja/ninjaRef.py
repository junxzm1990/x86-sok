from deps import *
import sys
import binaryninja as binja
from binaryninja import core_version
import optparse
import os
import logging

from binaryninja.enums import LowLevelILOperation

import refInf_pb2 
import re

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

pattern = re.compile(r'([0-9a-f]+)')

def init_ref(ref, from_addr, to_addr, kind):
    ref.ref_va = from_addr
    ref.target_va = to_addr
    ref.kind = kind
    ref.ref_size = 8

# store the virtual address -> LLIL list
ADDR2LLIL = dict()
IGNORED_OPS = (LowLevelILOperation.LLIL_UNIMPL,
                          LowLevelILOperation.LLIL_UNIMPL_MEM,
                          LowLevelILOperation.LLIL_UNDEF)

LOAD_STORE = (LowLevelILOperation.LLIL_LOAD,
                        LowLevelILOperation.LLIL_STORE)

def handleILBB(bb):
    if bb.start in ADDR2LLIL:
        return
    for il in bb:
        if il.address in ADDR2LLIL:
            ADDR2LLIL[il.address].append(il)
        else:
            ADDR2LLIL[il.address] = list()
            ADDR2LLIL[il.address].append(il)

def getLLILFromAddr(addr):
    return ADDR2LLIL.get(addr, None)

def getCandidateRefsRecursive(il, result):
    if isinstance(il, int):
        result.add(il)
        return
    if not isinstance(il, binja.LowLevelILInstruction):
        return
    if il.operation in IGNORED_OPS:
        return
    if il.operation in LOAD_STORE:
        mem_il = il.src if il.operation == LowLevelILOperation.LLIL_LOAD else il.dest
        getCandidateRefsRecursive(mem_il, result)
    elif il.operation == LowLevelILOperation.LLIL_CONST_PTR:
        result.add(il.constant)

    for oper in il.operands:
        getCandidateRefsRecursive(oper, result)

def getCandidateRefs(ils):
    result = set()
    for il in ils:
        getCandidateRefsRecursive(il, result)
    
    return None if len(result) == 0 else result

def getCandidateRefsFromInsn(ins):
    result = set()
    m = pattern.findall(ins)
    for op in m:
        try:
            addr = int(op, 16)
            result.add(addr)
        except:
            continue
    if len(result) == 0:
        return None
    return result

def dumpRefs(bv, output):
    refInf = refInf_pb2.RefList()
    for (func_idx, func) in enumerate(bv.functions):
        indirect_branches = func.indirect_branches
        indirect_source = set()
        for branch in indirect_branches:
            if branch.source_addr in indirect_source:
                continue
            indirect_source.add(branch.source_addr)
        for ins in func.instructions:
            cur_addr = ins[1]
            for cref in bv.get_code_refs(cur_addr):
                ref_from = cref.address
                #il = cref.function.get_low_level_il_at(ref_from)
                #if il == None:
                #    continue
                #handleILBB(il.il_basic_block)
                #ils = getLLILFromAddr(ref_from)
                #if ils == None:
                #    logging.error("cref from address 0x%x does not have corresponding ils" % (ref_from))
                #    continue
                #candidateRefs = getCandidateRefs(ils)
                ref_from_ins = bv.get_disassembly(ref_from)
                candidateRefs = getCandidateRefsFromInsn(ref_from_ins)
                if candidateRefs == None:
                    logging.warning("cref from address 0x%x is not a fixup." % (ref_from))
                    continue
                if cur_addr not in candidateRefs:
                    continue
                ref = refInf.ref.add()
                # c2c
                init_ref(ref, ref_from, cur_addr, 0)
                logging.info("[Code Ref]: 0x%x -> 0x%x" % (ref_from , cur_addr))
            for dref in bv.get_data_refs(cur_addr):
                ref_from = dref

                ref = refInf.ref.add()
                # d2c
                init_ref(ref, ref_from, cur_addr, 2)
                logging.info("[Data Ref]: 0x%x -> 0x%x" % (ref_from , cur_addr))
            prev_addr = cur_addr

    # TODO(there is no jump table references)
    for sec in bv.sections.values():
        if sec.name == '.text':
            continue
        for cur_addr in range(sec.start, sec.end):
            for cref in bv.get_code_refs(cur_addr):
                ref_from = cref.address
                #il = cref.function.get_low_level_il_at(ref_from)
                #if il == None:
                #    continue
                #handleILBB(il.il_basic_block)
                #ils = getLLILFromAddr(ref_from)
                #if ils == None:
                #    logging.error("cref from address 0x%x does not have corresponding ils" % (ref_from))
                #    continue
                ref_from_ins = bv.get_disassembly(ref_from)
                candidateRefs = getCandidateRefsFromInsn(ref_from_ins)
                if candidateRefs == None:
                    logging.warning("cref from address 0x%x is not a fixup." % (ref_from))
                    continue
                if cur_addr not in candidateRefs:
                    continue
                ref = refInf.ref.add()
                # c2d
                init_ref(ref, ref_from, cur_addr, 1)
                logging.info("[code Ref]: 0x%x -> 0x%x" % (ref_from , cur_addr))
            for dref in bv.get_data_refs(cur_addr):
                ref_from = dref
                ref = refInf.ref.add()
                # d2d
                init_ref(ref, ref_from, cur_addr, 3)
                logging.info("[data Ref]: 0x%x -> 0x%x" % (ref_from , cur_addr))
    pbout = open(output, 'wb')
    pbout.write(refInf.SerializeToString())
    pbout.close()

if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("-o", "--output", dest = "output", action= "store", type = "string", \
            help = "output of the protobuf file", default = "/tmp/angr_blocks.pb2") 
    parser.add_option("-b", "--binary", dest = "binary", action = "store", type = "string", \
            help = "binary file", default = None)
    parser.add_option("-s", "--ss", dest = "ss", action = "store", type = "string", \
            help = "dummy option. (do not use)", default = None)
    (options, args) = parser.parse_args()
    if options.binary == None:
        binja.log_info("please input the binary file")
        exit(-1)

    bv = binja.BinaryViewType.get_view_of_file(options.binary)
    #binja.log_to_stdout(binja.LogLevel.DebugLog)
    binja.log_to_stdout(binja.LogLevel.ErrorLog)
    #binja.log_info("----------------- %s ------------" % options.binary)
    binja.log_info("START: 0x%x" % bv.start)
    binja.log_info("ENTRY: 0x%x" % bv.entry_point)
    binja.log_info("ARCH: %s" % bv.arch.name)
    logging.info("version: %s" % core_version())
    binja.log_info("\n--------------- Function List -----------")
    #bv.update_analysis_and_wait()
    dumpRefs(bv, options.output)
