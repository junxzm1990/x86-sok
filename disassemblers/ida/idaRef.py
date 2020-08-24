'''
environment: python3, idapro 7.4

'''
from deps import *
import idautils
import idaapi
import ida_ua
import logging
import refInf_pb2 

logging.basicConfig(format='%(levelname)s:%(message)s', level = logging.ERROR)

def is_invalid_ea(ea):
    if idc.BADADDR == ea:
        return True
    try:
        idc.get_segm_attr(idc.get_segm_start(ea), idc.SEGATTR_TYPE)
        return False
    except:
        return True

def getCandidateRefsFromInsn(decoded_insn):
    # store the candidate reference value -> op address
    result = dict()
    for op in decoded_insn.ops:
        addr_val = None
        if idc.o_imm == op.type:
            addr_val = op.value
        elif op.type in (idc.o_displ, idc.o_mem, idc.o_near):
            addr_val = op.addr
        else:
            continue
        result[addr_val] = op.offb + decoded_insn.ea
    if len(result) == 0:
        return None
    return result

def processRefs(output):
    """
    process all the xrefs that ida recognizes

    params:
        output: protobuf file path
    returns:
    """

    refInf = refInf_pb2.RefList()
    # iterate over all valid terms
    for head in idautils.Heads():
        is_code = False
        candidateRefs = None
        if idc.is_code(idc.get_full_flags(head)):
            is_code = True
            decoded_inst = ida_ua.insn_t()
            insn_len = ida_ua.decode_insn(decoded_inst, head)
            if insn_len > 0:
                candidateRefs = getCandidateRefsFromInsn(decoded_inst)
        if is_code and candidateRefs == None:
            continue

        for xref in idautils.XrefsFrom(head, 0):
            ref_from = head
            target_addr = xref.to
            # check if target_addr is in current instruction internal representation
            if is_code:
                if target_addr not in candidateRefs:
                    continue
                else:
                    ref_from = candidateRefs[target_addr]
            if is_invalid_ea(target_addr):
                continue

            logging.debug("Ref: 0x%x -> 0x%x, type is %s" % (ref_from, target_addr, idautils.XrefTypeName(xref.type)))
            ref = refInf.ref.add()
            ref.ref_va = ref_from
            ref.target_va = target_addr
            # default value
            ref.ref_size = 8
            target_is_code = idc.is_code(idc.get_full_flags(target_addr))
            if is_code and target_is_code:
                ref.kind = 0 # c2c
            elif is_code and not target_is_code:
                ref.kind = 1 # c2d
            elif not is_code and target_is_code:
                ref.kind = 2 # d2c
            else:
                ref.kind = 3 # d2d

    
    ## save the protobuf result
    with open(output, 'wb') as pbOut:
        pbOut.write(refInf.SerializeToString())

def get_output_file():
    current_file = idaapi.get_input_file_path()
    current_dir = os.path.dirname(current_file)
    current_base = os.path.basename(current_file)
    output_file = os.path.join(current_dir, "Block-idaRef-" + current_base + ".pb")
    return output_file


if __name__ == '__main__':
    logging.debug("current INF_AF flag is %x" % (idc.get_inf_attr(idc.INF_AF)))
    logging.debug("current INF_AF1 flag is %x" % (idc.get_inf_attr(idc.INF_AF2)))
    idaapi.auto_wait()
    output_file = get_output_file()
    print("output file name is %s" % output_file)
    processRefs(output_file)
    idc.process_config_line("ABANDON_DATABASE=YES")
    idc.qexit(0)
