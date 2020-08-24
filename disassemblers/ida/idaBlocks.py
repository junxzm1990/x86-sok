from deps import *
import idautils
import idaapi
import ida_ua
import logging
import sys
import os
import blocks_pb2 

logging.basicConfig(level = logging.ERROR)

# Maps instruction EAs to a pair of decoded inst, and the bytes of the inst.
# reference https://github.com/trailofbits/mcsema/blob/master/tools/mcsema_disass/ida7/x86_util.py
PREFIX_ITYPES = (idaapi.NN_lock, idaapi.NN_rep,
                         idaapi.NN_repe, idaapi.NN_repne)

def isValidBlock(bb):
    ## There may happen when bb.endEA == bb.startEA in IDA pro
    if bb.end_ea > bb.start_ea:
        return True
    return False

def processFunctionsAndBlocks(output):
    """
    process all the functions and their basic blocks that ida recognizes

    params:
        output: protobuf file path
    returns:
    """
    functions = set()
    module = blocks_pb2.module()
    insts = set()
    ## FIXME some basic blocks that ida identified may don't belong to any function
    for func in idautils.Functions():

        if func in functions:
            continue
        functions.add(func)

        pbFunc = module.fuc.add()
        pbFunc.va = func
        ## Get all the basic blocks that in specific function func
        blocks = idaapi.FlowChart(idaapi.get_func(func))
        for idx, block in enumerate(blocks):
            if isValidBlock(block) == False:
                continue
            bb = pbFunc.bb.add()
            bb.va = block.start_ea
            bb.parent = func
            bb.size = (block.end_ea - block.start_ea)
            logging.debug("block#%d: 0x%x to 0x%x" % (idx, block.start_ea, block.end_ea))

            if block.type == idaapi.fcb_noret:
                logging.debug("block: 0x%x no ret" % (bb.va))
                bb.type = 0x20
            
            ## iterater the successors
            for succ in block.succs():
                if isValidBlock(succ) == False:
                    continue
                child = bb.child.add()
                child.va = succ.start_ea
	    
	    ## iterater its instructions
            inst_idx = 0
            for head in idautils.Heads(block.start_ea, block.end_ea):
                if head == idc.BADADDR:
                    logging.error("HEAD %x is not instrction!" % (head))
                    continue
                if idc.is_code(idc.get_full_flags(head)):
                    insts.add(head)
                    decoded_inst = ida_ua.insn_t()
                    inslen = ida_ua.decode_insn(decoded_inst, head)
                    if inslen <= 0:
                        continue
                    assert decoded_inst.ea == head 
                    instruction = bb.instructions.add()
                    instruction.va = head
                    instruction.size = decoded_inst.size
                    logging.debug("inst#%d: 0x%x to 0x%x" % (inst_idx, head, head + instruction.size - 1))
                    inst_idx += 1
    
    ## save the protobuf result
    with open(output, 'wb') as pbOut:
        pbOut.write(module.SerializeToString())
'''
def decode_instruction(ea):
    decoded_inst = ida_ua.insn_t()
    inslen = ida_ua.decode_insn(decoded_inst, ea)
    if inslen <= 0:
        return None
    assert decoded_inst.ea == ea
    end_ea = ea + decoded_inst.size
    decoded_bytes = read_bytes_slowly(ea, end_ea)
    if 1 == decoded_inst.size and decoded_inst.itype in PREFIX_ITYPES:
        decoded_inst, extra_bytes = decode_instruction(end_ea)
        decoded_bytes += extra_bytes
    return decoded_inst, decoded_bytes

def read_bytes_slowly(start, end):
    bytestr = []
    for i in xrange(start, end):
        if idc.has_value(idc.get_full_flags(i)):
            bt = idc.get_wide_byte(i)
            bytestr.append(chr(bt))
        else:
            bytestr.append("\x00")
    return "".join(bytestr)
'''
        

def get_output_file():
    current_file = idaapi.get_input_file_path()
    current_dir = os.path.dirname(current_file)
    current_base = os.path.basename(current_file)
    output_file = os.path.join(current_dir, "Block-idaBlocks-" + current_base + ".pb")
    return output_file


if __name__ == '__main__':
    idaapi.auto_wait()
    output_file = get_output_file()
    print("output file name is %s" % output_file)
    processFunctionsAndBlocks(output_file)
    idc.process_config_line("ABANDON_DATABASE=YES")
    idc.qexit(0)
