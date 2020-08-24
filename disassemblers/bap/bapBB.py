from deps import *
import sys
import optparse
import os
import traceback
import blocks_pb2
import random
import string
import logging

logging.basicConfig(level=logging.INFO)
def randomString(stringLength = 10):
    """Generate a random string of fixed length"""
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

logging.basicConfig(level=logging.INFO)
def dumpBB(binary, output):
    # store the cfg edge.
    cfg_edge = dict()
    non_ret_sites = set()
    try:
        dump_tmp = randomString()
        abs_path = os.path.abspath(binary)
        basename = os.path.basename(binary)
        execute_str = "bap %s -d -drcfg -dasm --passes=with-no-return --print-bir-attr=address > /tmp/%s.dump" % (abs_path, dump_tmp)
        logging.info("execute string is %s" % (execute_str))
        os.system(execute_str)
        
        ## collect all non-ret call sites
        non_ret_tmp = randomString()
        execute_str1 = 'grep "address\|call @.* with noreturn" /tmp/%s.dump > /tmp/%s.log' % (dump_tmp, non_ret_tmp)
        os.system(execute_str1)
        valid_address = -1
        with open("/tmp/%s.log" % (non_ret_tmp), "r") as non_ret_file:
            for line in non_ret_file:
                if 'address' in line:
                    try:
                        valid_address = int(line.split(' ')[-1].strip(), 16)
                        continue
                    except:
                        pass
                if 'noreturn' in line and valid_address != -1:
                    logging.debug('collect noret site %x' % valid_address)
                    non_ret_sites.add(valid_address)
                    valid_address = -1


        grep_cfg_tmp = randomString()
        execute_str2 = 'grep -e "->" /tmp/%s.dump | tr -s " " | cut -d \\" -f2,4 | awk "{print $1 $2}" > /tmp/%s.log' % (dump_tmp, grep_cfg_tmp)
        os.system(execute_str2)
        logging.info("excute string is %s" % (execute_str2))
        with open("/tmp/%s.log" % (grep_cfg_tmp), "r") as grep_cfg_file:
            for line in grep_cfg_file:
                line = line.split('"')
                start = int(line[0], 16)
                end = int(line[1], 16)
                logging.info("edge 0x%x -> 0x%x" % (start, end))
                if start in cfg_edge:
                    cfg_edge[start].add(end)
                else:
                    tmp_set = set()
                    tmp_set.add(end)
                    cfg_edge[start] = tmp_set
        os.system('rm /tmp/%s.log' % (grep_cfg_tmp))
        os.system('rm /tmp/%s.log' % (non_ret_tmp))
    except Exception as e:
        traceback.print_exc()
        return

    # get the function and basic block information
    try:
        #bb_dump_tmp = randomString()
        #execute_str3 = "bap %s -dasm > /tmp/%s.dump" % (binary, bb_dump_tmp)
        #logging.info("execute string is %s" % (execute_str3))
        #os.system(execute_str3)
        grep_bb_tmp = randomString()
        execute_str4 = 'sed -ne "/Disassembly of/,$ p" /tmp/%s.dump | egrep "^[[:space:]]*[0-9a-f]+:" | cut -d : -f1 | awk "{print $1}" > /tmp/%s.log' % (dump_tmp, grep_bb_tmp)
        logging.info("execute string is %s" % (execute_str4))
        os.system(execute_str4)
        last_last_inst_addr = None
        last_inst_addr = None
        cur_inst_addr = None
        last_func_addr = None
        last_bb_addr = None
        pb_cur_func = None
        pb_cur_bb = None

        with open("/tmp/%s.log" % (grep_bb_tmp), "r") as grep_bb_file:
            module = blocks_pb2.module()
            for line in grep_bb_file:
                cur_inst_addr = int(line.strip(), 16)
                if cur_inst_addr == last_inst_addr:
                    # find the new function
                    if last_inst_addr == last_last_inst_addr:
                        logging.info("current function addr 0x%x" % (cur_inst_addr))
                        # delete the last function's last basic block
                        if pb_cur_func != None:
                            del pb_cur_func.bb[-1]
                        pb_cur_func = module.fuc.add()
                        pb_cur_func.va = cur_inst_addr

                        # WARNING: the result lacks of basic block size
                        pb_cur_bb = pb_cur_func.bb.add()
                        pb_cur_bb.va = cur_inst_addr
                        pb_cur_bb.parent = pb_cur_func.va

                        # add the current basic block successors
                        # WARNING: the successors does not contain the `call` instruction target
                        successors = set() 
                        if cur_inst_addr in cfg_edge:
                            successors = cfg_edge[cur_inst_addr]
                        for suc in successors:
                            child = pb_cur_bb.child.add()
                            child.va = suc
                        instruction = pb_cur_bb.instructions.add()
                        instruction.va = cur_inst_addr
                        if cur_inst_addr in non_ret_sites:
                            instruction.call_type = 4 # call a non-return
                            logging.debug("set non-return instruction at 0x%x, call_type is 0x%x" % (instruction.va, instruction.call_type))


                    elif pb_cur_func != None: # find the new basic block
                        if pb_cur_bb != None:
                            del pb_cur_bb.instructions[-1]

                        logging.info("current basic block addr 0x%x" % (cur_inst_addr))
                        # WARNING: the result lacks of basic block size
                        pb_cur_bb = pb_cur_func.bb.add()
                        pb_cur_bb.va = cur_inst_addr
                        pb_cur_bb.parent = pb_cur_func.va
                        # add the current basic block successors
                        # WARNING: the successors does not contain the `call` instruction target
                        successors = set() 
                        if cur_inst_addr in cfg_edge:
                            successors = cfg_edge[cur_inst_addr]
                        for suc in successors:
                            child = pb_cur_bb.child.add()
                            child.va = suc
                        instruction = pb_cur_bb.instructions.add()
                        instruction.va = cur_inst_addr

                        if cur_inst_addr in non_ret_sites:
                            instruction.call_type = 4 # call a non-return
                            logging.debug("set non-return instruction at 0x%x, call_type is 0x%x" % (instruction.va, instruction.call_type))

                # current instruction
                elif pb_cur_bb != None:
                    # WARNING: the result lacks of basic block size
                    logging.info("current instruction addr 0x%x" % (cur_inst_addr))
                    instruction = pb_cur_bb.instructions.add()
                    instruction.va = cur_inst_addr

                    # set current bb type
                    if cur_inst_addr in non_ret_sites:
                        instruction.call_type = 4 # call a non-return

                last_last_inst_addr = last_inst_addr
                last_inst_addr = cur_inst_addr
            f = open(output, "wb")
            f.write(module.SerializeToString())
            f.close()

        os.system('rm /tmp/%s.dump' % (dump_tmp))
        os.system('rm /tmp/%s.log' % (grep_bb_tmp))
    except Exception as e:
        traceback.print_exc()
        return

if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("-o", "--output", dest = "output", action= "store", type = "string", \
            help = "output of the protobuf file", default = "/tmp/objdump_inst.pb2") 
    parser.add_option("-b", "--binary", dest = "binary", action = "store", type = "string", \
            help = "binary file", default = None)
    parser.add_option("-s", "--statics", dest = "statics", action= "store", type = "string", \
            help = "store statics or not", default = "/tmp/bap_statics.log") 
    (options, args) = parser.parse_args()
    if options.binary == None:
        print("please input the binary file")
        exit(-1)
    dumpBB(options.binary, options.output)
