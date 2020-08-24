"""
file: objdumpBlocks.py

Get instruction address from objdump
"""
from deps import *
import logging
import sys
import optparse
import os
import traceback
import blocks_pb2
import random
import string

def randomString(stringLength=10):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

logging.basicConfig(level=logging.INFO)
def dumpInsts(binary, output):
    try:
        output_tmp = randomString()
        execute_str = "objdump --wide -d %s | egrep '^[[:space:]]*[0-9a-f]+:' | cut -d: -f1 | awk '{print \"0x\"$1}' | tee /tmp/%s.log" % (binary, output_tmp)
        print(execute_str)
        os.system(execute_str)
        with open("/tmp/%s.log" % (output_tmp)) as objdump_file:
            module = blocks_pb2.module()
            # because objdump doesn't have function and basic block if the binary is striped
            dummy_func = module.fuc.add()
            dummy_func.va = 0x0
            dummy_bb = dummy_func.bb.add()
            dummy_bb.va = 0x0
            dummy_bb.parent = 0x0
            for line in objdump_file:
                line = line.strip()
                addr = int(line, 16)
                instruction = dummy_bb.instructions.add()
                instruction.va = addr
            f = open(output, "wb")
            f.write(module.SerializeToString())
            f.close()
    except Exception as e:
        traceback.print_exc()
        return

    os.system("rm -f /tmp/%s.log" % (output_tmp))

if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("-o", "--output", dest = "output", action= "store", type = "string", \
            help = "output of the protobuf file", default = "/tmp/objdump_inst.pb2") 
    parser.add_option("-b", "--binary", dest = "binary", action = "store", type = "string", \
            help = "binary file", default = None)
    (options, args) = parser.parse_args()
    if options.binary == None:
        print("please input the binary file")
        exit(-1)
    dumpInsts(options.binary, options.output)
