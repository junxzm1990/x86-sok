from deps import *
import sys
import optparse
import os
import logging
import traceback
import string
import random
import blocks_pb2

logging.basicConfig(level = logging.INFO)

def randomString(stringLength = 10):
    """Generate a random string of fixed length"""
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

def dumpFunc(binary, output):
    try:
        dump_tmp = randomString()
        abs_path = os.path.abspath(binary)
        basename = os.path.basename(binary)
        execute_str = 'docker run --rm -v %s:/opt/shared/%s nucleus:latest nucleus -e /opt/shared/%s -d linear \
                            | grep "function" | grep entry | cut -d "@" -f2 | cut -d " " -f1 > /tmp/%s' % (binary, basename, basename, dump_tmp)
        os.system(execute_str)

        with open("/tmp/%s" % (dump_tmp)) as func_dumps:
            module = blocks_pb2.module()
            for line in func_dumps:
                try:
                    addr = int(line, 16)
                    pb_func = module.fuc.add()
                    pb_func.va = addr
                    logging.info("Function is 0x%x" % addr)
                except:
                    pass
            f = open(output, "wb")
            f.write(module.SerializeToString())
            f.close()
        os.system('rm /tmp/%s' % dump_tmp)

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
    dumpFunc(options.binary, options.output)