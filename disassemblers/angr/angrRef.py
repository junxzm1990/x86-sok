from deps import *
import angr
import logging
import sys
import optparse
import os
import refInf_pb2

logging.getLogger('angr.analyses').setLevel(logging.ERROR)
from multiprocessing import Process
ref_cnt = 0
def extract(p, refInf):
    global ref_cnt
    reassembler = p.analyses.Reassembler()
    for (i, rel) in enumerate(reassembler.relocations):
        ref_cnt += 1
        ref = refInf.ref.add()
        ref.ref_va = rel.addr
        ref.target_va = rel.ref_addr
        ref.ref_size = 8
        # TODO(Get the kind)
        ref.kind = 0
        print("Relocation#%d: ref addr %x - target addr %x" % (i, ref.ref_va, ref.target_va))

def dumpRef(binary, refInf):
    # logging.getLogger('angr.analyses.cfg.indirect_jump_solvers.jumptable').setLevel(logging.DEBUG)
    p = angr.Project(binary, load_options={'auto_load_libs': False})
    print("load project done!")
    extract(p, refInf)

if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("-o", "--output", dest = "output", action = "store", type = "string", \
            help = "output of the protobuf file", default = "/tmp/angr_refs.pb2")
    parser.add_option("-b", "--binary", dest = "binary", action = "store", type = "string", \
            help = "binary file", default = None)
    parser.add_option("-s", "--ss", dest = "ss", action = "store", type = "string", \
            help = "binary file", default = None)
    (options, args) = parser.parse_args()

    if options.binary == None:
        logging.error("Please input the binary file path!")
        exit(-1)

    refInf = refInf_pb2.RefList()
    dumpRef(options.binary, refInf)
    if ref_cnt == 0:
        exit(-1)
    with open(options.output, 'wb') as pbOut:
        pbOut.write(refInf.SerializeToString())
