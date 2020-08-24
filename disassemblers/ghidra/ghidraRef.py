#TODO write a description for this script
#@author 
#@category Functions
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here

# reference https://github.com/NationalSecurityAgency/ghidra/issues/826
import logging
import site
import sys
import os
import ctypes
import time

from ghidra.program.model.listing import CodeUnitIterator;
from ghidra.program.model.listing import Listing;
from ghidra.program.model.listing import Instruction;
from ghidra.program.model.pcode import PcodeOp
# as ghidra uses jython
# add the default python27 dist-packages to the sys path
# protobuf is installed in these two pathes
sys.path.append('/usr/lib/python2.7/dist-packages')
sys.path.append('/usr/local/lib/python2.7/dist-packages')
# print("current python version is {0}".format(site.getsitepackages()))
# print(os.path.join(os.path.dirname(os.path.realpath("__file__")), "../protobuf_def"))
# sys.path.append("../protobuf_def")
import refInf_pb2

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

timeout = time.time() + 60*20 # 20 miniutes to stop
def dumpRefs(output):
    refInf = refInf_pb2.RefList()
    listing = currentProgram.getListing()
    refSet = set()
    # record the basic block that has been added by functions
    for codeunit in listing.getCodeUnits(True):
        if time.time() > timeout:
            logging.error("Oh, sorry! time out!")
            exit(-1)
        if isinstance(codeunit, Instruction):
            target_vas = set()
            for pcode in codeunit.getPcode():
                for varnode in pcode.getInputs():
                    if varnode.isAddress() or varnode.isConstant():
                        target_vas.add(varnode.getOffset())
                output_varnode = pcode.getOutput()
                if output_varnode != None and (output_varnode.isAddress() or output_varnode.isConstant()):
                    target_vas.add(output_varnode.getOffset())

            collected_refs = set()
            for xref in codeunit.getReferencesFrom():
                if xref.isStackReference():
                    continue
                target_va = xref.getToAddress().getOffset()
                # make sure the target_va is in current instruction's internal represent
                if target_va not in target_vas or \
                        target_va in collected_refs:
                    continue
                collected_refs.add(target_va)
                ref = refInf.ref.add()
                ref.ref_va = xref.getFromAddress().getOffset()
                ref.target_va = target_va
                # TODO: Get the correct size and kind
                ref.ref_size = 8
                ref.kind = 0
                logging.info("[code]: From 0x%x -> 0x%x" % (ref.ref_va, ref.target_va))
        else:
            for xref in codeunit.getReferencesFrom():
                ref_addr = xref.getFromAddress().getOffset()
                if ref_addr in refSet:
                    continue
                logging.info("[data]: From 0x%x -> 0x%x" % 
                        (xref.getFromAddress().getOffset(), xref.getToAddress().getOffset()))
                refSet.add(ref_addr)
                ref = refInf.ref.add()
                ref.ref_va = xref.getFromAddress().getOffset()
                ref.target_va = xref.getToAddress().getOffset() & 0xffffffffffffffff
                #ref.target_va = 0
                ref.ref_size = 0
                ref.kind = 0
    logging.debug("Collect Refs done! ready to write output...")
    f = open(output, "wb")
    f.write(refInf.SerializeToString())
    f.close()

if __name__ == "__main__":
    # parser = optparse.OptionParser()
    # parser.add_option("-o", "--output", dest = "output", action = "store", type = "string", \
    #        help = "output of the protobuf file", default = "/tmp/ghidra_block.pb2")
    # (options, args) = parser.parse_args()
    output = "/tmp/ghidra_ref.pb2"
    # FIXME: Here, can't get the argument by sys.argv from ghidra analyzeHeadless
    # if len(sys.argv) > 1:
    #     output = sys.argv[1]
    
    # Get the output path from environment variable
    try:
        if os.environ['GHIDRA_OUT_PATH']:
            output = os.environ['GHIDRA_OUT_PATH']
            logging.debug("ghidra output path is {0}".format(os.environ['GHIDRA_OUT_PATH']))
    except:
        pass
    dumpRefs(output)
