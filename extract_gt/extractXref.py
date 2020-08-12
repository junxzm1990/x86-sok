from deps import *
import optparse
import constants as C
import reconstructInfo 
import logging

import sys
import os
import refInf_pb2
from reorderInfo import *

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)

KindList = ["C2C", "C2D", "D2C", "D2D"]

jumpTableRange = list()


def dumpRefInfoSegment(segmentFixup, refinf):
    for (i,fi) in enumerate(segmentFixup):
        ref = refinf.ref.add()
        ref.ref_va = fi.VA
        ref.target_va = fi.refTo & 0xffffffffffffffff
        ref.ref_size = fi.derefSz
        ref.kind = fi.type
        ref.is_rela = fi.isRela
        if isJTEntry(ref.ref_va):
            ref.jt_entry = True
        else:
            ref.jt_entry = False

        logging.debug("Fixup#%d reference va %x, ref_size %d, target va %x, kind %s, jt_entry %s, rela %s" % \
                (i, ref.ref_va, ref.ref_size, ref.target_va, KindList[ref.kind], "True" if ref.jt_entry else "False", "True" if ref.is_rela else "False"))

def isJTEntry(addr):
    global jumpTableRange
    for addRange in jumpTableRange:
        if addr >= addRange[0] and addr <= addRange[1]:
            return True
    return False

def dumpRefInfoText(segmentFixup, refinf):
    global jumpTableRange
    for (i, fi) in enumerate(segmentFixup):
        ref = refinf.ref.add()
        curBB = fi.parent
        startAdr = curBB.offsetFromBase
        endAdr = curBB.size + startAdr
        virAdr = curBB.VA
        ref.ref_va = fi.VA
        ref.target_va = fi.refTo & 0xffffffffffffffff
        ref.ref_size = fi.derefSz
        ref.kind = fi.type
        ref.jt_entry = False
        ref.is_rela = fi.isRela
        logging.debug("Fixup#%d reference va %x, ref_size %d, target va %x, kind %s, rela %s" % \
                (i, ref.ref_va, ref.ref_size, ref.target_va, KindList[ref.kind], "True" if ref.is_rela else "False"))
        # print("Inst#%d 0x%x\t%s\t%s" % (i, instAdr.address, instAdr.mnemonic, instAdr.op_str))
        if fi.numJTEntries != 0:
            jumpTableRange.append((ref.target_va, ref.target_va + (fi.numJTEntries) * fi.jtEntrySz))


def dumpRefInfo(essinfo, refinf):
    """
    print the jump table according to the ccr generated information

    args:
        essinfo: essentialinfo that ccr define
        refinf: proto buffer defined reference definition
        outfile: log output
        binary:

    returns:
    """

    if essinfo.hasFixupsInText():
        logging.debug("Text reference")
        dumpRefInfoText(essinfo.getFixupsText(), refinf)

    if essinfo.hasFixupsInRodata():
        logging.debug("Rodata reference")
        dumpRefInfoSegment(essinfo.getFixupsRodata(), refinf)

    if essinfo.hasFixupsInData():
        logging.debug("Data reference")
        dumpRefInfoSegment(essinfo.getFixupsData(), refinf)

    if essinfo.hasFixupsInDataRel():
        logging.debug("DataRel reference")
        dumpRefInfoSegment(essinfo.getFixupsDataRel(), refinf)

    if essinfo.hasFixupsInInitArray():
        logging.debug("InitArray reference")
        dumpRefInfoSegment(essinfo.getFixupsInitArray(), refinf)
    return 1

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-b", "--binary", dest = "binary", action="store", type="string", help="input elf binary path", default=None)
    parser.add_option("-m", "--metadata", dest = "metadata", action="store", type="string", help="metadata file path", default=None)
    parser.add_option("-o", "--output", dest = "output", action="store", type="string", help="output file path", default="/tmp/Ref_gt.pb")
    (options, args) = parser.parse_args()
    if options.binary == None:
        print('Please input the elf file')
        exit(-1)

    shuffleInfoBin = None
    if options.metadata == None:
        shuffleInfoBin = options.binary + C.METADATA_POSTFIX
    else:
        shuffleInfoBin = options.metadata

    rData = None
    if os.path.exists(shuffleInfoBin):
        rData = reconstructInfo.read(shuffleInfoBin, False, options.binary)
    elif os.path.exists(C.METADATA_PATH):
        rData = reconstructInfo.read(C.METADATA_PATH, True, options.binary)
    else:
        print("Error: No metadata file\n")
        exit(-1)

    refInf = refInf_pb2.RefList()

    rData['bin_info']['bin_path'] = options.binary
    essInfo = EssentialInfo(rData)
    dumpRefInfo(essInfo, refInf)
    pbOut = open(options.output, "wb")
    pbOut.write(refInf.SerializeToString())
    pbOut.close()
