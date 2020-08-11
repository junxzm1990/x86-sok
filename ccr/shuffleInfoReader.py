################################################################
#  Compiler-assisted Code Randomization: Practical Randomizer  #
#   (In the 39th IEEE Symposium on Security & Privacy 2018)    #
#                                                              #
#  Author: Hyungjoon Koo <hykoo@cs.stonybrook.edu>             #
#          Computer Science@Stony Brook University             #
#                                                              #
#  This file can be distributed under the MIT License.         #
#  See the LICENSE.TXT for details.                            #
################################################################

import os, sys
import logging
import gzip
import shuffleInfo_pb2
import constants as C
from BlockUtil import *

def deserializeInfo(ri):
    """ Deserialze the metadata from compiler and linker """
    def dumpFixups(F, section, fixupsBag):
        """
        :param F: Fixups from ReorderInfo binary
        :param section: Could be either .text, .rodata or .data
        :param fixupsBag: list() of all fixupInfo attributes
        :return:
        """
        if len(F) > 0:
            '''
            FixupTuple has been defined as following in shuffleInfo.proto
            message FixupTuple {
              required uint32 offset = 1;         // UPDATE AT LINKTIME WHEN COMBINING SECTIONS
              required uint32 deref_sz = 2;
              required bool   is_rela = 3;
              optional uint32 type = 4;           // (c2c,c2d,d2c,d2d) = range(3)
              optional string section_name = 5;   // section identifier in c++ mutiple sections
                                                  // fixup has a jump table (.rodata) for pic/pie use
              optional uint32 num_jt_entries = 6; // number of the jump table entries
              optional uint32 jt_entry_sz = 7;    // size of each jump table entry in byte
            }
            '''
            specialFixupCtr = 0
            specialFixupComment = ""
            for i in range(len(F)):
                # Only .text section might have jump table information for JT update with pic/pie
                if section == C.SEC_TEXT:
                    fixupEntry = (F[i].offset, F[i].deref_sz, F[i].is_rela, F[i].type, F[i].section_name, F[i].num_jt_entries, F[i].jt_entry_sz)
                    if F[i].type == 5:
                        specialFixupCtr += 1
                else:
                    fixupEntry = (F[i].offset, F[i].deref_sz, F[i].is_rela, F[i].type, F[i].section_name)
                fixupsBag.append(fixupEntry)

            if specialFixupCtr > 0:
                specialFixupComment = "(" + str(specialFixupCtr) + " in special sections)"
            logging.info("\tFixups in %s\t: %d %s" %
                         (section, len(F) - specialFixupCtr, specialFixupComment))

    dataset = dict()
    obj = ri.bin
    #bblLayout = ri.layout
    bblLayout = fix_1_byte_padding(ri.layout) 
    bblLayout = fixFunctionStartInGaps(bblLayout)
    fixups = ri.fixup
    srcTypes = ri.source

    obj_sz, fn_sz, bbl_sz = [], [], []
    #align_sz = [] ## added to store basic block's alignment size
    objLayout, funLayout, FixupCnts = [], [], []  #fn/obj, #bbl/fn
    canFallThroughs = []

    # binpang, add
    bbl_offset = [] # store basic block offset from its section
    bbl_section_name = [] # store its section
    bbl_padding = [] # basic block padding size
    func_offset = []
    func_section_name = []
    func_type = [] # store the function type. 0 represents that normal function
                   # 1 represents that `fake` function
    obj_offset = []
    obj_section_name = []
    # inline type: inline assemble type or handwritten assemble code
    bbl_inline = []

    fsz, osz = 0, 0
    bid, fid, oid = 0, 0, 0
    bb_ctr, fn_ctr = 0, 0

    is_start_func = True
    is_start_obj = True

    # TODO: For handwritten assemble file, we can't collect function information. So treat them seperately

    # Expand the BBL layout to binary, object, function and basic blocks
    # It feeds the EssentialInfo to construct a single hierarchical tree structure
    # Entries of each layer constitute a doubly linked list structure
    for idx in range(len(bblLayout)):
        '''
        LayoutInfo has been defined as following in shuffleInfo.proto
          message LayoutInfo {
            optional uint32 bb_size = 1;          // UPDATE AT LINKTIME WITH OBJ ALIGNMENTs
                                                  // All alignments between fn/bbl are included here
            optional uint32 type = 2;             // Represents the end of [OBJ|FUN|BBL] = range(2)
            optional uint32 num_fixups = 3;       // Number of fixups within this basic block
            optional bool bb_fallthrough = 4;     // Can this basic block be fallen through the next?
          }
        '''
        sz = bblLayout[idx].bb_size
        type = bblLayout[idx].type
        numFixups = bblLayout[idx].num_fixups
        canFallThrough = bblLayout[idx].bb_fallthrough
        offset = bblLayout[idx].offset
        sec_name = bblLayout[idx].section_name
        padding = bblLayout[idx].padding_size
        inline_type = bblLayout[idx].assemble_type

        bbl_sz.append(sz)

        bbl_offset.append(offset)
        bbl_section_name.append(sec_name)
        bbl_padding.append(padding)
        bbl_inline.append(inline_type)

        fsz += sz
        osz += sz

        bb_ctr += 1
        bid += 1
        FixupCnts.append(numFixups)
        canFallThroughs.append(canFallThrough)

        if is_start_func == True:
            func_section_name.append(sec_name)
            func_offset.append(offset)
            # Here, we unit handwritten file's basic block into a `fake` function 
            if inline_type == 2:
                func_type.append(1)
            else:
                func_type.append(0)

            is_start_func = False

        if is_start_obj == True:
            obj_section_name.append(sec_name)
            obj_offset.append(offset)
            is_start_obj = False

        if type == 1 or type == 3 or (type == 2 and bblLayout[idx].assemble_type == 2):       # End of the function the BBL belongs to
            fn_sz.append(fsz)
            funLayout.append(bb_ctr)
            fn_ctr += 1
            bid = 0
            fid += 1
            fsz, bb_ctr = 0, 0
            is_start_func = True

        if type == 2 or type == 3:       # End of the object the BBL belongs to
            obj_sz.append(osz)
            objLayout.append(fn_ctr)
            fid = 0
            oid += 1
            osz, fn_ctr = 0, 0
            is_start_obj = True

    # [FIXME] Ugly, but just a workaround
    # Function information is somehow disappeared from LTO...
    # In case of LTO, objLayout and obj_sz need to be adjusted
    if len([bblLayout[x].type for x in range(len(bblLayout)) if bblLayout[x].type == 1 or bblLayout[x].type == 3]) == 0:
        assert (len(objLayout) == len(obj_sz))
        idxes = list()
        for i in range(len(objLayout)):
            if objLayout[i] > 1:
                idxes.append(i)

        adjustedLayout = list()
        adjustedSz = list()
        start = 0
        for j in idxes:
            adjustedLayout.append(sum(objLayout[start:j]))
            adjustedLayout.append(objLayout[j])
            adjustedSz.append(sum(obj_sz[start:j]))
            adjustedSz.append(obj_sz[j])
            start = j + 1

        adjustedLayout.append(sum(objLayout[start:]))
        adjustedSz.append(sum(obj_sz[start:]))
        objLayout, obj_sz = adjustedLayout, adjustedSz

    '''
    BinaryInfo has been defined as following in shuffleInfo.proto
      message BinaryInfo {
        optional uint32 rand_obj_offset = 1;     // PLACEHOLDER FOR LINKER
        optional uint32 main_addr_offset = 2;    // PLACEHOLDER FOR LINKER
        optional uint32 obj_sz = 3;              // Verification purpose
      }
    '''
    dataset['bin_info'] = {}
    dataset['bin_info']['reorderObjStartFromText'] = obj.rand_obj_offset
    dataset['bin_info']['mainAddrOffsetFromText']  = obj.main_addr_offset
    dataset['bin_info']['reorderedObjSize'] = obj.obj_sz

    # The info for Objects and Functions is derived from LayoutInfo
    # dataset['obj_size'] = obj_sz
    # dataset['obj_func_cnt'] = objLayout
    dataset['func_size'] = fn_sz
    dataset['func_bb_cnt'] = funLayout
    dataset['bb_size'] = bbl_sz
    dataset['bb_fixup_cnt'] = FixupCnts
    dataset['bb_fall_through'] = canFallThroughs
    
    # add basic block offset and section information
    dataset['bb_offset'] = bbl_offset
    dataset['bb_section'] = bbl_section_name
    dataset['bb_padding'] = bbl_padding
    dataset['bb_assemble'] = bbl_inline
    dataset['func_offset'] = func_offset
    dataset['func_section'] = func_section_name
    dataset['func_type'] = func_type
    # dataset['obj_offset'] = obj_offset
    # dataset['obj_section'] = obj_section_name

    assert (sum(fn_sz) == sum(bbl_sz)), "Does not match FnSz, and BBLSz!"

    logging.info('Reading the metadata from the .rand section...')
    logging.info('\tOffset to the object  : 0x%02x', obj.rand_obj_offset)
    logging.info('\tOffset to the main()  : 0x%02x', obj.main_addr_offset)
    logging.info('\tTotal Emitted Bytes   : 0x%04x' % sum(obj_sz))
    logging.info('\tNumber of Objects     : %d' % len(obj_sz))
    logging.info('\tNumber of Functions   : %d' % len(fn_sz))
    logging.info('\tNumber of Basic Blocks: %d' % len(bbl_sz))

    # Fixups in .text has to point its parent BBL, which consist of leaves in the tree
    fixupsText, fixupsRodata, fixupsData, fixupsDataRel, fixupsInitArray = [], [], [], [], []
    for fi in range(len(fixups)):
        dumpFixups(fixups[fi].text, C.SEC_TEXT, fixupsText)
        dumpFixups(fixups[fi].rodata, C.SEC_RODATA, fixupsRodata)
        dumpFixups(fixups[fi].data, C.SEC_DATA, fixupsData)
        dumpFixups(fixups[fi].datarel, C.SEC_DATA_REL, fixupsDataRel)
        dumpFixups(fixups[fi].initarray, C.SEC_INIT_ARR, fixupsInitArray)

    def __getDataSet(fixups, kind):
        if len(fixups) > 0:
            return list(zip(*fixups)[kind])
        else:
            return []

    def _collectDataSet(DS_FIXUP, fixups):
        for i, DS in enumerate(DS_FIXUP):
            dataset[DS] = __getDataSet(fixups, i)

    _collectDataSet(C.DS_FIXUP_TEXT, fixupsText)
    _collectDataSet(C.DS_FIXUP_RODATA, fixupsRodata)
    _collectDataSet(C.DS_FIXUP_DATA, fixupsData)
    _collectDataSet(C.DS_FIXUP_DATAREL, fixupsDataRel)
    _collectDataSet(C.DS_FIXUP_INIT_ARR, fixupsInitArray)

    dataset['obj_src_type'] = srcTypes.src_type

    logging.info('\tNumber of Jump Tables : %d' %
                 len(filter(lambda x: x!=0, dataset['fixup_num_jt_entries'])))

    return dataset

# binpang. For some special cases(we found it in mysql 5.7.27) compiled by gcc.
# fix this bug here.
"""
    nop
    .bb_bbinfo // basic block start mark
    xxxxx
    xxxxxxx
    xxxx
    .be_bbinfo // basic block end mark

The above example shows that nop instruction was not included in the right basic block
"""
def fix_1_byte_padding(layout):
    bblLayout = layout
    layout_map = dict() # basic block begining address => index
    for idx in range(len(bblLayout)):
        layout_map[bblLayout[idx].offset] = idx
    current_idx = 0
    
    miss_1_byte_map = set()
    additional_1_byte_map = set()
    for (address, idx) in layout_map.items():
        layout = bblLayout[idx] 
        current_idx += 1
        next_bb_addr = address + layout.bb_size
        # the address is continuous
        if next_bb_addr in layout_map:
            continue

        # the last basic block
        if current_idx == len(bblLayout):
            continue

        # the basic block may lack 1 byte
        if (next_bb_addr + 1) in layout_map:
            miss_1_byte_map.add(layout_map[next_bb_addr+1])

        # the basic block may have addition 1 byte
        if (next_bb_addr - 1) in layout_map:
            additional_1_byte_map.add(idx)

    # double check
    # for every basic block which has additional 1 byte
    # we check if its next basic block lacks 1 byte
    for addi_idx in additional_1_byte_map:
        if (addi_idx + 1) in miss_1_byte_map:
            # fix the basic block size
            bblLayout[addi_idx].bb_size -= 1

            # update the address and size of basic block which lacks 1 byte
            bblLayout[addi_idx+1].bb_size += 1
            bblLayout[addi_idx+1].offset -= 1

    return bblLayout


def readOnly(outFile, randInfo):
    def printFixups(F, sec):
        if len(F) > 0:
            out.write("Fixups in %s: %d\n" % (sec, len(F)))
            for i in range(len(F)):
                isRela = 'Y' if F[i].is_rela else 'N'
                ty = C.FIXUP_TYPE[F[i].type]
                secName = F[i].section_name
                JTEntries, JTEntrySz = F[i].num_jt_entries, F[i].jt_entry_sz
                out.write("\tFixup#%4d [%s] - Off:0x%04x, DerefSz:%d, IsRela:%s, Type: %s (@Sec %s)" % \
                      (i, sec, F[i].offset, F[i].deref_sz, isRela, ty, secName))
                if sec == C.SEC_TEXT and JTEntries > 0:
                    out.write(", [JT] %d Entries with %dB in size\n" % (JTEntries, JTEntrySz))
                else:
                    out.write("\n")

    obj = randInfo.bin
    #bblLayout = randInfo.layout
    bblLayout = fix_1_byte_padding(randInfo.layout)
    #bblLayout = fixFunctionStartInGaps(bblLayout)
    fixups = randInfo.fixup
    srcTypes = randInfo.source

    out = open(outFile, 'w')
    out.write("Main Addr Offset   : 0x%04x\n" % obj.main_addr_offset)
    out.write("Rand Object Offset : 0x%04x\n" % obj.rand_obj_offset)
    out.write("Rand Object Size   : 0x%04x\n" % obj.obj_sz)
    out.write("Total BBLs in .text: %d\n" % len(bblLayout))

    fallThroughCtr = 0

    for idx in range(len(bblLayout)):
        sz = bblLayout[idx].bb_size
        type = C.BBL_TYPE[bblLayout[idx].type]
        numFixups = bblLayout[idx].num_fixups
        offset = bblLayout[idx].offset
        padding = bblLayout[idx].padding_size
        inline_asm = ""
        if bblLayout[idx].bb_fallthrough:
            canFallThrough = "Y"
            fallThroughCtr += 1
        else:
            canFallThrough = "N"

        if bblLayout[idx].assemble_type == 1:
            inline_asm = "[inline]"
        elif bblLayout[idx].assemble_type == 2:
            inline_asm = "[handwritten]"

        secName = bblLayout[idx].section_name
        out.write("\tBBL#%4d (%3dB) [%s] - Off:0x%04x, Fixups: %2d, padding: %2d, FallThrough: %s (@Sec %s) %s\n" % \
                 (idx, sz, type, offset, numFixups, padding, canFallThrough, secName, inline_asm))

    for fi in range(len(fixups)):
        printFixups(fixups[fi].text, C.SEC_TEXT)
        printFixups(fixups[fi].rodata, C.SEC_RODATA)
        printFixups(fixups[fi].data, C.SEC_DATA)
        printFixups(fixups[fi].datarel, C.SEC_DATA_REL)
        printFixups(fixups[fi].initarray, C.SEC_INIT_ARR)

    numObjs = len(srcTypes.src_type)
    if numObjs > 0:
        out.write("Total Objects: %d\n" % (numObjs))
        for j in range(numObjs):
            ty = srcTypes.src_type[j]
            if ty > 0:
                out.write("\tObj %d: %s\n" % (j, C.SRC_TYPE[ty]))
    else:
        logging.critical("The metadata does not contain the type of an object (obsolete ver?)")

    out.close()
    print("\tMain Addr Offset   : 0x%04x" % obj.main_addr_offset)
    print("\tRand Object Offset : 0x%04x" % obj.rand_obj_offset)
    print("\tRand Object Size   : 0x%04x" % obj.obj_sz)
    print("\tTotal BBLs in .text: %d" % len(bblLayout))
    #print "\tTotal BBLs in .text: %d (Fallthrough = %d, %.2f%%)" \
    #      % (len(bblLayout), fallThroughCtr, fallThroughCtr / float(len(bblLayout)) * 100)
    print("Wrote the metadata to %s..." % outFile)

def read(metaData, hasRandSection):
    """
    Deserialize the metadata for randomization in google protobuf format
    :param metaData: target file name
    :param isDebug:
    :return:
    """
    randInfo = shuffleInfo_pb2.ReorderInfo()
    if hasRandSection:
        try:
            randInfo.ParseFromString(gzip.open(metaData, "rb").read())
        except IOError:
            print("Found a .rand section but not gzipped. Check out the CCR linker!")
    else:
        randInfo.ParseFromString(open(metaData, "rb").read())
    return deserializeInfo(randInfo)

if __name__ == '__main__':
    def isELF(f):
        # Check if the magic number is "\x7F ELF"
        return open(f, 'rb').read(4) == '\x7f\x45\x4c\x46'
    def isMetadata(f):
        return f.endswith(C.METADATA_POSTFIX)

    def getMetadata(param):
        if isMetadata(param):
            print("Found the metadata at %s" % param)
            return param
        if isELF(param):
            if os.path.exists(C.METADATA_PATH):
                os.remove(C.METADATA_PATH)
            os.system(' '.join(['objcopy', '--dump-section',
                               C.RAND_SECTION + '=' + C.METADATA_PATH, param, '2> /dev/null']))
            return C.METADATA_PATH

    fn = getMetadata(sys.argv[1])
    ri = shuffleInfo_pb2.ReorderInfo()

    if isMetadata(fn):
        ri = shuffleInfo_pb2.ReorderInfo()
        ri.ParseFromString(open(fn, "rb").read())
        readOnly(fn + C.METADESC_POSTFIX, ri)
    elif isELF(sys.argv[1]):
        try:
            ri.ParseFromString(gzip.open(fn, "rb").read())
            print("Found the .rand section, dumping into %s (will be removed at the end)" % C.METADATA_PATH)
            readOnly(sys.argv[1] + C.METADATA_POSTFIX + C.METADESC_POSTFIX, ri)
            os.remove(C.METADATA_PATH)
        except IOError:
            print("The ELF binary does not contain a .rand section for metadata!")
    else:
        print("Usage:", sys.argv[0], "<filename.shuffle.bin> or <ELF format with a .rand section>")
