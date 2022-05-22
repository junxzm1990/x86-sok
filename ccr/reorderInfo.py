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

from sqlalchemy import true
import util
import struct
import unit
import constants as C
from util import hexPrint as HP
from elfParser import ELFParser
from elftools.elf.elffile import ELFFile
from capstone import *
from capstone.arm64 import *
from BlockUtil import *
from mipsRelocs import *


'''
Brief overview of classes
    BinaryInfo  : the location of the object for reordering
    Objects     : object sizes and function counts in each object
    Functions   : function sizes and basic block counts in each function
    BasicBlocks : basic block sizes and fixup counts in each basic block
    Fixups      : fixup offsets from each function, sizes for de-referencing and kinds
'''

class BinaryInfo():
    def __init__(self, BinInfo):
        '''
        Holds the given binary information including:
            Base address
            Entry point
            [Required] the location of the object for reordering
        :param BinInfo:
        '''

        self.elfParser = ELFParser(BinInfo['bin_path'])
        self.entryPoint = self.elfParser.elf.header['e_entry']
        load_segment = self.elfParser.elf.get_segment(2)
        if load_segment['p_type'] == 'PT_LOAD':
            self.base = load_segment['p_vaddr']
        else:
            ## iter over the segment, find the first PT_LOAD segment
            for seg in self.elfParser.elf.iter_segments():
                if seg['p_type'] == 'PT_LOAD':
                    self.base = seg['p_vaddr']
                    break
        
        # binpang, add
        self.secVA = self._getSecVA()

        self.reorderObjStartFromText = BinInfo['reorderObjStartFromText']
        self.mainAddrOffsetFromText = BinInfo['mainAddrOffsetFromText']
        self.reorderedObjSize = BinInfo['reorderedObjSize']

        # Whether or not pic/pie, executable should have an entry point
        if self.entryPoint > 0:
            self.baseOffsetFromFile = self._getTextSecVA() - self.base
        # Only shared object does not have one
        else:
            self.baseOffsetFromFile = self._getTextSecVA()
            self.base = 0x0

        self.Objects = []   # Objects that consist of the binary
        self.fixupCnt = 0

    def _getTextSecVA(self):
        for s in range(1, self.elfParser.elf.num_sections()):
            if self.elfParser.elf.get_section(s).name == C.SEC_TEXT:
                return self.elfParser.elf.get_section(s)['sh_addr']

    # binpang, add
    def _getSecVA(self):
        ''' 
        return the mappint of section name and its virtual address
        '''
        result = {}
        for s in range(1, self.elfParser.elf.num_sections()):
            sec_name = self.elfParser.elf.get_section(s).name
            if sec_name != "" and sec_name != None:
                result[sec_name] = self.elfParser.elf.get_section(s)['sh_addr']
        return result



    def getBinary(self):
        return self

    def getElfParser(self):
        return self.elfParser

    def getReorderObjOff(self):
        return self.reorderObjStartFromText

    def isInReorderRange(self, addr):
        s = self._getTextSecVA() + self.reorderObjStartFromText
        return s <= addr < s + self.reorderedObjSize

    def __repr__(self):
        return '<Binary>' \
                 '\n\t [Parsed] Base Address  : 0x%08x' \
                 '\n\t [Parsed] Entry Point   : 0x%08x' \
                 '\n\t [Linker] Main Offset   : 0x%08x' \
                 '\n\t [Linker] Reorder Start : 0x%08x' \
                 '\n\t OffsetFromBase   : 0x%08x' \
               % (self.base, self.entryPoint, self.mainAddrOffsetFromText,
                  self.reorderObjStartFromText, self.baseOffsetFromFile)

class Functions(BinaryInfo):
    """
    The Functions class inherits Objects class
    """
    def __init__(self, bar, BinInfo, FuncInfo):
        BinaryInfo.__init__(self, BinInfo)
        self.FunctionLayout = []
        self.lookupByVA = dict()
    
        # Unpack the function information
        self.funcSize, self.funcBBCnt, self.funcOffsetFromSection, self.funcSec, self.funcType = FuncInfo
        self.numBBs = sum(self.funcBBCnt)
        self.numFunctions = len(self.funcSize)

        # binpang, add
        self.funcSecVA = [self.secVA[sec_name] for sec_name in self.funcSec]

        # Func X belongs to Obj Y; dict(X:Y)
        # self.func2Obj = util.buildLookupTbl(self.objFuncCnt)

        #self.funcOffset = util.getOffset(self.funcSize)
        #self.funcOffsetFromObj = util.getOffsetFromAccordingOffset(self.objFuncCnt, self.funcOffsetFromSection)
        # self.funcOffsetFromSection = util.computeRelaOffset(self.funcOffset, self.reorderObjStartFromText)
        self.funcOffsetFromBase = util.computeOffsetFromBase(self.funcOffsetFromSection, self.funcSecVA, self.base)
        self.funcVA = util.computeRelaOffset(self.funcOffsetFromBase, self.base)

        self.generateFunctionList(bar)

    def generateFunctionList(self, bar):
        prevFun = None
        for idx in range(self.numFunctions):
            F = unit.Function()
            F.idx = idx
            F.size = self.funcSize[idx]
            F.VA = self.funcVA[idx]
            self.type = self.funcType[idx]

            if prevFun:
                prevFun.next = F
                F.prev = prevFun

            # Assign the parent of the Function and add it to the list
            # F.parent = self.getObject(self.func2Obj[idx])
            # F.parent.Functions.append(F)

           # F.offsetFromObj = self.funcOffsetFromObj[idx]
            F.offsetFromSection = self.funcOffsetFromSection[idx]
            F.offsetFromBase = self.funcOffsetFromBase[idx]

            self.FunctionLayout.append(F)
            self.lookupByVA[F.VA] = F
            prevFun = F
            bar += 1

    def getFunctions(self):
        return self.FunctionLayout

    def getFunction(self, idx):
        return self.FunctionLayout[idx]

    def getFunByVA(self, va):
        return self.lookupByVA[va]

    def __repr__(self):
        objInfo = Objects.__repr__(self)
        return objInfo + '\n<%d Functions>' \
                         '\n\t [Compiler] Sizes        : %s' \
                         '\n\t [Compiler] BBs per func : %s' \
                         '\n\t offsetFromSection       : %s ' \
                         '\n\t offsetFromBase          : %s ' \
                         '\n\t VirtualAddress          : %s' \
                         % (self.numFuncs, self.funcBBCnt, HP(self.funcSize),
                            HP(self.funcOffsetFromSection),
                            HP(self.funcOffsetFromBase), HP(self.funcVA))

class BasicBlocks(Functions):
    """
    The BasicBlocks class inherits Functions class
    """
    def __init__(self, bar, BinInfo, FuncInfo, BBInfo,fixupaddreslist,fixupname):
        Functions.__init__(self, bar, BinInfo, FuncInfo)
        self.BasicBlockLayout = []
        self.lookupByVA = dict()

        # Unpack the basic block information
        self.BBSize, self.BBFixupCnt, self.BBFallThrough, self.BBOffsetFromSection, \
                self.BBSec, self.BBPadding, self.BBAssembleType, self.BBType = BBInfo

        self.numFixups = sum(self.BBFixupCnt)
        self.numBasicBlocks = len(self.BBSize)

        # binpang, add
        self.BBSecVA = [self.secVA[sec_name] for sec_name in self.BBSec]

        # BB X belongs to Func Y; dict(X:Y)
        self.BB2Func = util.buildLookupTbl(self.funcBBCnt)

        # self.BBOffset = util.getOffset(self.BBSize)
        self.BBOffsetFromBase = util.computeOffsetFromBase(self.BBOffsetFromSection, self.BBSecVA, self.base)
        self.BBOffsetFromFunc = util.getOffsetFromAccordingOffset(self.funcBBCnt, self.BBOffsetFromSection)
        self.BBVA = util.computeRelaOffset(self.BBOffsetFromBase, self.base)
        # for idx in range(0,len(self.BBOffsetFromSection)):
        #     print("Original Data: VA is 0x%x, Baseoff: 0x%x, SecVA: 0x%x, Base: 0x%x" %(self.BBVA[idx],self.BBOffsetFromSection[idx], self.BBSecVA[idx], self.base))

        self.block_check(fixupaddreslist,fixupname)

        self.numFixups = sum(self.BBFixupCnt)
        self.numBasicBlocks = len(self.BBSize)

        # binpang, add
        self.BBSecVA = [self.secVA[sec_name] for sec_name in self.BBSec]

        # BB X belongs to Func Y; dict(X:Y)
        self.BB2Func = util.buildLookupTbl(self.funcBBCnt)

        # self.BBOffset = util.getOffset(self.BBSize)
        self.BBOffsetFromBase = util.computeOffsetFromBase(self.BBOffsetFromSection, self.BBSecVA, self.base)
        self.BBOffsetFromFunc = util.getOffsetFromAccordingOffset(self.funcBBCnt, self.BBOffsetFromSection)
        self.BBVA = util.computeRelaOffset(self.BBOffsetFromBase, self.base)

        self.generateBasicBlockList(bar)

    #TODO(ztt) make it fit to arm32 and other arch
    # sub padding and add it to the last instruction
    def multi_jump(self,idx):
        return self.elfParser.multi_jump(self.BBVA[idx],self.BBSize[idx] - self.BBPadding[idx],self.BBSec[idx],self.BBSecVA[idx],self.BBType[idx],True)
        #return list()

    def count_fixup(self,left,right,fixupaddreslist):
        res = 0
        for pc in range(left,right,0x2):
            if(fixupaddreslist.count(pc) > 0):
                res += 1
        return res

    def block_check(self,fixupaddreslist,fixupname):
        resBBSize = list()
        resBBFixupCnt = list()
        resBBFallThrough = list()
        resBBOffsetFromSection = list()
        resBBSec = list()
        resBBPadding = list()
        resBBAssembleType = list()
        resBBVA = list()
        resBBType = list()
        now = 0
        now_func = 0
        for idx in range(len(fixupaddreslist)):
            fixupaddreslist[idx] = fixupaddreslist[idx] + self.getElfParser().getSectionVA(fixupname[idx])
        for idx in range(self.numBasicBlocks):
            now += 1
            (res,cond) = self.multi_jump(idx)

            if len(res) > 1:
                # print("T: BB#%d find jump count is %d" %(idx,len(res)))
                last = self.BBVA[idx]
                self.numBBs -= 1
                self.funcBBCnt[now_func] -= 1
                cnt = 0
                for (pc,condition) in zip(res,cond):
                    # print("T: MULTI JUMP: 0x%x" %pc)
                    # pc is first instruction address of the next BB
                    # last is the fisrt instruction address of the BB
                    cnt = cnt + 1

                    resBBFixupCnt.append(self.count_fixup(last,pc,fixupaddreslist))
                    resBBOffsetFromSection.append(last - self.BBVA[idx] + self.BBOffsetFromSection[idx])
                    resBBSec.append(self.BBSec[idx]) # same section
                    if cnt == len(res):
                        resBBSize.append(pc - last + self.BBPadding[idx])
                        resBBFallThrough.append(self.BBFallThrough[idx])
                        resBBPadding.append(self.BBPadding[idx]) # only last bb have padding
                    else:
                        resBBSize.append(pc - last)
                        resBBFallThrough.append(condition)
                        resBBPadding.append(0) # same padding
                    resBBAssembleType.append(self.BBAssembleType[idx]) # same asseble type
                    resBBVA.append(pc)
                    resBBType.append(self.BBType[idx]) # same type
                    last = pc
                    self.numBBs += 1
                    self.funcBBCnt[now_func] += 1
            else:
                resBBSize.append(self.BBSize[idx])
                resBBFixupCnt.append(self.BBFixupCnt[idx])
                resBBFallThrough.append(self.BBFallThrough[idx])
                resBBOffsetFromSection.append(self.BBOffsetFromSection[idx])
                resBBSec.append(self.BBSec[idx])
                resBBPadding.append(self.BBPadding[idx])
                resBBAssembleType.append(self.BBAssembleType[idx])
                resBBVA.append(self.BBVA)
                resBBType.append(self.BBType[idx])

            if now == self.funcBBCnt[now_func]:
                now_func += 1
                now = 0

            
        self.BBSize = resBBSize
        self.BBFixupCnt = resBBFixupCnt
        self.BBFallThrough = resBBFallThrough
        self.BBOffsetFromSection = resBBOffsetFromSection
        self.BBSec = resBBSec
        self.BBPadding = resBBPadding
        self.BBAssembleType = resBBAssembleType
        self.BBVA = resBBVA
        self.BBType = resBBType
            

    def generateBasicBlockList(self, bar):
        prevBBL = None
        for idx in range(self.numBasicBlocks):
            BBL = unit.BasicBlock()
            BBL.idx = idx
            BBL.type = self.BBType[idx]
            BBL.size = self.BBSize[idx]
            BBL.hasFallThrough = self.BBFallThrough[idx]
            BBL.VA = self.BBVA[idx]
            BBL.padding = self.BBPadding[idx]
            BBL.assembleType = self.BBAssembleType[idx]

            if prevBBL:
                prevBBL.next = BBL
                BBL.prev = prevBBL

            # Assign the parent of the BB and add it to the list
            BBL.parent = self.getFunction(self.BB2Func[idx])
            BBL.parent.BasicBlocks.append(BBL)
            BBL.offsetFromFunc = self.BBOffsetFromFunc[idx]
            BBL.offsetFromSection = self.BBOffsetFromSection[idx]
            BBL.offsetFromBase = self.BBOffsetFromBase[idx]
            '''
            if self.elfParser.check_terminator(BBL.VA + BBL.size - 0x4,self.BBSec[idx],self.BBSecVA[idx],True):
                BBL.flag = True
            else:
                BBL.flag = False
            '''
            # As fixup might not be in BBL, all ctrs have to be taken care of here
            # binpang, comment it out
            # may be not accurate
            #BBL.fixupCnt = self.BBFixupCnt[idx]
            #BBL.parent.fixupCnt += BBL.fixupCnt               # Update function ctr
            #BBL.parent.parent.fixupCnt += BBL.fixupCnt        # Update object ctr
            #BBL.parent.parent.parent.fixupCnt += BBL.fixupCnt # Update binary ctr

            self.BasicBlockLayout.append(BBL)
            self.lookupByVA[BBL.VA] = BBL
            prevBBL = BBL
            bar += 1

    def getBasicBlocks(self):
        return self.BasicBlockLayout

    def getBasicBlock(self, idx):
        return self.BasicBlockLayout[idx]

    def getBBlByVA(self, va):
        if va in self.lookupByVA:
            return self.lookupByVA[va]

    def show(self, level=1):
        for bbl in self.BasicBlockLayout:
            print(bbl)
            if level > 1:
                for fixup in bbl.Fixups:
                    print('\t', fixup)


    def __repr__(self):
        funcInfo = Functions.__repr__(self)
        return funcInfo + '\n<%d BasicBlocks>' \
                          '\n\t [Compiler] Sizes         : %s' \
                          '\n\t [Compiler] Fixups per BB : %s' \
                          '\n\t offsetFromFunc           : %s ' \
                          '\n\t offsetFromSection        : %s ' \
                          '\n\t offsetFromBase           : %s ' \
                          '\n\t VirtualAddress           : %s' \
                          % (self.numBBs, self.BBFixupCnt, HP(self.BBSize), HP(self.BBOffsetFromFunc),
                             HP(self.BBOffsetFromSection),
                             HP(self.BBOffsetFromBase), HP(self.BBVA))

class Fixups():
    """
    The Fixups class that contains a variety of fixups
    """
    #Fixups(list(zip(*fixupsText)), self.constructInfo, C.SEC_TEXT, bar)
    def __init__(self, FixupData, constructInfo, sectionName, bar):
        self.FixupData = FixupData
        self.FixupsLayout = []
        self.FixupsLayoutInsn = []
        # The following layout is only defined when special section has been found in .text
        self.FixupsLayoutSpecial = []
        self.FixupsLayoutSpecialInsn = []
        # The following layout is only defined in CFI-enabled binary with LLVM (-cfi-icall)
        self.FixupsLayoutOrphan = []
        self.FixupsLayoutOrphanInsn = []
        
        self.curBBIdx = 0

        self.CI = constructInfo
        self.elfParser = self.CI.getElfParser()
        self.sectionName = sectionName
        self.secOff = self.elfParser.getSectionVA(self.sectionName)

        if sectionName == C.SEC_TEXT:
            self.Fixup2BB = util.buildLookupTbl(self.CI.BBFixupCnt)

        self._generateFixupList(bar)
        self.numFixups = len(self.FixupsLayout)
        self.numFixupsSpecial = len(self.FixupsLayoutSpecial)
        self._processRefs()


    def hasSpecialSection(self):
        """  Check if the section contains any fixup in a spectial section """
        return self.sectionName == C.SEC_TEXT and len(self.FixupsLayoutSpecial) > 0

    def hasOrphanFixups(self):
        """  Check if the section contains any orphan fixup """
        return self.sectionName == C.SEC_TEXT and len(self.FixupsLayoutOrphan) > 0

    def getParent(self, addr):
        bbNum = len(self.CI.getBasicBlocks())
        curIdx = self.curBBIdx % bbNum
        while True:
            curBB = self.CI.getBasicBlocks()[self.curBBIdx % bbNum]
            if addr >= curBB.VA and addr < curBB.VA + curBB.size - curBB.padding:
                return curBB
            self.curBBIdx += 1

            # we have iterate the whole basic blocks
            if self.curBBIdx % bbNum == curIdx:
                return None
    # return the sink position for adrp / adr
    def taintedRegsCrossFixup(self,fixup_insn_list,now_id,max_id):
        
        first_inst = fixup_insn_list[now_id]
        (regs_read, regs_write)  = first_inst.regs_access()
        tainted_regs = list()

        for r in regs_write:
            reg_name = first_inst.reg_name(r)
            logging.debug("[Fixup: taint initialize]: reg write is %s " % (reg_name))
            if 'ip' in reg_name:
                continue
            tainted_regs.append(r)
            logging.debug("[Fixup: taint initialize]: reg name is %s " % (reg_name))
        for idx in range(now_id + 1,max_id):
            inst = fixup_insn_list[idx]
            (regs_read, regs_write) = inst.regs_access()
            taint_read = False

            for r in regs_read:
                if r in tainted_regs:
                    taint_read = True
                    break

            # taint the write regs
            if taint_read:
                if inst.mnemonic == 'add' or inst.mnemonic == 'ldr':
                    logging.debug("[Fixup match pair 0x%x with 0x%x ]" %(first_inst.address,inst.address))
                    return idx

        logging.error("[Fixup match failed for the address : 0x%x]" %first_inst.address)
        return -1

    def _is_cisc(self, binary):
        result = False
        with open(binary, 'rb') as openFile:
            elffile = ELFFile(openFile)
            arch = elffile.get_machine_arch()

            if arch == 'x86' or arch == 'x64':
                result = True
        return result

    def _resolve_refto(self, FI,LOAD_RANGE,offset2reloction,mips_jmp_tbl_blk,is_cisc = False):
        if is_cisc:
            return

        if self.sectionName == C.SEC_TEXT and FI.VA in mips_jmp_tbl_blk:
            FI.numJTEntries = 0
            FI.jtEntrySz = 0

        parent = self.getParent(FI.VA)
        pc_flag = False
        if parent != None:
            #logging.debug("Fixup#%4d - Off:0x%04x, DerefSz:%d, IsRela:%s, Type: %s (@Sec %s) , VA: 0x%x, IMM: 0x%x , RefTo: 0x%x ,NumEntry: 0x%x" % \
            #    (cnt, FI.offset, FI.derefSz, FI.isRela, FI.type, FI.secName ,FI.VA, FI.imm, FI.refTo,FI.numJTEntries))
            if(parent.type & (1 << 6) == 64):
                FI.imm = self.elfParser.getArmImmValue(FI,True)
                if(self.elfParser.getAccessReg(FI,True)):
                    pc_flag = True
            else:
                FI.imm = self.elfParser.getArmImmValue(FI,False)
                if(self.elfParser.getAccessReg(FI,False)):
                    pc_flag = True
        if pc_flag:
            if(parent.type & (1 << 6) == 64):
                if FI.VA % 4 != 0:
                    sz = 2
                else:
                    sz = 4
            else:
                    sz = 8
            if self.elfParser.checkTBInstruction(FI):
                FI.refTo = FI.VA + 0x4
            else:
                FI.refTo = FI.VA + sz + FI.imm

        elif FI.VA in offset2reloction.keys():
            FI.refTo = offset2reloction[FI.VA]
            if not isInRange(FI.refTo, LOAD_RANGE):
                FI.refTo = FI.imm
        else:
            FI.refTo = FI.imm


    def _generateFixupList(self, bar):
        """ Initialize the fixup information from metadata """
        # The following is counting non-special fixups, excluding the type 5
        textIdx, specialIdx, orphanIdx = 0, 0, 0
        cnt = 0

        LOAD_RANGE = getLoadAddressRange(self.elfParser.fn)
        offset2reloction = readElfRelocation(self.elfParser.fn)
        # for mips
        (mips_fixups, mips_jmp_tbl_blk) = resolve_refs(self.elfParser.fn)

        if mips_fixups is not None:
            offset2reloction = mips_fixups

        for idx in range(len(self.FixupData)):
            FI = unit.Fixup()
            # sec_name = None
            # Only .text section could have a jump table.
            if self.sectionName == C.SEC_TEXT:
                FI.offset, FI.derefSz, FI.isRela, FI.type, FI.secName, FI.numJTEntries, FI.jtEntrySz = self.FixupData[idx]
            else:
                FI.offset, FI.derefSz, FI.isRela, FI.type, FI.secName = self.FixupData[idx]

            # Relative address to section
            FI.VA = self.elfParser.getSectionVA(FI.secName) + FI.offset

            is_cisc = self._is_cisc(self.elfParser.fn)
            self._resolve_refto(FI, LOAD_RANGE, offset2reloction, mips_jmp_tbl_blk, is_cisc)

            logging.debug("Fixup#%4d - Off:0x%04x, DerefSz:%d, IsRela:%s, Type: %s (@Sec %s) , VA: 0x%x, IMM: 0x%x , RefTo: 0x%x ,NumEntry: 0x%x" % \
                    (cnt, FI.offset, FI.derefSz, FI.isRela, FI.type, FI.secName ,FI.VA, FI.imm, FI.refTo,FI.numJTEntries))
            cnt = cnt + 1
            # Assign the parent of the BB and add it to the list iff .text section
            if self.sectionName == C.SEC_TEXT and FI.type < 4:
                try:
                    parent = self.getParent(FI.VA)
                    #FI.parent = self.CI.getBasicBlock(self.Fixup2BB[textIdx])
                    assert (parent != None), "fixup %x in .text does not match a basic block!" % FI.VA
                    FI.parent = parent
                    FI.parent.Fixups.append(FI)
                    # update fixup number
                    FI.parent.fixupCnt += 1
                    FI.parent.parent.fixupCnt += 1
                except:
                    FI.isOrphan = True

            if FI.type == C.FT_Special:
                FI.idx = specialIdx
                self.FixupsLayoutSpecial.append(FI)
                #self.FixupsLayoutSpecailInsn.append(self.elfParser.getInsn(FI))
                specialIdx += 1
            elif FI.isOrphan:
                FI.idx = orphanIdx
                FI.isRela = True    # Should be done manually (metadata does not have it)
                self.FixupsLayoutOrphan.append(FI)
                #self.FixupsLayoutOrphanInsn.append(self.elfParser.getInsn(FI))
                orphanIdx += 1
            else:
                FI.idx = textIdx
                self.FixupsLayout.append(FI)
                #self.FixupsLayoutInsn.append(self.elfParser.getInsn(FI))
                textIdx += 1
            bar += 1
        #print("\nT:")
        #print(LOAD_RANGE)
        # ztt add to fix arm instruction
    def _processRefs(self):
        """ Compute fixup derefVals and refTos from the given section """
        def findFixupTarget(FI):
            FI.derefVal = int.from_bytes(sectionData[FI.offset:FI.offset + FI.derefSz],byteorder='little')
            if is_cisc:
                FI.refTo = FI.VA + FI.derefSz + util.toSigned32(FI.derefVal) if FI.isRela else FI.derefVal

            FI.refBB = self.CI.getBBlByVA(FI.refTo)
            if FI.refBB:
                FI.target = "BB#%3s" % str(FI.refBB.idx)
            else:
                FI.target = self.elfParser.getSectionByVA(FI.refTo)

        is_cisc = self._is_cisc(self.elfParser.fn)

        sectionData = self.elfParser.elf.get_section_by_name(self.sectionName).data()
        fmt = {1: "<b", 2: "<h", 4: "<i", 8: "<q"}
        for FI in self.FixupsLayout:
            try:
                FI.derefVal = struct.unpack(fmt[FI.derefSz],
                                        sectionData[FI.offset:FI.offset + FI.derefSz])[0]
            except:
                FI.derefVal = int.from_bytes(sectionData[FI.offset:FI.offset + FI.derefSz],byteorder='little')
            # In the small/medium ABI model, it is safe to assume that
            # all FixupRefValues are the signed 32-bit integers
            # FIXME : Handle the large model (64-bit offset) in need - we do not care for now
            if is_cisc:
                FI.refTo = FI.VA + FI.derefSz + util.toSigned32(FI.derefVal) if FI.isRela else FI.derefVal


# binpang. Comment it
            FI.refBB = self.CI.getBBlByVA(FI.refTo)
            if FI.refBB:
                FI.target = "BB#%3s" % str(FI.refBB.idx)
                if FI.parent:
                    FI.parent.refFroms.append(FI.refBB)

                    '''
                    # [NEW] We only trace CFG of the function (i.e., cross reference)
                    #       iff a fixup points to the region within .text section
                    if self.sectionName == C.SEC_TEXT and FI.type == C.FT_C2C:
                        fixupFunc, refBBFunc = FI.parent.parent, FI.refBB.parent

                        if fixupFunc.idx != refBBFunc.idx:
                            # For direct references (either by calls or jump families)
                            # For indirect references using JT, see updateFixupRefs1() in reorderEngine
                            fixupFunc.refTos.add(refBBFunc)
                            refBBFunc.refFroms.add(fixupFunc)
                    '''

            else:
                FI.target = self.elfParser.getSectionByVA(FI.refTo)
                nopBytes = util.countRefToNops(sectionData, FI)
                if FI.target == C.SEC_TEXT and nopBytes > 0:
                    FI.refBB = self.CI.getBBlByVA(FI.refTo + nopBytes)
                    logging.warning("\tFound the Fixup that points to a NOP block: refBBL adjusted to the next BBL")
                    if FI.refBB:
                        FI.target = "BB#%3s" % str(FI.refBB.idx)

        # Since we do not have BBL information for special sections,
        #       a) Find the corresponding BBL here
        #       b) Patching fixup should be done in patchCodeSection() in a binaryBuilder class
        if self.hasSpecialSection():
            for FI in self.FixupsLayoutSpecial:
                findFixupTarget(FI)

        if self.hasOrphanFixups():
            for FI in self.FixupsLayoutOrphan:
                findFixupTarget(FI)
                logging.info("Orphan Fixup (maybe -cfi-icall?): %s" % (FI))

    def verifyFixups(self):
        """ Processes fixup verification not to screw up further randomization """
        sn = self.sectionName
        saneFlag = True

        if len(set([FI.offset for FI in self.FixupsLayout])) < self.numFixups:
            logging.warning('\t[%s] There are redundant fixups!' % (sn))
            saneFlag = False

        if sn == C.SEC_TEXT:
            for FI in self.FixupsLayout:
                if FI.type not in C.FIXUP_TYPE:
                    logging.warning('\t[%s] Has unknown type (Fixup#%d): %s' % (sn, FI.idx, C.FIXUP_TYPE[FI.type]))
                    saneFlag = False
                if FI.type == C.FT_D2C or FI.type == C.FT_D2D:
                    logging.warning('\t[%s] Has wrong type (Fixup#%d): %s' % (sn, FI.idx, C.FIXUP_TYPE[FI.type]))
                    saneFlag = False
                if FI.type == C.FT_C2C and not FI.refBB:
                    if FI.parent.parent.parent.srcKind == C.SRC_TYPE_ASSEMBLY:
                        logging.warning("\t[%s] Fixup %d comes from standalone assembly (Obj#%d)!" %
                                        (sn, FI.idx, FI.parent.parent.parent.idx))
                        continue
                    else:
                        logging.warning('\t[%s] Fails to discover the reference BBL (Fixup#%d)' % (sn, FI.idx))
                        saneFlag = False
                if FI.VA < FI.parent.VA:
                    logging.warning('\t[%s] Has wrong Fixup VA: VA(Parent BBL)=0x%04x VS VA(Fixup)=0x%04x'
                                   % (sn, FI.parent.VA, FI.VA))
                    saneFlag = False
                if FI.type != C.FT_C2D and FI.numJTEntries > 0:
                    logging.warning('\t[%s] Refers a jump table from non-C2D type (Fixup#%d)' % (sn, FI.idx))
                    saneFlag = False

        if sn == C.SEC_RODATA or sn == C.SEC_DATA or sn == C.SEC_DATA_REL:
            for FI in self.FixupsLayout:
                if FI.type not in C.FIXUP_TYPE:
                    logging.warning('\t[%s] Has unknown type (Fixup#%d): %s' % (sn, FI.idx, C.FIXUP_TYPE[FI.type]))
                    saneFlag = False
                if FI.type == C.FT_C2C or FI.type == C.FT_C2D:
                    logging.warning('\t[%s] Has wrong type (Fixup#%d): %s' % (sn, FI.idx, C.FIXUP_TYPE[FI.type]))
                    saneFlag = False
                if FI.type == C.FT_D2C and not FI.isRela and not FI.refBB:
                    logging.warning('\t[%s] No legitimate RefBBL (Fixup#%d)' % (sn, FI.idx))
                    saneFlag = False

        return saneFlag

    def getFixups(self):
        """ Return the list of fixup(s) in a layout order """
        return self.FixupsLayout

    def getSpecialFixups(self):
        """ Return the list of special fixup(s) """
        return self.FixupsLayoutSpecial

    def getOrphanFixups(self):
        """ Return the list of special fixup(s) """
        return self.FixupsLayoutOrphan

    def show(self):
        """ Show the fixup layout in detail """
        logging.info("\tFixups in %s section: %d" % (self.sectionName, self.numFixups))
        for fixup in self.FixupsLayout:
            logging.info(fixup)

class EssentialInfo():
    def __init__(self, RI):
        """
        Construct the essential information based on the collected information from compiler toolchain
            a) Build the layout tree - basic blocks, functions, and objects
            b) Build the entire fixup info (.text, .rodata, .data.rel.ro, .data and .init_array section)
            c) Confirm if reconstructed data is sane before processing randomization
        :param RI:
        """

        # Pre-processing: data collection and preparation for building essential information
        binInfo = RI['bin_info']

        # objInfo = (RI['obj_size'], RI['obj_func_cnt'], RI['obj_src_type'], RI['obj_offset'], RI['obj_section'])
        funcInfo = (RI['func_size'], RI['func_bb_cnt'], RI['func_offset'], RI['func_section'], RI['func_type'])
        bbInfo = (RI['bb_size'], RI['bb_fixup_cnt'], RI['bb_fall_through'], RI['bb_offset'],  \
                RI['bb_section'], RI['bb_padding'], RI['bb_assemble'],RI['bb_type'])

        fixupsText      = (RI[C.DS_FIXUP_TEXT[0]], RI[C.DS_FIXUP_TEXT[1]],
                           RI[C.DS_FIXUP_TEXT[2]], RI[C.DS_FIXUP_TEXT[3]],
                           RI[C.DS_FIXUP_TEXT[4]], RI[C.DS_FIXUP_TEXT[5]],
                           RI[C.DS_FIXUP_TEXT[6]])
        fixupsRodata    = (RI[C.DS_FIXUP_RODATA[0]], RI[C.DS_FIXUP_RODATA[1]],
                           RI[C.DS_FIXUP_RODATA[2]], RI[C.DS_FIXUP_RODATA[3]],
                           RI[C.DS_FIXUP_RODATA[4]])
        fixupsData      = (RI[C.DS_FIXUP_DATA[0]], RI[C.DS_FIXUP_DATA[1]],
                           RI[C.DS_FIXUP_DATA[2]], RI[C.DS_FIXUP_DATA[3]],
                           RI[C.DS_FIXUP_DATA[4]])
        fixupsDataRel   = (RI[C.DS_FIXUP_DATAREL[0]], RI[C.DS_FIXUP_DATAREL[1]],
                           RI[C.DS_FIXUP_DATAREL[2]], RI[C.DS_FIXUP_DATAREL[3]],
                           RI[C.DS_FIXUP_DATAREL[4]])
        fixupsInitArray = (RI[C.DS_FIXUP_INIT_ARR[0]], RI[C.DS_FIXUP_INIT_ARR[1]],
                           RI[C.DS_FIXUP_INIT_ARR[2]], RI[C.DS_FIXUP_INIT_ARR[3]],
                           RI[C.DS_FIXUP_INIT_ARR[4]])
        
        self.fixaddresslist = list()
        self.fixupname = list()

        if len(RI[C.DS_FIXUP_TEXT[0]]) > 0:
            self.count_fixup_address(list(zip(*fixupsText)),C.SEC_TEXT)

        if len(RI[C.DS_FIXUP_RODATA[0]]) > 0:
            self.count_fixup_address(list(zip(*fixupsRodata)),C.SEC_RODATA)

        if len(RI[C.DS_FIXUP_DATA[0]]) > 0:
            self.count_fixup_address(list(zip(*fixupsData)),C.SEC_DATA)

        # comment it out for now. Have bug(when there exists both .data.rel.ro and .data.rel.ro.local
        #if len(RI[C.DS_FIXUP_DATAREL[0]]) > 0:
        #    self.FixupsInDataRel = count_fixup_address(zip(*fixupsDataRel), self.constructInfo, C.SEC_DATA_REL, bar)

        if len(RI[C.DS_FIXUP_INIT_ARR[0]]) > 0:
            self.count_fixup_address(list(zip(*fixupsInitArray)),C.SEC_INIT_ARR)


        
        layoutInfoCnt = len(RI['func_size']) + len(RI['bb_size'])
        self.fixupInfoCnt = len(RI[C.DS_FIXUP_TEXT[0]]) + len(RI[C.DS_FIXUP_RODATA[0]]) + \
                            len(RI[C.DS_FIXUP_DATA[0]]) + len(RI[C.DS_FIXUP_DATAREL[0]]) + \
                            len(RI[C.DS_FIXUP_INIT_ARR[0]])
        bar = util.ProgressBar(layoutInfoCnt + self.fixupInfoCnt)

        # a) Construct BasicBlocks, Functions, Objects and the binary in Bottom-Up way
        self.constructInfo = BasicBlocks(bar, binInfo, funcInfo, bbInfo,self.fixaddresslist,self.fixupname)
        self.constructInfo.show()
        # self.constructInfo.storeAlignSize(RI['align_size'])


        # b) Construct all fixups in .text, .rodata, .data, data.rel.ro, and .init_array
        self.FixupsInText, self.FixupsInRodata = None, None
        self.FixupsInData, self.FixupsInDataRel = None, None
        self.FixupsInInitArray, self.FixupsInEhframe = None, None
        self.processFixups(bar, RI, fixupsText, fixupsRodata, fixupsData, fixupsDataRel, fixupsInitArray)
        bar.finish()

        # c) Check if the provided data is appropriate for generating a variant
        # self.__sanityCheck(RI, self.constructInfo)

    def count_fixup_address(self,FixupData,sectionName):
        for idx in range(len(FixupData)):
            sec_name = None
            # Only .text section could have a jump table.
            if sectionName == C.SEC_TEXT:
                offset, derefSz, isRela, _type, secName, numJTEntries, jtEntrySz = FixupData[idx]
            else:
                offset, derefSz, isRela, _type, secName = FixupData[idx]

            # Relative address to section
            self.fixaddresslist.append(offset)
            self.fixupname.append(secName)

    def processFixups(self, bar, RI, fixupsText, fixupsRodata, fixupsData, fixupsDataRel, fixupsInitArray):
        """ If a section contains fixups, generate fixup instances """
        if len(RI[C.DS_FIXUP_TEXT[0]]) > 0:
            self.FixupsInText = Fixups(list(zip(*fixupsText)), self.constructInfo, C.SEC_TEXT, bar)

        # ReorderOffset does not need to be adjusted other than .text
        if len(RI[C.DS_FIXUP_RODATA[0]]) > 0:
            self.FixupsInRodata = Fixups(list(zip(*fixupsRodata)), self.constructInfo, C.SEC_RODATA, bar)

        if len(RI[C.DS_FIXUP_DATA[0]]) > 0:
            self.FixupsInData = Fixups(list(zip(*fixupsData)), self.constructInfo, C.SEC_DATA, bar)

        # comment it out for now. Have bug(when there exists both .data.rel.ro and .data.rel.ro.local
        #if len(RI[C.DS_FIXUP_DATAREL[0]]) > 0:
        #    self.FixupsInDataRel = Fixups(zip(*fixupsDataRel), self.constructInfo, C.SEC_DATA_REL, bar)

        if len(RI[C.DS_FIXUP_INIT_ARR[0]]) > 0:
            self.FixupsInInitArray = Fixups(list(zip(*fixupsInitArray)), self.constructInfo, C.SEC_INIT_ARR, bar)

    def __sanityCheck(self, RI, CI):
        """ Check if the provided data makes sense for transformation """
        binPath = RI['bin_info']['bin_path']
        logging.info("Sanity check for %s... " % binPath)

        # Assertion contains a series of significant sanity checks
        assert (os.path.isfile(binPath))
        #assert (CI.numObjects > 0 and CI.numFunctions > 0 and CI.numBasicBlocks > 0)
        assert (sum(RI['obj_size']) == sum(RI['func_size']) == sum(RI['bb_size']))
        # assert (CI.numObjects     == len(RI['obj_func_cnt']))
        assert (CI.numFunctions   == len(RI['func_bb_cnt']))
        assert (CI.numBasicBlocks == len(RI['bb_fixup_cnt']))
        assert (CI.numFixups == sum(RI['bb_fixup_cnt']))
        assert (len(RI['fixup_deref_size_ro']) == len(RI['fixup_offset_ro']))

        # Failing of the following checks requires further investigation
        if self.getFixupsText() and not self.FixupsInText.verifyFixups():
            logging.critical("\tVerification for Fixups in .text section has been failed!")

        if self.getFixupsRodata() and not self.FixupsInRodata.verifyFixups():
            logging.critical("\tVerification for Fixups in .rodata section has been failed!")

        if self.getFixupsData() and not self.FixupsInData.verifyFixups():
            logging.critical("\tVerification for Fixups in .data section has been failed!")

        if self.getFixupsDataRel() and not self.FixupsInDataRel.verifyFixups():
            logging.critical("\tVerification for Fixups in .data.rel section has been failed!")

        logging.info("\tAll sanity checks have been PASSED!!")

    def getInfo(self):
        """ Return the instance of this class """
        return self.constructInfo

    # Wrapper functions to obtain fixup(s) and to check if a section has any fixup
    def getFixupsText(self):
        """ Return fixup(s) in .text section if any """
        return self.FixupsInText.getFixups() if self.FixupsInText else None

    def getFixupsSpecial(self):
        """ Return special fixup(s) in .text section if any """
        if self.hasFixupsInText() and self.FixupsInText.hasSpecialSection():
            return self.FixupsInText.getSpecialFixups()

    def getFixupsOrphan(self):
        """ Return orphan fixup(s) in .text section if any """
        if self.hasFixupsInText() and self.FixupsInText.hasOrphanFixups():
            return self.FixupsInText.getOrphanFixups()

    def getFixupsRodata(self):
        """ Return fixup(s) in .rodata section if any """
        return self.FixupsInRodata.getFixups() if self.FixupsInRodata else None

    def getFixupsData(self):
        """ Return fixup(s) in .data section if any """
        return self.FixupsInData.getFixups() if self.FixupsInData else None

    def getFixupsDataRel(self):
        """ Return fixup(s) in .data.rel.ro section if any """
        return self.FixupsInDataRel.getFixups() if self.FixupsInDataRel else None

    def getFixupsInitArray(self):
        """ Return fixup(s) in .init_array section if any """
        return self.FixupsInInitArray.getFixups() if self.FixupsInInitArray else None

    def hasFixupsInText(self):
        """ Check if .text section has any fixup """
        return True if self.getFixupsText() else False

    def hasFixupsInRodata(self):
        """ Check if .rodata section has any fixup """
        return True if self.getFixupsRodata() else False

    def hasFixupsInData(self):
        """ Check if .data section has any fixup """
        return True if self.getFixupsData() else False

    def hasFixupsInDataRel(self):
        """ Check if .data.rel.ro section has any fixup """
        return True if self.getFixupsDataRel() else False

    def hasFixupsInInitArray(self):
        """ Check if .init_array section has any fixup """
        return True if self.getFixupsInitArray() else False

    def getNumFixups(self, section):
        """ Return the number of fixups for the given section """
        if section == C.SEC_TEXT:
            numFixupsText = self.FixupsInText.numFixups if self.hasFixupsInText() else 0
            numFixupsSpecial = self.FixupsInText.numFixupsSpecial \
                if self.hasFixupsInText() and self.FixupsInText.hasSpecialSection() else 0
            return (numFixupsText, numFixupsSpecial)

        if section == C.SEC_RODATA:
            return self.FixupsInRodata.numFixups if self.hasFixupsInRodata() else 0

        if section == C.SEC_DATA:
            return self.FixupsInData.numFixups if self.hasFixupsInData() else 0

        if section == C.SEC_DATA_REL:
            return self.FixupsInDataRel.numFixups if self.hasFixupsInDataRel() else 0

        if section == C.SEC_INIT_ARR:
            return self.FixupsInInitArray.numFixups if self.hasFixupsInInitArray() else 0

    def show(self, showlevel=1):
        """ Show the reconstructed layout (obj, fun, and bbl) in detail """
        logging.info('Reconstructed binary information from the metadata...')
        if showlevel > 0:
            for obj in self.constructInfo.getBinary().Objects:
                logging.info(obj)
                if showlevel > 1:
                    for fn in obj.Functions:
                        logging.info(fn)
                        if showlevel > 2:
                            for bbl in fn.BasicBlocks:
                                logging.info(bbl)
                                if showlevel > 3:
                                    for fixup in bbl.Fixups:
                                        logging.info(fixup)
