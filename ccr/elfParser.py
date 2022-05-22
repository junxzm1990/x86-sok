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

import sys,logging
import util 

try:
    from capstone import *
    from capstone.arm64 import *
    from capstone.arm import *
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.dynamic import DynamicSection
    from BlockUtil import *
    import bbinfoconfig as bbl
except ImportError:
    logging.critical("You need to install the following packages: elftools")
    sys.exit(1)

class ELFParser:
    """  Class to help ELF parsing """
    def __init__(self, filename):
        self.fn = filename
        self.f = open(self.fn, 'rb')
        self.bin = self.f.read()
        self.elf = ELFFile(self.f)
        self.md = Cs(bbl.BB_CS_MODE_1, bbl.BB_CS_MODE_2 + bbl.BB_ENDIAN)
        self.md.detail = True
        # section data
        self.section_data = dict()

        self.struct_elf = {
           'e_type': "Object File Type",
           'e_machine': "Architecture",
           'e_entry': "Entry Point VA",
           'e_phoff': "Program header table file offset",
           'e_shoff': "Section header table file offset",
           'e_ehsize': "ELF header size in bytes",
           'e_phentsize': "Program header table entry size",
           'e_phnum': "Program header table entry count",
           'e_shentsize': "Section header table entry size",
           'e_shnum': "Section header table entry count",
           'e_shstrndx': "Section header string table index"
        }

        self.struct_section = {
            'sh_type': "Section Type",
            'sh_addralign': "Section Address Align",
            'sh_offset': "Section Offset",
            'sh_entsize': "Section Entry Size",
            'sh_name': "Section Name",
            'sh_flags': "Section Flags",
            'sh_size': "Section Size",
            'sh_addr': "Section VA",
            'sh_link': "Section Link",
            'sh_info': "Section Info"
        }

        # Relocation Types: Value, Name, Field and Calculation from linux64-ABI
        self.struct_relocation = {
            0: "R_X86_64_NONE",             # none, none
            1: "R_X86_64_64",               # word64, S + A
            2: "R_X86_64_PC32",             # word32, S + A - P
            3: "R_X86_64_GOT32",            # word32, G + A
            4: "R_X86_64_PLT32",            # word32, L + A - P
            5: "R_X86_64_COPY",             # none, none
            6: "R_X86_64_GLOB_DAT",         # wordclass, S
            7: "R_X86_64_JUMP_SLOT",        # wordclass, S
            8: "R_X86_64_RELATIVE",         # wordclass, B + A
            9: "R_X86_64_GOTPCREL",         # word32, G + GOT + A - P
            10: "R_X86_64_32",              # word32, S + A
            11: "R_X86_64_32S",             # word32, S + A
            12: "R_X86_64_16",              # word16, S + A
            13: "R_X86_64_PC16",            # word16, S + A - P
            14: "R_X86_64_8",               # word8, S + A
            15: "R_X86_64_PC8",             # word8, S + A - P
            16: "R_X86_64_DTPMOD64",        # word64
            17: "R_X86_64_DTPOFF64",        # word64
            18: "R_X86_64_TPOFF64",         # word64
            19: "R_X86_64_TLSGD",           # word32
            20: "R_X86_64_TLSLD",           # word32
            21: "R_X86_64_DTPOFF32",        # word32
            22: "R_X86_64_GOTTPOFF",        # word32
            23: "R_X86_64_TPOFF32",         # word32
            24: "R_X86_64_PC64",            # word64, S + A - P (only for LP64)
            25: "R_X86_64_GOTOFF64",        # word64, S + A - GOT (only for LP64)
            26: "R_X86_64_GOTPC32",         # word32, GOT + A - P
            32: "R_X86_64_SIZE32",          # word32, Z + A
            33: "R_X86_64_SIZE64",          # word64, Z + A (only for LP64)
            34: "R_X86_64_GOTPC32_TLSDESC", # word32
            35: "R_X86_64_TLSDESC_CALL",    # none
            36: "R_X86_64_TLSDESC",         # word64 * 2
            37: "R_X86_64_IRELATIVE",       # wordclass, indirect (B + A)
            38: "R_X86_64_RELATIVE64"       # word64, B + A (only for ILP32 executable or shared objects)
        }

        self.section_ranges = {}
        self.extractSectionVAs()
        self.extractSectionData()

    def readElfHdr(self):
        print('ELF Header (%s)' % self.fn)
        elf_info = self.elf._parse_elf_header()

        for i in sorted(self.struct_elf.keys()):
            elf_decr = self.struct_elf[i].ljust(35)
            if isinstance(elf_info[i], int):
                val = '(' + hex(elf_info[i]) + ')'
                print("  %s: %s%s" % (elf_decr, elf_info[i], val.rjust(15)))
            else:
                print("  %s: %s" % (elf_decr, elf_info[i]))

    def readRelocations(self):
        """
        Read the relocation sections in a given ELF binary
        :return:
        """
        # There are several different sections for relocation:
        # '.rela.plt', '.rela.dyn', '.rel.plt', '.rel.dyn'
        # The postfix .dyn represents the table for dynamic linker
        reloc_section_names = ['.rela.plt', '.rela.dyn', '.rel.plt', '.rel.dyn']

        for reloc_name in reloc_section_names:
            rel = self.elf.get_section_by_name(reloc_name)
            if isinstance(rel, RelocationSection):
                print('Relocation Section: %s (%d)' % (reloc_name, rel.num_relocations()))
                # Lookup all entry attributes
                for i, r in enumerate(rel.iter_relocations()):
                    print('\t[%3d] Offset + Addend: %s +' % (i+1, hex(r['r_offset']))),
                    if 'rela' in reloc_name:
                        print(r['r_addend']),
                    print('\tInfo (Type, Symbol): %s (%s, %s)' \
                          % (hex(r['r_info']), self.struct_relocation[r['r_info_type']],r['r_info_sym']))

    def readSections(self):
        """ Read all sections in a given ELF binary """
        def sectionInfo(s):
            section = self.elf.get_section(s)
            
            # A section type is in its header, but the name was decoded and placed in a public attribute.
            print('  [%2d] Section %s' %(s, section.name))
            for s in sorted(self.struct_section.keys()):
                sec_desc = self.struct_section[s].ljust(25)
                print('\t%s : %s' % (sec_desc, section[s]))

            # Case: a section table contains a symbol table section
            if isinstance(section, SymbolTableSection):
                for sym_no in range(section.num_symbols()):
                    symbol = section.get_symbol(sym_no)
                    print("      [%2d] Symbol: %s (Ty=%-7s, Bind=%-6s, Sym_Other=%-7s, Shndx=%4s, Val=0x%x, Sz=0x%x)" % \
                          (sym_no, symbol.name, symbol['st_info']['type'], symbol['st_info']['bind'],
                           symbol['st_other']['visibility'], symbol['st_shndx'], symbol['st_value'], symbol['st_size']))

        sec_cnt = self.elf.num_sections()
        print('Found %s sections' % sec_cnt)
        for s in range(sec_cnt):
            sectionInfo(s)

    def extractSectionVAs(self):
        for s in range(1, self.elf.num_sections()):
            sec = self.elf.get_section(s)
            va = sec['sh_addr']
            if va > 0:
                self.section_ranges[sec.name] = ((va, va + sec['sh_size']))

    def extractSectionData(self):
        for s in range(1, self.elf.num_sections()):
            sec = self.elf.get_section(s)
            self.section_data[sec.name] = sec.data() + b' '

    def getSectionVA(self, sn):
       # if sn == '.data.rel.ro':
       #     secNames = self.section_ranges.keys()
       #     for sname in secNames:
       #         if sn in sname:
       #             return self.section_ranges[sname][0]
       # else:
       return self.section_ranges[sn][0] 

    def getSectionByVA(self, va):
        secNames = self.section_ranges.keys()
        for sn in secNames:
            s, e = self.section_ranges[sn]
            if s <= va < e:
                return sn

    def isVAinSection(self, kind, va):
        for s, e in self.section_ranges[kind]:
            if s <= va < e:
                return True

        return False
    def armRet(self,inst):
        if inst.mnemonic == "bx":
            for i in inst.operands:
                if i.type == bbl.BB_OP_REG and inst.reg_name(i.value.reg) == 'lr':
                    return True
        last_reg = ""
        if inst.mnemonic == "pop":
            for i in inst.operands:
                if i.type == bbl.BB_OP_REG:
                    last_reg = inst.reg_name(i.value.reg)
            if last_reg == "pc":
                return True
        if inst.mnemonic == "mov":
            cnt = 0
            reg = list()
            for i in inst.operands:
                if i.type == bbl.BB_OP_REG:
                    reg.append(inst.reg_name(i.value.reg))
                    cnt = cnt + 1
            if cnt == 2 and reg[0] == "pc" and reg[1] == 'lr':
                return True
        return False
    def armCheck(self,inst):
        cnt = 0
        reg = list()
        for i in inst.operands:
            if i.type == arm.ARM_OP_REG:
                reg.append(inst.reg_name(i.value.reg))
                cnt = cnt + 1
        if cnt > 0 and reg[0] == "pc":
            return True
        return False
    def multi_jump(self, pc, bbsize, sec_name, sec_va, bbtype, bgendian = False):
        data = self.section_data[sec_name]

        if bbl.BB_ARCH == 'MIPS':
            return (list(), list())

        addrst = pc - sec_va
        addred = pc + bbsize - sec_va
        # logging.info(f"[debug]: The section name is {sec_name}, pc is {pc}, addrst is {addrst}, addred is {addred}, sec_va is {sec_va}")

        #print("0x%x 0x%x 0x%x" %(pc,bbsize,sec_va))
        CODE = data[addrst: addred]
        arm64_sepcial_jump = {"tbnz","tbz","cbz","cbnz"}
        res = list()
        condtion = list()
        if (bbtype & 1 << 6) != 0:
            self.md.mode = bbl.BB_CS_MODE_3 + bbl.BB_ENDIAN
        else:
            self.md.mode = bbl.BB_CS_MODE_2 + bbl.BB_ENDIAN
        last_addr = pc
        for inst in self.md.disasm(CODE, pc):
            last_addr = inst.address + inst.size
            if inst.mnemonic == "bl" or inst.mnemonic == "blr":
                continue
            if bbl.BB_JUMP_FLAG in inst.groups or \
                bbl.BB_RET_FLAG in inst.groups or \
                    (bbl.BB_RET_FLAG == -1 and self.armRet(inst)) or \
                        (bbl.BB_RET_FLAG == -1 and self.armCheck(inst)) or \
                        "loop "in inst.mnemonic.lower():
                res.append(inst.address + inst.size)
                if bbl.BB_CC_AL == -1 or len(inst.operands) == 0:
                    condtion.append(False)
                elif inst.cc != bbl.BB_CC_AL and inst.cc != bbl.BB_CC_INVALID:
                    condtion.append(True)
                elif inst.mnemonic in arm64_sepcial_jump:
                    condtion.append(True)
                else:
                    condtion.append(False)
        if last_addr not in res:
            res.append(last_addr)
            condtion.append(False)
        return (res,condtion)

    def check_terminator(self,pc,sec_name,sec_va,bbtype,bgendian = False):
        data = self.section_data[sec_name]
        offset = pc - sec_va
        CODE = b''
        if bgendian:
            for i in range(offset,offset + 4):
                CODE = CODE + bytes([data[i]])
        else:
            for i in range(offset,offset + 4,-1):
                CODE = CODE + bytes([data[i]])
        if (bbtype & (1 << 6)) != 0:
            self.md.mode = bbl.BB_CS_MODE_3
        else:
            self.md.mode = bbl.BB_CS_MODE_2
        for inst in self.md.disasm(CODE, pc):
            #print("TT: 0x%x:\t%s\t%s" %(inst.address, inst.mnemonic, inst.op_str))
            if inst.mnemonic == "bl" or inst.mnemonic == "blr":
                continue
            if len(inst.operands) > 0:
                for i in inst.operands:
                    if bbl.BB_JUMP_FLAG in inst.groups or \
                        bbl.BB_RET_FLAG in inst.groups or \
                            (bbl.BB_RET_FLAG == -1 and self.armRet(inst)) or \
                        "loop "in inst.mnemonic.lower():
                        return True
                    return False
        return False
    def checkTBInstruction(self,fi):
        CODE = self.getBinaryCode(fi)
        pc = fi.VA
        self.md.mode = bbl.BB_CS_MODE_3

        for insn in self.md.disasm(CODE, pc):
            if insn.mnemonic == 'tbb' or insn.mnemonic == 'tbh':
                return True
            #logging.debug("0x%x:\t%s\t%s\t0x%x" %(insn.address, insn.mnemonic, insn.op_str, result))
        return False
    def getBinaryCode(self,fi):
        sn = fi.secName
        offset = fi.offset
        pc = fi.VA
        sz = 0x4
        data = self.section_data[sn]
        return data[offset: offset + sz]

    def getInsnSize(self,fi,bgendian,special_mode = False):
        pc = fi.VA
        if(special_mode):
            self.md.mode = bbl.BB_CS_MODE_3
        else:
            self.md.mode = bbl.BB_CS_MODE_2

        CODE = self.getBinaryCode(fi)
        for insn in self.md.disasm(CODE,pc):
            return insn.size
        return 0

    def getArmImmValue(self,fi,special_mode = False):
        CODE = self.getBinaryCode(fi)
        pc = fi.VA
        result = 0x0
        if(special_mode):
            self.md.mode = bbl.BB_CS_MODE_3
        else:
            self.md.mode = bbl.BB_CS_MODE_2

        for insn in self.md.disasm(CODE, pc):
            if len(insn.operands) > 0:
                for i in insn.operands:
                    if i.type == bbl.BB_OP_IMM:
                        result = i.value.imm
                        if result > 0x1f:
                            return result
            break
            #logging.debug("0x%x:\t%s\t%s\t0x%x" %(insn.address, insn.mnemonic, insn.op_str, result))
        return result

    # def getInstStr(i):
    #     if i == None or i.id == 0:
    #         return ""
    #     return "0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str)

    def getAccessReg(self,fi,special_mode = False):
        CODE = self.getBinaryCode(fi)
        pc = fi.VA
        if(special_mode):
            self.md.mode = bbl.BB_CS_MODE_3
        else:
            self.md.mode = bbl.BB_CS_MODE_2

        insns = self.md.disasm(CODE, pc)
        try:
            insn = next(insns)
        except Exception as e:
            print(e)
            return False
        if len(insn.operands) > 0:
            for i in insn.operands:
                if i.type == bbl.BB_OP_REG and insn.reg_name(i.value.reg) == "pc":
                    return True
                if i.type == bbl.BB_OP_MEM and i.value.mem.base != 0:
                    if insn.reg_name(i.value.mem.base) == "pc":
                        return True
        return False

if __name__ == '__main__':
    import os
    if len(sys.argv) != 2:
        print("Usage: %s [ELF file to parse]" % (sys.argv[0]))
        sys.exit(1)
    else:
        f = sys.argv[1]
        if os.path.exists(f):
            ep = ELFParser(f)
            ep.readSections()
            ep.readRelocations()
        else:
            print("No such file!")
