from capstone import *
from capstone.arm64 import *
from capstone import arm64
from capstone.arm import *
from capstone import arm
from capstone.arm_const import ARM_OP_REG
import bbinfoconfig as bbl

BB_CALL_FLAG = arm64.ARM64_GRP_CALL
BB_JUMP_FLAG = arm64.ARM64_GRP_JUMP
BB_RET_FLAG = arm64.ARM64_GRP_RET
BB_OP_REG = ARM64_OP_REG
BB_OP_IMM = ARM64_OP_IMM
BB_OP_MEM = ARM64_OP_MEM

# ztt add to handle the arm ret
def armRet(inst):
    if inst.mnemonic == "bx":
        for i in inst.operands:
            if i.type == ARM_OP_REG and inst.reg_name(i.value.reg) == 'lr':
                return True
    last_reg = ""
    if inst.mnemonic == "pop":
        for i in inst.operands:
            if i.type == ARM_OP_REG:
                last_reg = inst.reg_name(i.value.reg)
        if last_reg == "pc":
            return True
    return False
def isTerminator(inst):
    if inst.id == 0:
        return False
    '''
    if x86.X86_GRP_JUMP in inst.groups or \
        x86.X86_GRP_RET in inst.groups or \
        x86.X86_GRP_CALL in inst.groups or \
        "loop "in inst.mnemonic.lower() or \
        inst.op_str in TERMINAL_LIST or inst.mnemonic in TERMINAL_LIST:
    '''
    if BB_JUMP_FLAG in inst.groups or \
            BB_RET_FLAG in inst.groups or \
                (BB_RET_FLAG == - 1 and armRet(inst)) or \
                bbl.BB_CALL_FLAG in inst.groups or \
            "loop "in inst.mnemonic.lower() or \
            inst.op_str in TERMINAL_LIST or inst.mnemonic in TERMINAL_LIST:
        return True
    return False

# CODE = b"\x10\x00\x03\xde\x12\x10\x00\x00\x2d\x18\x62\x00\x00\x00\x6a\x8c\x13\x00\x00\x10\x25\x10\x00\x00"
# CODE = b"\xa8\x80\x95\xdf\x09\x00\xe2\xdc"
CODE = b"\x00\x00\xa2\xff"
#CODE = b"\x00\x08\x2d\xe9"
# bbl.init()
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64)
# md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
# md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
# md = Cs(CS_ARCH_X86,CS_MODE_64)

md.detail = True
for insn in md.disasm(CODE, 0xe860):
    print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))
    # if ARM_GRP_JUMP in insn.groups:
    #     print("T:JUMP!!!!!\n")
    if len(insn.operands) > 0:
        print("\tNumber of operands: %u" %len(insn.operands))
        c = -1
        for i in insn.operands:
            c += 1
            if i.type == ARM_OP_REG:
                print("\t\toperands[%u].type: REG = %s" %(c, insn.reg_name(i.value.reg)))
            if i.type == ARM_OP_IMM:
                print("\t\toperands[%u].type: IMM = 0x%x" %(c, i.value.imm))
            if i.type == ARM_OP_CIMM:
                print("\t\toperands[%u].type: C-IMM = %u" %(c, i.value.imm))
            if i.type == ARM_OP_FP:
                print("\t\toperands[%u].type: FP = %f" %(c, i.value.fp))
            if i.type == ARM_OP_MEM:
                print("\t\toperands[%u].type: MEM" %c)

                if i.value.mem.base != 0:
                    print("\t\t\toperands[%u].mem.base: REG = %s" \
                        %(c, insn.reg_name(i.value.mem.base)))
                # if i.value.mem.index != 0:
                #     print("\t\t\toperands[%u].mem.index: REG = %s" \
                #         %(c, insn.reg_name(i.value.mem.index)))
                # if i.shift.type != ARM_SFT_INVALID and i.shift.value:
                #     print("\t\t\tShift: type = %u, value = %u" \
                #     %(i.shift.type, i.shift.value))
                if i.value.mem.disp != 0:
                    print("\t\t\toperands[%u].mem.disp: 0x%x" \
                        %(c, i.value.mem.disp))
        # if insn.cc != arm64.ARM64_CC_AL and insn.cc != arm64.ARM64_CC_INVALID:
        # print("\tCode condition: %u" %insn.cc)
