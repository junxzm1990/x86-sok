from capstone import x86 ## Change capstone from x86 to arm
from capstone import arm64
from capstone import arm
from capstone import mips
import capstone as cs
import logging


def init(ELF_ARCH, ELF_CLASS, ELF_ENDIAN):
    global BB_CALL_FLAG
    global BB_JUMP_FLAG
    global BB_RET_FLAG
    global BB_CS_MODE_1
    global BB_CS_MODE_2
    global BB_CS_MODE_3
    global BB_OP_REG
    global BB_OP_IMM
    global BB_OP_MEM
    global BB_OP_CIMM
    global BINARY_ARCH
    global BB_ENDIAN
    global BB_ARCH
    global BB_CC_AL
    global BB_CC_INVALID
    global BB_OP_SFT
    BB_ARCH = ELF_ARCH

    if ELF_ENDIAN:
        BB_ENDIAN = cs.CS_MODE_LITTLE_ENDIAN
    else:
        BB_ENDIAN = cs.CS_MODE_BIG_ENDIAN

    BINARY_ARCH = ELF_ARCH
    if ELF_ARCH == "AArch64":
        BB_CALL_FLAG = arm64.ARM64_GRP_CALL
        BB_JUMP_FLAG = arm64.ARM64_GRP_JUMP
        BB_RET_FLAG = arm64.ARM64_GRP_RET
        BB_CS_MODE_1 = cs.CS_ARCH_ARM64
        BB_CS_MODE_2 = cs.CS_MODE_ARM
        BB_CS_MODE_3 = BB_CS_MODE_2
        BB_OP_REG = arm64.ARM64_OP_REG
        BB_OP_IMM = arm64.ARM64_OP_IMM
        BB_OP_MEM = arm64.ARM64_OP_MEM
        BB_OP_CIMM = arm64.ARM64_OP_CIMM
        BB_CC_AL = arm64.ARM64_CC_AL
        BB_OP_SFT = arm64.ARM64_SFT_INVALID
        BB_CC_INVALID = arm64.ARM64_CC_INVALID
    elif ELF_ARCH == 'x86' or ELF_ARCH == 'x64':
        BB_CALL_FLAG = x86.X86_GRP_CALL
        BB_JUMP_FLAG = x86.X86_GRP_JUMP
        BB_RET_FLAG = x86.X86_GRP_RET
        BB_CS_MODE_1 = cs.CS_ARCH_X86
        BB_OP_REG = x86.X86_OP_REG
        BB_OP_IMM = x86.X86_OP_IMM
        BB_OP_CIMM = x86.X86_OP_IMM #x86 don't have this op
        BB_OP_MEM = x86.X86_OP_MEM
        BB_OP_SFT = -1 # x86 does not have shift flag, need special handling
        BB_CC_AL = -1
        BB_CC_INVALID = -1
        if ELF_CLASS == 64:
            BB_CS_MODE_2 = cs.CS_MODE_64
        elif ELF_CLASS == 32:
            BB_CS_MODE_2 = cs.CS_MODE_32
        else:
            logging.error("Architecture {} bits not supported yet!".format(ELF_CLASS))
            exit(-1)
        BB_CS_MODE_3 = BB_CS_MODE_2
    elif ELF_ARCH == 'ARM':
        BB_CALL_FLAG = arm.ARM_GRP_CALL
        BB_JUMP_FLAG = arm.ARM_GRP_JUMP
        BB_RET_FLAG = -1 # arm does not have ret, need special handling
        BB_CS_MODE_1 = cs.CS_ARCH_ARM
        BB_CS_MODE_2 = cs.CS_MODE_ARM
        BB_CS_MODE_3 = cs.CS_MODE_THUMB
        BB_OP_REG = arm.ARM_OP_REG
        BB_OP_IMM = arm.ARM_OP_IMM
        BB_OP_CIMM = arm.ARM_OP_CIMM
        BB_OP_MEM = arm.ARM_OP_MEM
        BB_CC_AL = arm.ARM_CC_AL
        BB_OP_SFT = arm.ARM_SFT_INVALID
        BB_CC_INVALID = arm.ARM_CC_INVALID
    elif ELF_ARCH == 'MIPS':
        BB_CALL_FLAG = mips.MIPS_GRP_CALL
        BB_JUMP_FLAG = mips.MIPS_GRP_JUMP
        BB_RET_FLAG = -1 # mips does not have ret, need special handling
        BB_CS_MODE_1 = cs.CS_ARCH_MIPS # only support MIPS3 for now.
        if ELF_CLASS == 64:
            BB_CS_MODE_2 = cs.CS_MODE_MIPS64
        elif ELF_CLASS == 32:
            BB_CS_MODE_2 = cs.CS_MODE_MIPS32
        else:
            logging.error("Architecture {} bits not supported yet!".format(ELF_CLASS))
        BB_CS_MODE_3 = BB_CS_MODE_2

        BB_OP_REG = mips.MIPS_OP_REG
        BB_OP_IMM = mips.MIPS_OP_IMM
        BB_OP_CIMM = mips.MIPS_OP_IMM
        BB_OP_MEM = mips.MIPS_OP_MEM
        BB_OP_SFT = -1 # mips does not have shift flag, need special handling
        BB_CC_AL = -1