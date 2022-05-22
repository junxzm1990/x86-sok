'''
Capstone do not support the regs_access api for mips architecture.
So this script find the regs_access of mips instructions.
'''
from capstone import mips



mips_indirect_branches = {mips.MIPS_INS_JR, mips.MIPS_INS_JR16, mips.MIPS_INS_JRC, mips.MIPS_INS_JALR, mips.MIPS_INS_JALRC, mips.MIPS_INS_JALRS, mips.MIPS_INS_JALRS16}
def isIndirect(inst):
    def mipsRet(inst):
        if inst.id == mips.MIPS_INS_JR:
            reg = inst.operands[0]
            if inst.reg_name(reg.value.reg) == 'ra':
                return True
        return False
    if inst.id in mips_indirect_branches and not mipsRet(inst):
        return True
    return False

mips_taint_blacklist_insns = {mips.MIPS_INS_SC, mips.MIPS_INS_SCD, mips.MIPS_INS_CACHE}
mips_taint_blacklist_groups = {mips.MIPS_GRP_BITCOUNT, mips.MIPS_GRP_DSP, mips.MIPS_GRP_FP64BIT, \
                    mips.MIPS_GRP_MICROMIPS,}

def stores_handler(insn):
    assert len(insn.operands) > 1, "store instructions should have more than one operand!"
    regs_read = list()
    regs_write = list()
    src_reg = insn.operands[0]
    regs_read.append(src_reg.reg)
    assert src_reg.type == mips.MIPS_OP_REG

    mem = insn.operands[1]
    assert mem.type == mips.MIPS_OP_MEM
    base_reg = mem.mem.base
    regs_read.append(base_reg)
    return (regs_read, regs_write)

def mfhi_handler(insn):
    assert len(insn.operands) == 1, "mfhi instruction should have only one operand!"
    regs_read = list()
    regs_write = list()
    regs_read.append(mips.MIPS_REG_HI)
    regs_write.append(insn.operands[0].reg)
    print(regs_read)
    print(regs_write)
    return (regs_read, regs_write)

def mthi_handler(insn):
    assert len(insn.operands) == 1, "mthi instruction should have only one operand!"
    regs_read = list()
    regs_write = list()
    regs_read.append(insn.operands[0].reg)
    regs_write.append(mips.MIPS_REG_HI)
    return (regs_read, regs_write)

def mflo_handler(insn):
    assert len(insn.operands) == 1, "mflo instruction should have only one operand!"
    regs_read = list()
    regs_write = list()
    regs_read.append(mips.MIPS_REG_LO)
    regs_write.append(insn.operands[0].reg)
    return (regs_read, regs_write)

def mtlo_handler(insn):
    assert len(insn.operands) == 1, "mtlo instruction should have only one operand!"
    regs_read = list()
    regs_write = list()
    regs_read.append(insn.operands[0].reg)
    regs_write.append(mips.MIPS_REG_LO)
    return (regs_read, regs_write)

def mul_div_handler(insn):
    assert len(insn.operands) >= 2, "mul/div instruction should have two operands!"
    regs_read = list()
    regs_write = list()
    regs_read.append(insn.operands[0].reg)
    regs_read.append(insn.operands[1].reg)
    regs_write.append(mips.MIPS_REG_LO)
    regs_write.append(mips.MIPS_REG_HI)
    return (regs_read, regs_write)

MIPS_HANDLERS = {
    mips.MIPS_INS_SB: stores_handler,
    mips.MIPS_INS_SB16: stores_handler,
    mips.MIPS_INS_SW: stores_handler,
    mips.MIPS_INS_SD: stores_handler,
    mips.MIPS_INS_SDL: stores_handler,
    mips.MIPS_INS_SDR: stores_handler,
    mips.MIPS_INS_ST: stores_handler,
    mips.MIPS_INS_SH: stores_handler,
    mips.MIPS_INS_SH16: stores_handler,
    mips.MIPS_INS_MFHI: mfhi_handler,
    mips.MIPS_INS_MTHI: mthi_handler,
    mips.MIPS_INS_MFLO: mflo_handler,
    mips.MIPS_INS_MTLO: mtlo_handler,
    mips.MIPS_INS_DIV: mul_div_handler,
    mips.MIPS_INS_DIVU: mul_div_handler,
    mips.MIPS_INS_MUL: mul_div_handler,
    mips.MIPS_INS_MULU: mul_div_handler
}

def get_instr_str(insn):
    return "0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str)

def regs_access(insn):
    regs_read = list()
    regs_write = list()
    if insn.id == 0 or insn.mnemonic == '.unhandled':
        return (regs_read, regs_write)

    if len(insn.operands) == 0:
        return (regs_read, regs_write)

    if insn.id in mips_taint_blacklist_insns:
        return (regs_read, regs_write)

    if len(mips_taint_blacklist_groups.union(set(insn.groups))) < (len(mips_taint_blacklist_groups) + len(set(insn.groups))):
        # logging.debug(f"instruction {insn} is in taint blacklist")
        return (regs_read, regs_write)

    if insn.id in MIPS_HANDLERS:
        return MIPS_HANDLERS[insn.id](insn)


    if len(insn.operands) == 1:
        #logging.warning("Wried, the instruction %s has only one operand!" % get_instr_str(insn))
        op = insn.operands[0]
        if op.type == mips.MIPS_OP_REG:
            regs_read.append(op.reg)
        elif op.type == mips.MIPS_OP_MEM:
            regs_read.append(op.mem.base)
        return (regs_read, regs_write)

    reg_write = insn.operands[0]
    assert reg_write.type == mips.MIPS_OP_REG, f"Wried, the first operand of {get_instr_str(insn)} is not register!"
    regs_write.append(reg_write.reg)

    for op in insn.operands[1:]:
        if op.type == mips.MIPS_OP_REG:
            regs_read.append(op.reg)
        elif op.type == mips.MIPS_OP_MEM:
            regs_read.append(op.mem.base)
    return (regs_read, regs_write)


def to_hex2(s):
    r = "".join("{0:02x}".format(c) for c in s)  # <-- Python 3 is OK
    while r[0] == '0': r = r[1:]
    return r

def to_x(s):
    from struct import pack
    if not s: return '0'
    x = pack(">q", s)
    while x[0] in ('\0', 0): x = x[1:]
    return to_hex2(x)

def print_insn_detail(insn):
    # print address, mnemonic and operands
    print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))

    # "data" instruction generated by SKIPDATA option has no detail
    if insn.id == 0:
        return

    if len(insn.operands) > 0:
        print("\top_count: %u" % len(insn.operands))
        c = -1
        print(insn.id)
        for i in insn.operands:
            c += 1
            if i.type == mips.MIPS_OP_REG:
                print("\t\toperands[%u].type: REG = %s" % (c, insn.reg_name(i.value.reg)))
            if i.type == mips.MIPS_OP_IMM:
                print("\t\toperands[%u].type: IMM = 0x%s" % (c, to_x(i.imm)))
            if i.type == mips.MIPS_OP_MEM:
                print("\t\toperands[%u].type: MEM" % c)
                if i.mem.base != 0:
                    print("\t\t\toperands[%u].mem.base: REG = %s" \
                        % (c, insn.reg_name(i.mem.base)))
                if i.mem.disp != 0:
                    print("\t\t\toperands[%u].mem.disp: 0x%s" \
                        % (c, to_x(i.mem.disp)))

def test():
    MIPS_CODE = b"\x3c\x09\x20\x46\x04\x00\x04\x45\x00\x00\x00\x00"
    import capstone as cs
    md = cs.Cs(cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS64 + cs.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    for insn in md.disasm(MIPS_CODE, 0x1000, count = 1):
        print_insn_detail(insn)
        if mips.MIPS_GRP_RET in insn.groups:
            print("This is return")
            exit(-1)
        if mips.MIPS_GRP_JUMP in insn.groups:
            print("this is jump.")

        if mips.MIPS_GRP_CALL in insn.groups:
            print("This is call")

        (regs_read, regs_write) = regs_access(insn)
        for reg in regs_read:
            print(reg)
            print("read: %s" % insn.reg_name(reg))
        for reg in regs_write:
            print(reg)
            print("write: %s" % insn.reg_name(reg))

if __name__ == '__main__':
    test()
