from ctypes import sizeof
import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.elffile import RelocationSection
from elftools.elf.relocation import Relocation
import struct
import capstone as cs
from capstone import mips
import logging


R_MIPS_NONE=0
R_MIPS_16=1
R_MIPS_32=2
R_MIPS_REL32=3
R_MIPS_26=4
R_MIPS_HI16=5
R_MIPS_LO16=6
R_MIPS_GPREL16=7
R_MIPS_LITERAL=8
R_MIPS_GOT16=9
R_MIPS_PC16=10
R_MIPS_CALL16=11
R_MIPS_GPREL32=12
R_MIPS_SHIFT5=16
R_MIPS_SHIFT6=17
R_MIPS_64=18
R_MIPS_GOT_DISP=19
R_MIPS_GOT_PAGE=20
R_MIPS_GOT_OFST=21
R_MIPS_GOT_HI16=22
R_MIPS_GOT_LO16=23
R_MIPS_SUB=24
R_MIPS_INSERT_A=25
R_MIPS_INSERT_B=26
R_MIPS_DELETE=27
R_MIPS_HIGHER=28
R_MIPS_HIGHEST=29
R_MIPS_CALL_HI16=30
R_MIPS_CALL_LO16=31
R_MIPS_SCN_DISP=32
R_MIPS_REL16=33
R_MIPS_ADD_IMMEDIATE=34
R_MIPS_PJUMP=35
R_MIPS_RELGOT=36
R_MIPS_JALR=37
R_MIPS_TLS_DTPMOD32=38
R_MIPS_TLS_DTPREL32=39
R_MIPS_TLS_DTPMOD64=40
R_MIPS_TLS_DTPREL64=41
R_MIPS_TLS_GD=42
R_MIPS_TLS_LDM=43
R_MIPS_TLS_DTPREL_HI16=44
R_MIPS_TLS_DTPREL_LO16=45
R_MIPS_TLS_GOTTPREL=46
R_MIPS_TLS_TPREL32=47
R_MIPS_TLS_TPREL64=48
R_MIPS_TLS_TPREL_HI16=49
R_MIPS_TLS_TPREL_LO16=50
R_MIPS_GLOB_DAT=51
R_MIPS_COPY=126
R_MIPS_JUMP_SLOT=127

MIPS_ARCH = 32
md = None

'''
Relocation type:

R_MIPS_16: 1            => S + sign-extend(A)
R_MIPS_32: 2            => S + A
R_MIPS_REL32: 3           => A - EA + S
R_MIPS_26: 4            => local: ((A << 2) | (r_offset & 0xf000000) + S) >> 2
                        => external: (sign-extend(A << 2) + S) >> 2
R_MIPS_HI16: 5
R_MIPS_LO16: 6
R_MIPS_GPREL16: 7       => external: sign-extend(A) + S + GP
                        => local: sign-extend(A) + S + GP0 - GP
R_MIPS_LITERAL: 8       => local: sign-extend(A) + L
R_MIPS_GOT16:   9       => G
R_MIPS_PC16: 10         => external: sign-extend(A) + S - P
R_MIPS_CALL16: 11       => external: G
R_MIPS_GPREL32: 12      => A + S + GP0 - GP
R_MIPS_GOTHI16: 21      => (G - (short)G) >> 16 + A
R_MIPS_GOTLO16: 22      => G & 0xffff
R_MIPS_CALLHI16: 30     => (G - (short)G) >> 16 + A
R_MIPS_CALLLO16L 31     => G & 0xffff
'''
def sign_extend(value, bits):
    sign_bit = 1 << (bits - 1)
    return (value & (sign_bit - 1)) - (value & sign_bit)

def read_loaded_base_addr(elf):
    for seg in elf.iter_segments():
        if seg['p_type'] == 'PT_LOAD':
            return seg['p_vaddr']
    return 0

def read_got_plt_addr(elf):
    got_plt = elf.get_section_by_name(".got")
    if got_plt != None:
        return (got_plt['sh_addr'], got_plt['sh_size'], got_plt['sh_offset'])
    return 0

def read_mips_jalr_relos(binary):
    '''
    read jalr relocations to resolve the target of direct calls
    '''
    reloc_sections_names = ['.rel.text', '.rela.text']
    b = open(binary, 'rb')
    elf = ELFFile(b)
    result = dict()
    if elf.get_machine_arch() != "MIPS":
        return (None, set())

    for reloc_name in reloc_sections_names:
        rel = elf.get_section_by_name(reloc_name)

        if rel is None:
            continue

        symtbl = elf.get_section(rel['sh_link'])
        if isinstance(rel, RelocationSection):
            for _, r in enumerate(rel.iter_relocations()):
                r_type = r['r_info_type']
                if r_type != R_MIPS_JALR:
                    continue

                sym = symtbl.get_symbol(r['r_info_sym'])
                sym_v = sym['st_value']
                sym_name = sym.name

                result[r['r_offset']] = (sym_v, sym_name)

    b.close()
    return result

def init_md():
    global md
    mode = cs.CS_MODE_MIPS32
    if MIPS_ARCH == 64:
        mode = cs.CS_MODE_MIPS64
    md = cs.Cs(cs.CS_ARCH_MIPS, mode + cs.CS_MODE_LITTLE_ENDIAN)
    md.detail = True

'''
Calculate the value of reference to of mips.
'''
def resolve_refs(binary):
    '''
    calcualte the value of referecne to

    @arg:
        binary: elf binary

    @ret:
        dict of {ref: refto}
    '''
    global mips_last_got
    global mips_last_hi16
    global mips_last_gp
    global LO16_STATE   # 0 represents there is no pairs;
                       # 1 represents that the last one is HI16 disp
                        # 2 represents that the last one is general
    LO16_STATE = 0
    mips_last_got = None
    mips_last_hi16 = None
    mips_last_gp = 0

    def read_func_ranges(binary):
        funcs = list()
        with open(binary, 'rb') as open_b:
            elf = ELFFile(open_b)
            sym_sec = elf.get_section_by_name('.symtab')
            if sym_sec is None:
                logging.error("Do not contain symbol information")
                exit(-1)
            for sym in sym_sec.iter_symbols():
                addr = sym['st_value']
                if 'STT_FUNC' == sym.entry['st_info']['type']:
                    funcs.append((addr, sym['st_size']))
        return funcs

    def get_func_start(funcs, addr):

        for (start, size) in funcs:
            if addr >= start and addr < start + size:
                return start
        return None


    def resolve_refto(data, r, offset, got_plt, base_addr, sym, funcs):
        global mips_last_got
        global mips_last_hi16
        global mips_last_gp
        global LO16_STATE

        if MIPS_ARCH == 64:
            sym_v = sym['st_value']
            addend = r['r_addend']
            val = sym_v + addend
            return val

        def is_local_sym(sym):
            if sym['st_info']['bind'] == 'STB_LOCAL':
                return True
            return False

        (got_plt_addr, got_plt_size, got_plt_base) = got_plt
        # gp_global = got_plt_addr + 0x7ff0
        # got_offset = 0x7ff0
        # clang_got_offset = 0x28010
        val = None
        r_type = r['r_info_type']
        fmt = {1: "<b", 2: "<h", 4: "<i", 8: "<q"}
        if r_type == R_MIPS_GOT16:
            size = 2
            rel_val = sign_extend(struct.unpack(fmt[size],
                                            data[offset: offset + size])[0], 16)


            val = rel_val + mips_last_gp
            # print("offset is 0x%x, val is 0x%x, last gp is 0x%x" % (r['r_offset'], val, mips_last_gp))

            v_offset = val - base_addr
            if val > got_plt_addr + got_plt_size or val < got_plt_addr:
                # print("HELLLO, val is 0x%x, v_offset is 0x%x, got addr is 0x%x, size is 0x%x" % (val, v_offset, got_plt_addr, got_plt_size))
                return None
            got_v_offset = val - got_plt_addr + got_plt_base
            # print(sym.name) # if the name is _gp_disp
            # print(sym['st_info']['bind']) # the bind is 'STB_LOCAL'
            # if is_local_sym(sym):
            mips_last_got = struct.unpack(fmt[4],
                                    data[got_v_offset: got_v_offset + 4])[0]
            mips_last_hi16 = None
            # print("mips last got is 0x%x" % mips_last_got)

        elif r_type == R_MIPS_LO16:
            if mips_last_got == None and mips_last_hi16 == None:
                # print("HELLO???")
                return None

            size = 2
            rel_val = sign_extend(struct.unpack(fmt[size],
                                                data[offset: offset + size])[0], 16)
            if mips_last_got is not None:
                val = mips_last_got + rel_val
                # print("mips_last got is 0x%x, val is 0x%x" % (mips_last_got, val))
            else:
                val = mips_last_hi16 + rel_val
                # print("lo16 val is 0x%x" % val)
                if LO16_STATE == 1:
                    func_start = get_func_start(funcs, r['r_offset'])
                    mips_last_gp = val
                    if func_start != None:
                        mips_last_gp += func_start
                    # print("offset is 0x%x, last gp is 0x%x" % (r['r_offset'], mips_last_gp))
            LO16_STATE = 0
            mips_last_got = None
            mips_last_hi16 = None


        elif r_type == R_MIPS_HI16:
            h_v = sign_extend(int.from_bytes(data[offset: offset + 2], byteorder='little'), 16)
            h_v = h_v << 16
            val = h_v
            mips_last_hi16 = h_v
            if sym.name == "__gnu_local_gp" or sym.name == "_gp_disp":
                LO16_STATE = 1
            else:
                LO16_STATE = 2

            mips_last_got = None

                # print("The offset is 0x%x, val is 0x%x" % (offset, mips_last_hi16))

        elif r_type == R_MIPS_16:
            size = 2
            rel_val = sign_extend(struct.unpack(fmt[size], data[offset: offset + size])[0], 16)
            # sym_v = sym['st_value']
            # val = sym_v + rel_val
            val = rel_val
        elif r_type == R_MIPS_32:
            size = 4
            rel_val = struct.unpack(fmt[size], data[offset: offset + size])[0]
            # sym_v = sym['st_value']
            val = rel_val
            # print("R_MIPS_32 value is 0x%x" % val)
        elif r_type == R_MIPS_REL32:
            pass

        elif r_type == R_MIPS_GPREL32:
            size = 4
            rel_val = sign_extend(struct.unpack(fmt[size],
                                        data[offset: offset + size])[0], 32)
            # print("rel_val is %d, last gp is 0x%x" % (rel_val, mips_last_gp))
            val = rel_val + mips_last_gp
            # print("val is 0x%x" % val)

        elif r_type == R_MIPS_GPREL16:
            size = 2
            rel_val = sign_extend(struct.unpack(fmt[size],
                                        data[offset: offset + size])[0], 16)
            val = rel_val + mips_last_gp
        elif r_type in {R_MIPS_CALL16, R_MIPS_CALL_HI16, R_MIPS_CALL_LO16}:
            sym_v = sym['st_value']
            val = sym_v

        return val

    reloc_sections_names = ['.rel.text', '.rela.text', '.rel.rodata', '.rel.data', ".rela.rodata", ".rela.data"]
    b = open(binary, 'rb')
    b2 = open(binary, 'rb')
    content = b2.read()
    b2.close()
    elf = ELFFile(b)

    if elf.get_machine_arch() != "MIPS":
        return (None, set())

    base_addr = read_loaded_base_addr(elf)
    got_plt_info = read_got_plt_addr(elf)
    global MIPS_ARCH
    MIPS_ARCH = elf.elfclass
    res = dict()
    jmp_tbl_blk = set()

    funcs = read_func_ranges(binary)

    init_md()

    for reloc_name in reloc_sections_names:
        rel = elf.get_section_by_name(reloc_name)
        if rel is None:
            continue
        symtbl = elf.get_section(rel['sh_link'])
        if isinstance(rel, RelocationSection):
            # print('Relocation Section: %s (%d)' % (reloc_name, rel.num_relocations()))
            for i, r in enumerate(rel.iter_relocations()):
                #print('\t[%3d] Offset + Addend: %s +' % (i+1, hex(r['r_offset'])))
                # print("Offset is 0x%x" % r['r_offset'])
                sym = symtbl.get_symbol(r['r_info_sym'])
                val = resolve_refto(content, r, \
                                                r['r_offset'] - base_addr, got_plt_info, base_addr, sym, funcs)

                if val is not None:
                    res[r['r_offset']] = val

                if r['r_info_type'] == R_MIPS_GOT16 or r['r_info_type'] == R_MIPS_HI16:
                    jmp_tbl_blk.add(r['r_offset'])


    return (res, jmp_tbl_blk)

if __name__ == "__main__":
    resolve_refs(sys.argv[1])