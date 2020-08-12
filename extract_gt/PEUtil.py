import pefile
import string
import logging
import os
import random
import pepy

def getIats(binary, IAT_BASE):
    p = pepy.parse(binary)
    all_imports = set()
    for iobj in p.get_imports():
        all_imports.add(iobj.addr + IAT_BASE)
        logging.debug("iat obj %s at 0x%x" % (iobj.sym, iobj.addr + IAT_BASE))
    return all_imports

class section_t:
    def __init__(self, name_, addr_, size_, offset_, idx_):
        self.addr = addr_
        self.size = size_
        self.offset = offset_
        self.idx = idx_
        self.name = name_

def getPEType(type_int):
    IMAGE_FILE_MACHINE_I386 = 0x14c
    IMAGE_FILE_MACHINe_AMD64 = 0x8664
    result = -1
    if type_int == IMAGE_FILE_MACHINE_I386:
        result = 32
    else:
        result = 64
    return result

def parsePEFile(binaryfile):
    pe = pefile.PE(binaryfile)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    class_type = getPEType(pe.FILE_HEADER.Machine)
    if class_type == -1:
        logging.error("Don't support the machine type 0x%x", pe.FILE_HEADER.Machine)
        exit(-2)
    logging.info("binary image base is 0x%x, x86 %d bits" % (image_base, class_type))
    return (image_base, class_type)

def parsePEExecSecs(binaryfile):
    exec_secs = list()
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    pe = pefile.PE(binaryfile)
    for section in pe.sections:
        logging.debug("current section is 0x%x", section.Characteristics)
        if section.Characteristics & IMAGE_SCN_MEM_EXECUTE:
            exec_secs.append(section_t(section.Name, section.VirtualAddress, section.SizeOfRawData, section.PointerToRawData, 0))
            logging.debug("section: addr 0x%x, size 0x%x, file offset 0x%x", section.VirtualAddress, section.SizeOfRawData, section.PointerToRawData)
    return exec_secs

def parsePERdata(binaryfile):
    rdata = None
    pe = pefile.PE(binaryfile)
    for section in pe.sections:
        if section.Name == "rdata":
            rdata = section_t(section.Name, section.VirtualAddress, section.SizeOfRawData, section.PointerToRawData, 0)
            break
    return rdata

def randomString(stringLength=10):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

def parsePESecs(binaryfile):
    secs = list()
    pe = pefile.PE(binaryfile)
    idx = 0
    for section in pe.sections:
        idx += 1
        secs.append(section_t(section.Name, section.VirtualAddress, section.Misc_VirtualSize, section.PointerToRawData, idx))
        logging.debug("section %s: addr 0x%x, size 0x%x, file offset 0x%x, idx %d", section.Name, section.VirtualAddress, section.SizeOfRawData, section.PointerToRawData, idx)
    return secs

def parseFuncs(pdbfile, secs_list, image_base):
    result = dict()
    rand_output = randomString()
    try:
        os.system("llvm-pdbutil dump -symbols %s > /tmp/%s" % (pdbfile, rand_output))
    except:
        logging.error("Parseing thunk symbols error!")
        os.system('rm /tmp/%s' % (rand_output))
        return result
    with open("/tmp/%s" % (rand_output), 'r') as sym_file:
        for line in sym_file:
            if 'S_GPROC' in line or 'S_LPROC' in line:
                next_line = next(sym_file).strip()
                if 'addr' not in next_line:
                    continue
                size = int(next_line.split(' ')[-1])
                addr = next_line.split(',')[-2].strip()
                addr = addr.split(' ')[-1].strip()
                sec_str = addr.split(':')
                sec_id = int(sec_str[0])
                addr = int(sec_str[1])
                cur_addr = -1
                for sec in secs_list:
                    if sec.idx == sec_id:
                        cur_addr = sec.addr + addr + image_base
                        break
                if cur_addr == -1:
                    continue
                result[cur_addr] = cur_addr + size - 1
    os.system('rm /tmp/%s' % (rand_output))
    return result


def parseThunkSyms(pdbfile, secs_list, image_base):
    rand_output = randomString()
    result = set()
    try: 
        os.system("llvm-pdbutil dump -symbols %s | grep thunk > /tmp/%s" % (pdbfile, rand_output))
    except:
        logging.error("Parseing thunk symbols error!")
        os.system('rm /tmp/%s' % (rand_output))
        return result

    with open("/tmp/%s" % (rand_output), 'r') as sym_file:
        for line in sym_file.readlines():
            if 'kind = thunk' in line:
                cur_split = line.strip().split(' ')
                assert len(cur_split) > 0
                addr_str = cur_split[-1]
                sec_addr = addr_str.strip().split(':')
                assert len(sec_addr) > 1
                sec_id = int(sec_addr[0])
                offset = int(sec_addr[1])
                cur_addr = -1
                for sec in secs_list:
                    if sec.idx == sec_id:
                        cur_addr = sec.addr + offset + image_base
                        break
                if cur_addr == -1:
                    logging.error("[Parse Thunk Error]: can't find sec id for thunk:(sec id %d, offset %d)" % (sec_id, offset))
                logging.debug("[Thunk]: 0x%x" % cur_addr)
                result.add(cur_addr)

    os.system('rm /tmp/%s' % (rand_output))
    return result

def get_file_offset(exec_secs, va, image_base):
    offset = None
    for cur_sec in exec_secs:
        if va >= cur_sec.addr + image_base and va <=  image_base + cur_sec.addr + cur_sec.size:
            offset = va - image_base - cur_sec.addr + cur_sec.offset
            break
    return offset
