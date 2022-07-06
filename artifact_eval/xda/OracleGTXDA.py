import optparse
import logging
import blocks_pb2
from elftools.elf.elffile import ELFFile

def readSectionRange(binary, sec):
    sec_start = 0x0
    with open(binary, 'rb') as openFile:
        elf = ELFFile(openFile)
        elf_sec = elf.get_section_by_name(sec)
        if elf_sec:
            sec_start = elf_sec['sh_addr']
    return (sec_start, elf_sec['sh_size'], elf_sec['sh_offset'])

def dumpInstrs(mModule, binary):
    b_content = open(binary, 'rb').read()
    text_range = readSectionRange(binary, '.text')
    text_content = b_content[text_range[2]: text_range[1] + text_range[2]]

    def print_byte(addr, byte, type):
        print("%x %s" % (byte, type))

    for func in mModule.fuc:
        for bb in func.bb:
            for inst in bb.instructions:
                addr = inst.va
                if not (addr >= text_range[0] and addr < (text_range[0] + text_range[1])):
                    continue
                print_byte(addr, text_content[addr - text_range[0]], "S")
                for idx in range(inst.size - 1):
                    cur_addr = addr + idx + 1
                    print_byte(cur_addr, text_content[cur_addr - text_range[0]], "B")
            for padding_addr in range(bb.va + bb.size, bb.va + bb.size + bb.padding):
                print_byte(padding_addr, text_content[padding_addr - text_range[0]], "-")


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-g", "--groundtruth", dest = "groundtruth", action = "store", \
        type = "string", help = "ground truth file path", default = None)
    parser.add_option("-b", "--binaryFile", dest = "binaryFile", action = "store", \
        type = "string", help = "binary file path", default = None)

    (options, args) = parser.parse_args()

    if options.groundtruth == None:
        print("Please input the ground truth file")
        exit(-1)

    if options.binaryFile == None:
        print("Please input the binary file")
        exit(-1)

    mModule = blocks_pb2.module()

    try:
        f = open(options.groundtruth, 'rb')
        mModule.ParseFromString(f.read())
        f.close()
    except IOError:
        print("Could not open the file 0x%s" % options.groundtruth)
        exit(-1)

    dumpInstrs(mModule, options.binaryFile)


