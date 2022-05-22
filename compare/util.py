from elftools.elf.elffile import ELFFile

def is_arm(file):
    with open(file, 'rb') as openFile:
        elffile = ELFFile(openFile)
        machine = elffile.header['e_machine']
        if machine == "EM_ARM" or machine == "EM_AARCH64":
            return True
    return False