import capstoneCallback
from capstone import *
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.skipdata_setup = (".unhandled", capstoneCallback.mycallback, None)
md.skipdata = True
md.detail = True
CODE=b'\x0f\x01\xee\x34\x12\xff\x00\x00\x00\x00\x00'
current_addr = 0x1000
offset = 0
while True:
    disasm_result = md.disasm(CODE, current_addr, count = 1)
    try:
        i = next(disasm_result)
    except StopIteration:
        break
    print("Instruction Id is: ", i.id)
    print("0x%x: \t%d" % (i.address, i.size))
    if i.id == 0:
        print("Instruction mnemonic is %s" % i._raw.mnemonic.decode("utf-8"))
    else:
        print("0x%x: \t%s \t%s" % (i.address, i.mnemonic, i.op_str))
    offset += i.size
    current_addr += i.size
    CODE = CODE[offset:]
