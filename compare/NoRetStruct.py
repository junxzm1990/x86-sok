
class RetStatus:
    UNKNOWN = 0
    RET = 1
    NORET = 2


class BasicBlock():
    def __init__(self, va_, parent_va, bb_):
        self.va = va_
        self.successors_addr = set() # sometimes, we can't get the suc
        self.called_funcs = list()
        self.bb = bb_ # basic block 
        self.type = 0
        self.parent = parent_va
        self.terminate = False
        self.ret = False

    def addSuc(self, suc):
        self.successors_addr.add(suc)
    
    def addCalledFunc(self, func_va):
        self.called_funcs.append(func_va)

    def setType(self, type_):
        self.type = type_

    def setTerminate(self):
        self.terminate = True

    def setRet(self):
        self.ret = True


'''
Function struct
'''
class Function():
    def __init__(self, va_, type_, func_):
        self.va = va_
        self.status = type_
        self.root = None # root basic block
        self.func = func_

    def setRoot(self, root_):
        self.root = root_

    def setStatus(self, status_):
        self.status = status_

def getNonRetFuncsFromSymbols(binary, known_non_ret):
    e = elf.ELF(binary)
    for (sym, addr) in e.symbols.items():
        if sym in KNOWN_NON_RETS:
            logging.debug("Adding known non-ret %s at 0x%x" % (sym, addr))
            known_non_ret.add(sym)

    for (sym, addr) in e.plt.items():
        if sym in KNOWN_NON_RETS:
            logging.debug("Adding known non-ret %s at 0x%x" % (sym, addr))
