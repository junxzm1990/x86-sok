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

'''
Unit to represent the entity
        Object      : the class to represent an individual object
        Function    : the class to represent an individual function
        BasicBlock  : the class to represent an individual basic block
        Fixup       : the class to represent an individual fixup
'''

class Object():
    def __init__(self):
        self.idx = -1
        self.size = 0

        self.offsetFromSection = 0x0
        self.offsetFromBase = 0x0
        self.fixupCnt = 0
        self.VA = 0x0
        self.srcKind = 0  # SRC_TYPE_C as defined in constants.py

        # The structure btn objects (doubly linked list) and the hierarchy (tree)
        self.parent = None   # The parent of the object is always the binary (root)
        self.Functions = []  # Functions that consist of the object (children nodes)
        self.next = None
        self.prev = None

    def __repr__(self):
        return 'OBJ#%3d (%3dB), @0x%08x, BaseOff: 0x%04x, SecOff: 0x%04x, FNs: %d, BBLs: %d, Fixups: %d' \
                % (self.idx, self.size, self.VA, self.offsetFromBase, self.offsetFromSection,
                   len(self.Functions), sum([len(f.BasicBlocks) for f in self.Functions]), self.fixupCnt)

class Function():
    def __init__(self):
        self.idx = -1
        self.size = 0
       #  self.offsetFromObj = 0x0
        self.offsetFromSection = 0x0
        self.offsetFromBase = 0x0
        self.fixupCnt = 0
        self.VA = 0x0

        # function type: 0 => normal function; 1 => fake function
        self.type = 0

        # The structure btn functions (doubly linked list) and the hierarchy (tree)
        # self.parent = None     # Parent object that this function belongs to
        self.BasicBlocks = []  # Basic Blocks that consist of this function (children nodes)
        self.prev = None
        self.next = None

        # Cross reference information for Control Flow Graph at the function level
        self.refFroms = set()
        self.refTos = set()
        self.name = None

    def __repr__(self):
        return '  FUN#%3d (%3dB) @0x%08x, BaseOff: 0x%04x, SecOff: 0x%04x, BBLs: %d, Fixups: %d' \
                % (self.idx, self.size, self.VA, self.offsetFromBase, self.offsetFromSection,
                   len(self.BasicBlocks), self.fixupCnt)

class BasicBlock():
    def __init__(self):
        self.idx = -1
        self.size = 0
        self.padding= 0

        self.offsetFromFunc = 0x0
        #self.offsetFromObj = 0x0
        self.offsetFromSection = 0x0
        self.offsetFromBase = 0x0
        self.fixupCnt = 0
        self.VA = 0x0
        self.hasFallThrough = False

        self.assembleType = 0 # assemble type: inline assemble code or handwritten assemble code

        self.parent = None  # BBL X belongs to FN X'
        self.Fixups = []
        self.prev = None
        self.next = None
        self.refFroms = []  # BBLs that references to this BBL

        # Updated After randomization
        self.adjustedBytes = 0x0
        self.newOffsetFromSection = 0x0
        self.newVA = 0x0

        # Simulation purpose
        self.testVA = 0x0

    def __repr__(self):
        return '    BBL#%3d (%3dB) @0x%08x, BaseOff: 0x%04x, SecOff:0x%04x, Fixups: %d' \
                % (self.idx, self.size, self.VA, self.offsetFromBase,
                   self.offsetFromSection, self.fixupCnt)

class Fixup():
    def __init__(self):
        self.idx = -1
        self.offset = 0x0
        self.derefSz = 0
        self.isRela = False
        self.parent = None     # Basic Block that the fixup belongs to
        self.VA = 0x0
        self.type = None       # (c2c,c2d,d2c,d2d) = (0,1,2,3)
        self.numJTEntries = 0  # Number of jump table entries (for c2c only)
        self.jtEntrySz = 0     # Each jump table entry size

        self.derefVal = 0x0    # Value that the fixup holds (source)
        self.refTo = 0x0       # VA the fixup points to (destination)
        self.refBB = None      # Pointer that holds the referenced BB by refTo iff in .text
        self.target = None     # Resolve the target: either section name or BB#
        self.isOrphan = False  # Orphan fixup does not have a parent BBL,
                               # which only happens in CFI-enabled binary (in particular -cfi-icall)

        # Should be updated while randomization!
        self.newVA = 0x0
        self.newOffset = 0x0
        self.newRefVal = 0x0
        self.newRefTo = 0x0     # new VA the fixup points to

        # Simulation purpose
        self.testVA = 0x0

        # binpang, add
        # section name
        self.secName = None

    def __repr__(self):
        parentBB = str(self.parent.idx) if self.parent else "NA"
        type = {0: 'C2C', 1: 'C2D', 2: 'D2C', 3: 'D2D', 4: 'NewSectionStart', 5: 'Special'}
        isShortDist = "*" if self.derefSz < 4 else ""
        jumpTable = "JT [Entries: " + str(self.numJTEntries) + "(Sz: " + str(self.jtEntrySz) + "B)]"
        jtInfo = jumpTable if self.numJTEntries > 0 else ""
        return '      Fixup#%3d@0x%08x[BB#%3s]: SecOff=0x%04x, Val=0x%08x%s, RefTo=0x%08x [%s] (%s) %s' \
                % (self.idx, self.VA, parentBB, self.offset, self.derefVal,
                   isShortDist, self.refTo, type[self.type], self.target, jtInfo)

class Section():
    def __init__(self):
        self.idx = -1
        self.name = None
        self.sectionStart = 0x0
        self.sectionEnd = 0x0
        self.sz = 0x0
        self.align = 0x0
        self.va = 0x0

        self.fileOffsetEnd = 0x0        # includes the alignment to rewrite a binary
        self.next = None

    def __repr__(self):
        return '[Sec#%2d] FileOff[0x%04x:0x%04x] VA=0x%08x (%s)' \
               % (self.idx, self.sectionStart, self.fileOffsetEnd, self.va, self.name)
