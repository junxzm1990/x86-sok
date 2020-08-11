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

import logging
import math
class Report():
    def __init__(self):
        # Randomization option
        self.target = None
        self.granularity = None

        # Original Binary
        self.numObjs = 0
        self.numFuns = 0
        self.numBBLs = 0

        self.numFixupsText = 0
        self.numFixupsSpecial = 0
        self.numFixupsRodata = 0
        self.numFixupsData = 0
        self.numFixupsDataRel = 0
        self.numFixupsInitArray = 0

        self.isMain = True
        self.origMainAddr = 0x0
        self.origBinSz = 0x0
        self.origBinHash = 0x0
        self.ehframeCIE = 0
        self.ehframeFDE = 0

        # Instrumented Binary
        self.instBinName = ''
        self.instBinSz = 0x0
        self.incRate = 0
        self.instBinHash = 0x0

        self.instMainAddr = 0x0
        self.numRelocPatch = 0
        self.numSymPatch = 0
        self.numInitArrayPatch = 0
        self.numEhframePatch = 0
        self.numEhframeHdrPatch = 0

        self.shuffledSz = 0
        self.metadataSz = 0
        self.finalBinSz = 0

        # Shuffle Process
        self.verLB = 1        # Lower Bound Entropy (considering functions)
        self.verUB = 1        # Upper Bound Entropy (considering both functions and BBLs)
                              # Note that this is an approximate value; it might vary
        self.entropyFun = 0   # Number of functions that removed function constraints (f_i - y_i)
        self.entropyBBL = []  # Possible versions after applying BBL constraints (b_ij - x_ij)
        self.verLogLB = 0
        self.verLogUB = 0
        self.elapsedTime = 0

    def _computeEntropy(self):
        """ Compute the entropy (func/bbl) """
        self.verLB = math.factorial(self.entropyFun)
        self.verUB = self.verLB * \
                     reduce((lambda x, y: x * y), [math.factorial(k) for k in self.entropyBBL]) \
                     if len(self.entropyBBL) > 0 else self.verLB
        self.logLB, self.logUB = math.log10(self.verLB), math.log10(self.verUB)

    def showEntropy(self):
        self._computeEntropy()
        logging.info("\tEntropy [LB, UB]  : [10^%.2f, 10^%.2f] possible versions"
                     % (self.logLB, self.logUB))

    def showSummary(self):
        """ Summarize interesting statistics during transformation """
        logging.info("Summary of Binary Instrumentation")
        logging.info("\tBinary Name       : %s", self.instBinName)

        if self.isMain:
            logging.info("\tMain() Addr       : 0x%x -> 0x%x" % (self.origMainAddr, self.instMainAddr))
        else:
            logging.info("\tNo Main() has been found (maybe shared object?)")

        if self.numRelocPatch > 0:
            logging.info("\tReloc Patches     : %d (.rela.dyn)", self.numRelocPatch)

        logging.info("\tSymbol Patches    : %d (.dynsym|.symtab)", self.numSymPatch)
        logging.info("\tInitArray Patches : %d (.init_array)", self.numInitArrayPatch)
        logging.info("\tCIE / FDE         : %d / %d (.eh_frame)", self.ehframeCIE, self.ehframeFDE)
        logging.info("\tFDE Patches       : %d (.eh_frame)", self.numEhframePatch)
        logging.info("\tPair Patches      : %d (.eh_frame_hdr)", self.numEhframeHdrPatch)

        logging.info("\tOriginal MD5      : %s", self.origBinHash)
        logging.info("\tShuffled MD5      : %s", self.instBinHash)
        logging.info("\tShuffled Size     : 0x%06x", self.shuffledSz)
        logging.info("\tMetadata size     : 0x%06x" % self.metadataSz)
        logging.info("\tTotal Size        : 0x%06x" % self.finalBinSz)
        logging.info("\tFile Inc Rate     : %2.3f%%" % self.incRate)