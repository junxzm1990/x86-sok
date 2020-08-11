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

import os, time
import logging
import optparse
import reorderEngine
import binaryBuilder
import shuffleInfoReader
import util
import report
import constants as C

def transformBinaryImpl(target_path, opts, metaData, granularity, R, hasRandSection=False, showlevel=1):
    """
    This function contains full transformation process step by step
    :param target_path:
    :param opts:
    :param metaData:
    :param granularity:
    :param showlevel:
    :return:
    """
    startTime = time.time()

    # Read the metadata from the .rand section in a given binary
    reorderInfoData = shuffleInfoReader.read(metaData, hasRandSection)
    target = os.path.dirname(target_path) + os.sep + target_path.split(os.sep)[-1]
    reorderInfoData['bin_info']['bin_path'] = target

    R.target = target
    R.granularity = granularity

    # Main transformation process
    logging.info("Building up the layout...")
    RE = reorderEngine.ReorderCore(reorderInfoData, R)

    # Set the granularity (randomization level): function = 0, basic block = 1
    level = '@FUN' if granularity == 0 else '@BBL'
    logging.info("Performing reordering (%s)...", level)

    showLayout, showRandLayout, showFixups, isSymbolUpdate = opts
    if showLayout:
        RE.show(showlevel)

    RE.performTransformation(granularity)

    if showRandLayout:
        RE.showRandLayout()
    if showFixups:
        if RE.FixupsInText:      RE.FixupsInText.show()
        if RE.FixupsInRodata:    RE.FixupsInRodata.show()
        if RE.FixupsInData:      RE.FixupsInData.show()
        if RE.FixupsInDataRel:   RE.FixupsInDataRel.show()
        if RE.FixupsInInitArray: RE.FixupsInInitArray.show()

    # Rewriting Binary
    logging.info("Instrumenting the binary...")
    BB = binaryBuilder.BinaryBuilder(RE, hasRandSection)
    BB.checkOrigLayout()
    oldBin = reorderInfoData['bin_info']['bin_path']
    newBin = oldBin + C.NEWBIN_POSTFIX
    BB.instrumentBin(oldBin, newBin, isSymbolUpdate)

    endTime = time.time()
    R.elapsedTime = endTime - startTime
    R.showSummary()
    R.showEntropy()
    logging.info("Total elapsed time: %s", util._show_elapsed(startTime, endTime))

def transformBinary(target, opts, R, granularity=0, showlevel=1):
    """ Trigger binary instrumentation """
    shuffleInfoBin = target + C.METADATA_POSTFIX
    dumpRandSecCmd = ' '.join([C.OBJCOPY, C.OBJCOPY_DUMPSEC,
                               C.RAND_SECTION + '=' + C.METADATA_PATH, target, C.NULL])
    os.system(dumpRandSecCmd)

    if os.path.exists(shuffleInfoBin):
        transformBinaryImpl(target, opts, shuffleInfoBin, granularity, R, hasRandSection=False, showlevel=showlevel)
    elif os.path.exists(C.METADATA_PATH):
        transformBinaryImpl(target, opts, C.METADATA_PATH, granularity, R, hasRandSection=True, showlevel=showlevel)
    else:
        logging.info("[No metadata] check out either a .rand section or a separate metadata file (*.shuffle.bin)")

def isValidArgs(args):
    """ Check if arguments are valid to proceed """
    if len(args) == 0:
        parser.error("No input file")
        return False
    if len(args) > 1:
        parser.error("More than one input files")
        return False

    input = args[0]
    if not os.path.exists(input):
        print "The target file [%s] has not been found!", input
        return False

    return True

if __name__ == '__main__':
    """
    CCR (Compiler-assisted Code Randomization)
    Randomizer: Prander (Practical Randomizer) main()
    """

    print C.CCR_LOGO
    usage = "Usage: %prog [-b|-l|-r|-f|-s|-g] <FilePath> (Use -h for help)"
    parser = optparse.OptionParser(usage=usage, version=C.VERSION)

    parser.add_option("-b", "--basicblock", dest="bbl", action="store_true", default=False,
                      help="Randomized the given binary at the basic block level (function by default)")

    parser.add_option("-l", "--layout", dest="layout", action="store_true", default=False,
                      help="Show the original layout")

    parser.add_option("-r", "--randlayout", dest="randlayout", action="store_true", default=False,
                      help="Show the randomized layout")

    parser.add_option("-f", "--fixups", dest="fixups", action="store_true", default=False,
                      help="Show all fixups (.text, .rodata and .data)")

    parser.add_option("-s", "--symbolupdate", dest="symbol", action="store_true", default=False,
                      help="Update all symbols in the symbol table (May take a long time; not recommended)")

    parser.add_option("-g", "--debug", dest="debug", action="store_true", default=False,
                      help="Debugging mode for reordering engine")

    (options, args) = parser.parse_args()
    granularity = 1 if options.bbl else 0

    if isValidArgs(args):
        fp = args[0]
        opts = (options.layout, options.randlayout, options.fixups, options.symbol)

        logPath= fp + C.LOG_POSTFIX
        if os.path.exists(logPath):
            os.remove(logPath)

        if options.debug:
            logging.basicConfig(filename=logPath, level=logging.DEBUG)
        else:
            logging.basicConfig(filename=logPath, level=logging.INFO)

        rootLogger = logging.getLogger()
        consoleHandler = logging.StreamHandler()
        consoleHandler.setFormatter(util.ColorFormatter())
        rootLogger.addHandler(consoleHandler)

        # showlevel   [1:obj, 2:fun, 3:bbl, 4:fixup]
        # granularity [0:fun, 2:bbl]
        R = report.Report()
        transformBinary(fp, opts, R, granularity=granularity, showlevel=4)
        logging.info("Success!! The log has been saved to %s", logPath)