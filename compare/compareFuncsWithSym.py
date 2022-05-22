'''
file: compare_ehFrame.py
date: 2019/01/04
author: binpang
Extract the file's .eh_frame section's entry to extract the function entry.
And then compare them with the .symtab section.
'''
import optparse
import logging
import os
import traceback
import string
import random
from deps import *

import blocks_pb2
from elftools.elf.elffile import ELFFile
from elftools.dwarf.callframe import CIE, FDE

textAddr = 0
textSize = 0

LINKER_ADDED_FUNCS = {
         "__x86.get_pc_thunk.bx", # glibc in i386 function
               "__libc_csu_init",
               "__libc_csu_fini",
               "deregister_tm_clones",
               "register_tm_clones",
               "__do_global_dtors_aux",
               "frame_dummy",
               "_start",
               "atexit",
               "_dl_relocate_static_pie",
               "__stat",
               "stat64",
               "fstat64",
               "lstat64",
               "fstatat64",
               "__fstat",
               "call_weak_fn",
               "__udivsi3",
               "__aeabi_uidivmod",
               "__divsi3",
               ".divsi3_skip_div0_test",
               "__aeabi_idivmod",
               "__aeabi_idiv0",
               "__aeabi_ldivmod",
               "__udivmoddi4",
               "__aeabi_drsub",
               "__aeabi_dsub",
               "__adddf3",
               "__aeabi_ui2d",
               "__aeabi_i2f",
               "__aeabi_ul2f",
               "__aeabi_l2f",
               "__aeabi_i2d",
               "__aeabi_f2d",
               "__arm_set_fast_math",
               "__divsc3",
               "__mulsc3",
               "__aeabi_ul2d",
               "__aeabi_l2d",
               "__aeabi_frsub",
               "__aeabi_fsub",
               "__addsf3",
               "__aeabi_ui2f",
               "__aeabi_uldivmod",
               "hlt",
               "__start",
               "__addtf3",
               "__divtf3",
               "__multf3",
               "__floatunditf",
               # libc static
               "ns_name_pton",
               "__cxa_rethrow",
               "_Znwm",
               "__cxa_guard_abort",
               "__cxa_guard_release",
               "__cxa_throw_bad_array_new_length",
               "_ZSt7getlineIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RNSt7__cxx1112basic_stringIS4_S5_T1_EE",
               "_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC1Ev",
               "_ZNSt14basic_ifstreamIcSt11char_traitsIcEE4openEPKcSt13_Ios_Openmode",
               "_ZNSt14basic_ifstreamIcSt11char_traitsIcEED1Ev",
               "_Unwind_Resume",
               "_ZNKSt8__detail20_Prime_rehash_policy11_M_next_bktEm",
               "_ZSt24__throw_out_of_range_fmtPKcz",
               "_ZSt20__throw_length_errorPKc",
               "_ZSt17__throw_bad_allocv",
               "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6substrEmm",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructIPKcEEvT_S8_St20forward_iterator_tag",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructIPcEEvT_S7_St20forward_iterator_tag",
               "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7compareEmmPKc",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_appendEPKcm",
               "__subtf3",
               "__aeabi_d2ulz",
               "__aeabi_d2lz",
               "lstat64",
               "fstat64",
               "stat64",
               "__fixtfdi",
               "__cxx_global_var_init.8",
               "__mknod",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructEmc",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEaSERKS4_",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7reserveEm",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEpLEc",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5eraseEmm",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE14_M_replace_auxEmmmc",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE10_M_replaceEmmPKcm",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6assignEPKc",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEaSEPKc",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6appendERKS4_mm",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6appendEPKcm",
               "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEpLEPKc",
               ### other libs, libc
               "ns_name_rollback",
               "ns_name_skip",
               "__ns_get16",
               "__ns_get32",
               "ns_put16",
               "ns_put32",
               "binary_hnok",
               "__dn_expand",
               "__dn_comp",
               "__dn_skipname",
               "__res_hnok",
               "__res_ownok",
               "__res_mailok",
               "__res_dnok",
               "__putlong",
               "__putshort",
               "_getlong",
               "_getshort",
               "__res_context_mkquery",
               "__res_nmkquery",
               "__res_mkquery",
               "__res_nopt",
               "ns_msg_getflag",
               "ns_skiprr",
               "ns_initparse",
               "ns_parserr",
               "ns_parserr",
               "__ns_name_ntop",
               "ns_name_ntol",
               "__ns_name_unpack",
               "ns_name_pack",
               "ns_name_uncompress",
               "ns_name_compress",
               "__fixunstfdi",
               "__eqtf2",
               "set_fast_math",
               "__letf2",
               "__getf2",
               "__sfp_handle_exceptions",
               "__lstat",
               "__fstat",
               "fstatat",
               "__floatunsitf",
               "__extenddftf2",
               "__floatsitf",
               "__floatditf",
               "__unordtf2",
               "__trunctfsf2",
               "__trunctfdf2",
               "__cxx_global_var_init.9",
               "_GLOBAL__sub_I_step_14.cc"
        }

PLT_RANGE = None

BLACKLIST_ADDRS = set()

logging.basicConfig(level = logging.INFO)

def randomString(stringLength=10):
    """Generate a random string of fixed length """

    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

def readPltRange(binary):
    with open(binary, 'rb') as open_file:
        elffile = ELFFile(open_file)
        pltsec = elffile.get_section_by_name('.plt')
        if pltsec == None:
            return None
        return (pltsec['sh_addr'], pltsec['sh_size'])

def readFuncsFromProto(mModule):
    """
    read Funcs from protobufs
    params:
        mModule: protobuf module
    returns:
        Funcs start: store the result of function start
    """

    tmpFuncSet = set()
    for func in mModule.fuc:

        # this is the dummy function
        if func.va == 0x0:
            continue
        funcAddr = func.va

        if not isInTextSection(funcAddr):
            continue

        if funcAddr not in tmpFuncSet:
            tmpFuncSet.add(funcAddr)
        else:
            logging.warning("repeated handle the function in address %x" % func.va)
            continue

    return tmpFuncSet

def readTextSection(binary):
    with open(binary, 'rb') as openFile:
        elffile = ELFFile(openFile)
        for sec in elffile.iter_sections():
            if sec.name == '.text':
                global textSize 
                global textAddr
                global textOffset
                pltSec = sec
                textSize = pltSec['sh_size']
                textAddr = pltSec['sh_addr']
                textOffset = pltSec['sh_offset']
                logging.info(".text section addr: 0x%x, size: 0x%x, offset: 0x%x" % (textSize, textAddr, textOffset))

def isInTextSection(addr):
    if addr >= textAddr and addr < textAddr + textSize:
        return True
    return False

'''
read function information from symbol information
'''
def readFuncsFromSyms(binary):

    result = set()
    global BLACKLIST_ADDRS

    with open(binary, 'rb') as open_file:
        elffile = ELFFile(open_file)
        symsec = elffile.get_section_by_name('.symtab')
        if not symsec:
            logging.error("binary file %s does not contains .symtab section!" % (binary))
            return result 
        for sym in symsec.iter_symbols():
            if 'STT_FUNC' == sym['st_info']['type'] and sym['st_value'] != 0x0 and \
                    isInTextSection(sym['st_value']):
                #logging.debug("[Find Func Start From .symtab]: address 0x%x" % (sym['st_value']))
                result.add(sym['st_value'])
                if sym.name in LINKER_ADDED_FUNCS:
                    BLACKLIST_ADDRS.add(sym['st_value'])

    return result

'''
compare the function entry from .eh_frame and .symtab
we deem the .symtab information as ground truth
'''
def compareFuncs(func_from_eh, func_from_sym):
    false_neg_num = 0
    false_pos_num = 0
    size_not_equal = 0

    for func in func_from_eh:

        if func not in func_from_sym:
            logging.error("[False Negative#%d]: address 0x%x!" % (false_neg_num, func))
            false_neg_num += 1

    sym_blacklist_num = 0

    for func in func_from_sym:

        if func not in func_from_eh:

            if func in BLACKLIST_ADDRS:
                sym_blacklist_num += 1
                continue

            logging.error("[False Positive#%d]: address 0x%x!" % (false_pos_num, func))
            false_pos_num += 1

    true_pos_num = len(func_from_sym) - false_pos_num

    logging.info("The number of functions in symbols is %d" % len(func_from_sym))
    logging.info("The number of functions in gt is %d" % len(func_from_eh))

    if len(func_from_sym) != 0:
        logging.info("False positive number is 0x%x, rate %f" % (false_pos_num, false_pos_num / len(func_from_sym)))
        logging.info("False negative number is 0x%x, rate %f" % (false_neg_num, false_neg_num / len(func_from_sym)))
        logging.info("Recall %f" % (true_pos_num / (len(func_from_eh) + sym_blacklist_num)))
        logging.info("Precision %f" % (true_pos_num / len(func_from_sym)))
    else:
        logging.info("no .symtab information!")

    return

if __name__ == '__main__':

    parser = optparse.OptionParser()
    parser.add_option("-b", "--binary", dest = "binary", action = "store", \
            type = "string", help = "The binary path that comtains the symbol information", default = None)
    parser.add_option("-p", "--proto", dest = "proto", action = "store", \
            type = "string", help = "The protobuf we stored", default = None)
#    parser.add_option("-o", "--output", dest = "output", action = "store", \
#            type = "string", help = "The output path of the compared result", default = "/tmp/compare_ehFrame.log")

    (options, args) = parser.parse_args()

    if options.binary == None:
        print("Please input the binary file path")
        exit(-1)
    if options.proto== None:
        print("Please input the protobuf path")
        exit(-1)
    
    mModule1 = blocks_pb2.module()

    try:
        f1 = open(options.proto, 'rb')
        mModule1.ParseFromString(f1.read())
        f1.close()
    except IOError:
        print("Could not open the file\n")
        exit(-1)

    readTextSection(options.binary)
    PLT_RANGE = readPltRange(options.binary)
    funcFromProto = readFuncsFromProto(mModule1)
    funcFromSym = readFuncsFromSyms(options.binary)
    compareFuncs(funcFromProto, funcFromSym)