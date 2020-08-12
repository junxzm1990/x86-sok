'''
file: capstoneCallback.py
data: 09/24/2019
author: binpang

handle some instructions that capstone can't identify 
'''

from ctypes import *
# mnemonic => skip size 
HANDLE_MNEMONIC = {
        b'\x0f\x01\xef': 3, # wrpkru
        b'\x0f\x01\xee': 3 # rdpkru
        }

def mycallback(buffer, size, offset, userdata):
    global isSkippedData
    for mnemonic in HANDLE_MNEMONIC:
        if (size - offset) < len(mnemonic):
            continue
        tmp_flag = True
        for (idx, mne_char) in enumerate(mnemonic):
            if mne_char != buffer[offset + idx][0]:
                tmp_flag = False
        if tmp_flag == True:
            return HANDLE_MNEMONIC[mnemonic]
    return 0

