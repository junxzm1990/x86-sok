/*
 * bbInfo2asm.h
 * 
 * Here we output basic block related information to asm file. 
 * Including basic block boundries(includeing alignment), basic block fall through
 * jump table entries and function boundries.
 */

#ifndef GCC_BBINFO2ASM_H
#define GCC_BBINFO2ASM_H 1

// output the basic block begin label
extern void bbinfo2_asm_block_begin();

// output the basic block end label
extern void bbinfo2_asm_block_end(uint32_t);

// output the jump table information, including table size and entry size
extern void bbinfo2_asm_jumptable(uint32_t table_size, uint32_t entry_size);

// output the function begin label
extern void bbinfo2_asm_func_begin();

// output the function end label
extern void bbinfo2_asm_func_end();

// output the asm inline start label
extern void bbinfo2_asm_inline_start();
extern void bbinfo2_asm_inline_end();

#endif
