/*
 * bbInfo2asm.c
 *
 * output the basic block related information to asm file
 *
 * This file is part of GCC.
 */

#include "config.h"
#include "system.h"
#include "coretypes.h"
#include "target.h"
#include "output.h"
#include "bbInfo2asm.h"
#include "varasm.h"

// bbInfo magic string
#define MAGIC_STRING "bbInfo_"

// mark the basic block begin location
#define BB_BEGIN_MARK "BB"

// mark the basic block end location
#define BB_END_MARK "BE"

// mark the function start location
#define FUN_BEGIN_MARK "FUNB"

// mark the function end location
#define FUN_END_MARK "FUNE"

// mark the jump table information
#define JMP_TABLE_INFO "JMPTBL"

// mark the asm inline start information
#define INLINE_START "INLINEB"
#define INLINE_END "INLINEE"

#define BLOCK_BEGIN_LABEL MAGIC_STRING BB_BEGIN_MARK
#define BLOCK_END_LABEL MAGIC_STRING BB_END_MARK
#define FUN_BEGIN_LABEL MAGIC_STRING FUN_BEGIN_MARK
#define FUN_END_LABEL MAGIC_STRING FUN_END_MARK
#define JMP_TABLE_LABEL MAGIC_STRING JMP_TABLE_INFO
#define INLINE_START_LABEL MAGIC_STRING INLINE_START
#define INLINE_END_LABEL MAGIC_STRING INLINE_END

#define ASM_OUTPUT_DIRECTIVE(FILE, PREFIX) \
      fprintf (FILE, "\t.%s\n", PREFIX)

// output the basic block begin label
// if fall_through = 0, not fall through; otherwise, fall through
void bbinfo2_asm_block_begin(uint32_t fallThrough){
    switch_to_section(current_function_section());
    // ASM_OUTPUT_DIRECTIVE(asm_out_file, BLOCK_BEGIN_LABEL);
    fprintf(asm_out_file, "\t.%s %d\n", BLOCK_BEGIN_LABEL, fallThrough);
}

// output the basic block end label
void bbinfo2_asm_block_end(uint32_t fallThrough){
    switch_to_section(current_function_section());
    fprintf(asm_out_file, "\t.%s %d\n", BLOCK_END_LABEL, fallThrough);
}

// output the function begin label
void bbinfo2_asm_func_begin(){
    switch_to_section(current_function_section());
    ASM_OUTPUT_DIRECTIVE(asm_out_file, FUN_BEGIN_LABEL);
}

// output the jump table information, includeing table size and entry size
void bbinfo2_asm_func_end(){
    switch_to_section(current_function_section());
    ASM_OUTPUT_DIRECTIVE(asm_out_file, FUN_END_LABEL);
}

// output the jump table information, including table size and entry size
void bbinfo2_asm_jumptable(uint32_t table_size, uint32_t entry_size){
    //switch_to_section(current_function_section());
    fprintf(asm_out_file, "\t.%s %d %d\n", JMP_TABLE_LABEL, table_size, entry_size);
}

void bbinfo2_asm_inline_start(){
    ASM_OUTPUT_DIRECTIVE(asm_out_file, INLINE_START_LABEL);
}

void bbinfo2_asm_inline_end(){
    ASM_OUTPUT_DIRECTIVE(asm_out_file, INLINE_END_LABEL); 
}

