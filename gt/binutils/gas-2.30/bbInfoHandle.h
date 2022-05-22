/* bbInfoHandle.h
 *
 * Handle basic block related directives
 */

#ifndef BBINFOHANDLE_H
#define BBINFOHANDLE_H

// debug macro
#define BBINFO_DEBUG_MSG

#include "as.h"
#include "shuffleInfo.pb-c.h"
#include <stdint.h>

extern const pseudo_typeS bbInfo_pseudo_table[];
extern int update_last_symbol(symbolS*);
extern void init_bbinfo_global(void);
extern void bbinfo_init(void);
extern char bbinfo_is_collect_sec(asection*);
extern char bbinfo_is_new_sec_frag(asection*);
extern void handwritten_funcb_bbinfo_handler();
extern void handwritten_funce_bbinfo_handler();
extern char bbinfo_in_text;

#ifdef BBINFO_DEBUG_MSG
extern char *bbinfo_file_name;
#endif

// section's last basic block
typedef struct sec_last_bb{
  asection *sec;
  asection *offset;
  struct sec_last_bb *next;
} bbinfo_sec_last_bb;


//ztt add to save the symbol list

struct symbol_list{
  char *symbol_name;
  struct symbol_list *next;
};

typedef struct symbol_list bbinfo_symbol_list;

// basic block related information
struct basic_block{
  uint32_t ID; // basic block id, every basic block has unique id in an object
  uint8_t type; // basic block type: basic block or function boundary.
    // 0 represent basic block with normal mode ie. arm
    // 1 represents function start with normal mode ie. arm
    // 2 represents object end with normal mode ie. arm
    // 4 represent basic block with special mode ie. thumb
    // 5 represents function start with special mode ie. thumb
    // 6 represents object end with special mode ie. thumb
  uint32_t offset; // offset from the section
  int size; // basic block size, include alignment size
  uint32_t alignment; // basic block alignment size
  uint32_t num_fixs; // number fixups
  unsigned char fall_through; // whether the basic block is fall through
  asection *sec; // which section the basic block belongs to
  struct basic_block *next; // link next basic blosk
  uint32_t parent_id; // function id
  uint8_t is_begin; // if current instruction is the first instruction of this basic block
  uint8_t is_inline; // if current basic block contains inline assemble code or current basic block
  fragS *parent_frag; // this basic block belongs to which frag.
  		      // FIXME. I'm not sure if there exists a basic block cross two fragS.
};

typedef struct basic_block bbinfo_mbb;

// ztt add last instruction changing PC

typedef struct last_pc{
  fragS* frag;
  int offset;
  struct last_pc *next;
  int size;
  symbolS *symbol;
}bbinfo_last_pc;

// fixup information
typedef struct fixup{
  uint32_t offset; // offset from section
  asection *sec; // which section the basic block belongs to
  unsigned char is_new_section; // if its parent section is the new section that has the same name
  unsigned char is_rela; // if this fixup is relative
  uint32_t size; // the reference's size
  uint32_t table_size; // for jump table reference only
  uint32_t entry_size; // for jump table reference only
  struct fixup *next; // link next fixup
} bbinfo_fixup;

extern bbinfo_sec_last_bb* sec_last_bb_head;
extern bbinfo_fixup* fixups_list_head; // fixup list
extern bbinfo_fixup* fixups_list_tail; // last element of fixups list
extern bbinfo_mbb* mbbs_list_head; // basic blocks list
extern bbinfo_mbb* mbbs_list_tail; // the last element of basic blocks list
extern char new_bb_flag; // ztt add the flag of a new bb wait to build
extern bbinfo_last_pc* last_pc; //ztt add last instructino changing PC
extern bbinfo_symbol_list*  symbol_list_head; // ztt add head symbol in inst
extern bbinfo_symbol_list*  symbol_list_tail;  // ztt add tail symbol in inst
extern bbinfo_last_pc* added_fixups_list_head; //ztt add first element of added fixup list
extern bbinfo_last_pc* added_fixups_list_tail; //ztt add last element of added fixup list
extern uint32_t cur_function_id; // current function id
extern uint32_t prev_function_id; // prev function id
extern uint32_t cur_function_end_id; // current function end id
extern symbolS *last_symbol; // last user defined symbol
extern uint32_t cur_block_id; // global current basic block id
// according to CCR, in c++. there may exist multiple .text sections, so recording the .text number
extern unsigned text_sec_cnt;
extern unsigned rodata_sec_cnt;
extern unsigned data_sec_cnt;
extern unsigned datarel_sec_cnt;
extern unsigned init_sec_cnt;

extern unsigned text_sec_frag_cnt;
extern unsigned rodata_sec_frag_cnt;
extern unsigned data_sec_frag_cnt;
extern unsigned datarel_sec_frag_cnt;
extern unsigned init_sec_frag_cnt;

extern asection *bbinfo_text_sec;
extern asection *bbinfo_rodata_sec;
extern asection *bbinfo_data_sec;
extern asection *bbinfo_init_sec;
extern asection *bbinfo_datarel_sec;
extern const char* handwritten_bbinfo_func_name;

// This is the symbol that represent that current basic block
// contains inline assemble code
extern int bbinfo_app;

// represents that current assemble file is hand-written file
// For handwritten file, we can't get accurate basic block and function information,
// so we create `fake` basic block that contains continuous instructions
extern int bbinfo_handwritten_file;
extern void bbinfo_initbb_handwritten(void);
extern bbinfo_last_pc* bbinfo_init_last_pc(fragS*,int); // ztt add
extern bbinfo_symbol_list* bbinfo_init_symbol_list(void); // ztt add
extern bbinfo_last_pc* bbinfo_init_added_fixup(void); // ztt add

// it is used to begin a new `fake` basic block
extern int bbinfo_last_inst_offset;
extern unsigned int bbinfo_last_inst_size;
extern fragS* bbinfo_last_frag;

// shuffleInfo that CCR defines
extern char* bbinfo_shuffle_info_buf; 
extern unsigned bbinfo_shuffle_info_buf_len;

extern bbinfo_fixup* bbinfo_init_fixup(void);
extern bbinfo_fixup* bbinfo_init_insert_fixup(asection*, int);
extern void bbinfo_update_shuffle_info(void);
#endif
