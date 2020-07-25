/* bbInfoHandle.h
 *
 * Handle basic block related directives
 */

#ifndef BBINFOHANDLE_H
#define BBINFOHANDLE_H

#include "as.h"
#include "shuffleInfo.pb-c.h"
#include <stdint.h>

extern const pseudo_typeS bbInfo_pseudo_table[];
extern int update_last_symbol(symbolS*);
extern void init_bbinfo_global(void);
extern void bbinfo_init(void);
extern char bbinfo_is_new_sec(asection*);
extern char bbinfo_is_new_sec_frag(asection*);



// basic block related information
struct basic_block{
  uint32_t ID; // basic block id, every basic block has unique id in an object
  uint8_t type; // basic block type: basic block or function boundary.
 		// 0 represents basic block. 1 represents function start. 2 represents object end
  uint32_t offset; // offset from the section
  int size; // basic block size
  uint32_t alignment; // basic block alignment
  uint32_t num_fixs; // number fixups
  unsigned char fall_through; // whether the basic block is fall through
  asection *sec; // which section the basic block belongs to
  struct basic_block *next; // link next basic blosk
  uint32_t parent_id; // function id
  uint8_t is_begin; // if current instruction is the first instruction of this basic block
  fragS *parent_frag; // this basic block belongs to which frag.
  		      // FIXME. I'm not sure if there exists a basic block cross two fragS.
};

typedef struct basic_block bbinfo_mbb;


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

extern bbinfo_fixup* fixups_list_head; // fixup list
extern bbinfo_fixup* fixups_list_tail; // last element of fixups list
extern bbinfo_mbb* mbbs_list_head; // basic blocks list
extern bbinfo_mbb* mbbs_list_tail; // the last element of basic blocks list
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

// shuffleInfo that CCR defines
extern char* bbinfo_shuffle_info_buf; 
extern unsigned bbinfo_shuffle_info_buf_len;

extern bbinfo_fixup* bbinfo_init_fixup(void);
extern void bbinfo_update_shuffle_info(void);
#endif
