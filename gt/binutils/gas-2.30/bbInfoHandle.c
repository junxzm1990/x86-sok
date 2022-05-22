/*
 * bbInfoHandle.c
 */

#include "bbInfoHandle.h"
#include "as.h"
#include "struc-symbol.h"
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void jmptable_bbInfo_handler (int);
static void funcb_bbInfo_handler (int);
static void funce_bbInfo_handler (int);
static void bb_bbInfo_handler (int);
static void be_bbInfo_handler (int);
static void inlineb_bbInfo_handler (int);
static void inlinee_bbInfo_handler (int);
void bbinfo_update_shuffle_info(void);
bbinfo_mbb* init_basic_block(void);
bbinfo_last_pc* bbinfo_init_last_pc(fragS*,int);
bbinfo_symbol_list* bbinfo_init_symbol_list(void);
bbinfo_last_pc*  bbinfo_init_added_fixup(void);
bbinfo_fixup* bbinfo_init_fixup();
bbinfo_fixup* bbinfo_init_insert_fixup(asection*, int);
char bbinfo_is_collect_sec(asection*);
char bbinfo_is_new_sec_frag(asection*);
void handwritten_funcb_bbinfo_handler();
void handwritten_funce_bbinfo_handler();

#ifdef BBINFO_DEBUG_MSG
char *bbinfo_file_name = NULL;
#endif

const pseudo_typeS bbInfo_pseudo_table[] = {
    {"bbinfo_jmptbl", jmptable_bbInfo_handler, 0},
    {"bbinfo_funb", funcb_bbInfo_handler, 0},
    {"bbinfo_fune", funce_bbInfo_handler, 0},
    {"bbinfo_bb", bb_bbInfo_handler, 0},
    {"bbinfo_be", be_bbInfo_handler, 0},
    {"bbinfo_inlineb", inlineb_bbInfo_handler, 0},
    {"bbinfo_inlinee", inlinee_bbInfo_handler, 0},
    {NULL, NULL, 0}
};

// debug related symbol
const char* symbol_blacklist[] = {
  ".Ldebug",
  ".LASF"
};

// global variable
bbinfo_sec_last_bb* sec_last_bb_head = NULL;
bbinfo_fixup* fixups_list_head; // fixup list
bbinfo_mbb* mbbs_list_head;   // first element of basic blocks list
bbinfo_mbb* mbbs_list_tail; // last element of basic blocks list
char new_bb_flag;// add the flag of a new bb wait to build
bbinfo_last_pc* last_pc; // add last instructino changing PC
bbinfo_symbol_list*  symbol_list_head; // add head symbol in inst
bbinfo_symbol_list*  symbol_list_tail;  // add tail symbol in inst
bbinfo_last_pc* added_fixups_list_head; // add first element of added fixup list
bbinfo_last_pc* added_fixups_list_tail; // add last element of added fixup list
uint32_t cur_function_id;  // current functin id
uint32_t cur_function_end_id; // current function end id
uint32_t prev_function_id; // prev function id
symbolS *last_symbol; // last user defined symbol
uint32_t cur_block_id; // global current basic block id
unsigned char function_head; // represent that the current basic block is current function's first entry
const char* handwritten_bbinfo_func_name = NULL;

// in text section or not
char bbinfo_in_text = 0;
char bbinfo_handled_ee = 0;

// to record if fixups is in a new section(such as .text.xxx)
//unsigned text_sec_cnt;
//unsigned rodata_sec_cnt;
//unsigned data_sec_cnt;
//unsigned datarel_sec_cnt;
//unsigned init_sec_cnt;

unsigned text_sec_frag_cnt;
unsigned rodata_sec_frag_cnt;
unsigned data_sec_frag_cnt;
unsigned datarel_sec_frag_cnt;
unsigned init_sec_frag_cnt;

asection* bbinfo_text_sec;
asection* bbinfo_rodata_sec;
asection* bbinfo_data_sec;
asection* bbinfo_init_sec;
asection* bbinfo_datarel_sec;

int bbinfo_app;
int bbinfo_handwritten_file;
unsigned int bbinfo_last_inst_size;
int bbinfo_last_inst_offset;
fragS* bbinfo_last_frag;
void bbinfo_initbb_handwritten(void);

// store the shuffle information
char* bbinfo_shuffle_info_buf = NULL;
unsigned bbinfo_shuffle_info_buf_len = 0;


// init the global variables
void bbinfo_init(){
  fixups_list_head = NULL;
  mbbs_list_head = NULL;
  mbbs_list_tail = NULL;
  symbol_list_head = NULL; // add head symbol in inst
  symbol_list_tail = NULL;  // add tail symbol in inst
  added_fixups_list_head = NULL;
  added_fixups_list_tail = NULL;
  cur_function_id = 0;
  cur_function_end_id = 0;
  prev_function_id = 0;
  last_symbol = NULL;
  cur_block_id = 0;
  function_head = 0;

  text_sec_frag_cnt = 0;
  rodata_sec_frag_cnt = 0;
  data_sec_frag_cnt = 0;
  datarel_sec_frag_cnt = 0;
  init_sec_frag_cnt = 0;

  bbinfo_text_sec = NULL;
  bbinfo_rodata_sec = NULL;
  bbinfo_data_sec = NULL;
  bbinfo_init_sec = NULL;
  bbinfo_datarel_sec = NULL;

  bbinfo_app = 0;
  bbinfo_handwritten_file = 1;

  bbinfo_last_inst_size = 0;
  bbinfo_last_inst_offset = 0;
  fragS* bbinfo_last_frag = NULL;
}

// update the last_symbol global variable
// exclude dedug defined label
int update_last_symbol(symbolS *sym){
  unsigned int size = sizeof(symbol_blacklist) / sizeof(char*);
  const char* symbol_name = S_GET_NAME(sym);

  if (!strcmp(symbol_name, "")){
    as_warn (_("[bbInfo]: the symbol name is null"));
    return -1;
  }
// check if the symbol_name is in black list
  for (unsigned int i = 0; i < size; i++){
    if(strstr(symbol_name, symbol_blacklist[i]))
      return -1;
  } 
  last_symbol = sym;
  return 0;
}

#ifdef BBINFO_DEBUG_MSG
void save_to_tmp_directory(const char* file){
  if (!file)
    return;
  char* tmp_file = "/tmp/bbinfo/";
  char buf[100];
  strcpy(buf, tmp_file);
  srand(time(0));
  unsigned rand_num = rand();
  sprintf(buf, "cp %s /tmp/bbinfo/case_%x.s", file, rand_num);

  as_warn(_("Execute %s"), buf);
  system(buf);
}
#endif

// generate shuffleInfo into protobuf
void bbinfo_update_shuffle_info(void){
ShuffleInfo__ReorderInfo reorder_info = SHUFFLE_INFO__REORDER_INFO__INIT;
ShuffleInfo__ReorderInfo__BinaryInfo binary_info = 
  SHUFFLE_INFO__REORDER_INFO__BINARY_INFO__INIT;

binary_info.has_rand_obj_offset = 1;
binary_info.rand_obj_offset = 0; // should be update at linking time
binary_info.has_main_addr_offset = 1;
binary_info.main_addr_offset = 0; // should be update at linking time

// 0 is ordinary c/c++ file. 
// 1 is a source file contains inline assembly
// 2 is standalone assembly file
// TODO(binpang). Identify assemble file and inline 
binary_info.has_src_type = 1;
binary_info.src_type = 0;

reorder_info.bin = &binary_info;

unsigned bb_cnt = 0;
unsigned text_fixp_cnt = 0;
unsigned rodata_fixp_cnt = 0;
unsigned data_fixp_cnt = 0;
unsigned datarel_fixp_cnt = 0;
unsigned init_fixp_cnt = 0;

bbinfo_mbb* last_mbb = NULL;
// count the basic block number
for(bbinfo_mbb* cur_mbb = mbbs_list_head; cur_mbb;
    cur_mbb = cur_mbb->next){
  if (!cur_mbb->sec || !cur_mbb->size){
    continue;
  }
  //debug
  if (last_mbb && !bbinfo_handwritten_file)
    if (last_mbb->size + last_mbb->offset != cur_mbb->offset && last_mbb->sec == cur_mbb->sec){
#ifdef BBINFO_DEBUG_MSG
    as_warn(_("bb#%d, from %x to %x. last_mbb %d, its section is %s, last_mbb from %x to %x, last basic block added size %d"),
	bb_cnt, cur_mbb->offset, cur_mbb->offset + cur_mbb->size-1, (last_mbb->parent_frag->last_bb == last_mbb), cur_mbb->sec->name, last_mbb->offset, last_mbb->size+last_mbb->offset-1, last_mbb->parent_frag->last_bb_added_size);

    if (bbinfo_file_name){
      save_to_tmp_directory (bbinfo_file_name);
      bbinfo_file_name = NULL;
    }
#endif
    }
  // record the last basic block of every section
  if (!cur_mbb->next || cur_mbb->next->sec != cur_mbb->sec){
    bbinfo_sec_last_bb* current_sec_last_bb = sec_last_bb_head;
    while(current_sec_last_bb && current_sec_last_bb->sec != cur_mbb->sec){
      current_sec_last_bb = current_sec_last_bb->next;
    }
    // the list doesn't have the section record
    if (!current_sec_last_bb){
      bbinfo_sec_last_bb* tmp_sec_last_bb = malloc(sizeof(bbinfo_sec_last_bb));
      memset(tmp_sec_last_bb, 0, sizeof(bbinfo_sec_last_bb));
      // add the malloced bbinfo_sec_last_bb into the list
      tmp_sec_last_bb->next = sec_last_bb_head;
      tmp_sec_last_bb->offset = cur_mbb->offset;
      tmp_sec_last_bb->sec = cur_mbb->sec;
      sec_last_bb_head = tmp_sec_last_bb;
    }else{
      // we find the bbinfo_sec_last_bb
      if (current_sec_last_bb->offset < cur_mbb->offset)
	      current_sec_last_bb->offset = cur_mbb->offset;
    }
  }

  bb_cnt++;
  last_mbb = cur_mbb;
}

// if (!sec_last_bb_head && last_mbb) {
//   bbinfo_sec_last_bb* tmp_sec_last_bb = malloc(sizeof(bbinfo_sec_last_bb));
//   memset(tmp_sec_last_bb, 0, sizeof(bbinfo_sec_last_bb));
//   // add the malloced bbinfo_sec_last_bb into the list
//   tmp_sec_last_bb->next = sec_last_bb_head;
//   tmp_sec_last_bb->offset = last_mbb->offset;
//   tmp_sec_last_bb->sec = last_mbb->sec;
//   sec_last_bb_head = tmp_sec_last_bb;
//   sec_last_bb_head->next = NULL;
// }


// count the fixp number
for(bbinfo_fixup* cur_fixp = fixups_list_head; cur_fixp;
    cur_fixp = cur_fixp->next){

  // Bug here. The fixup does not have its parent section
  if (!cur_fixp->sec){
    as_warn(_("Bug here. The fixup does not have its parent section\n"));

#ifdef BBINFO_DEBUG_MSG
    if (bbinfo_file_name){
      save_to_tmp_directory(bbinfo_file_name);
      bbinfo_file_name = NULL;
    }
#endif
    continue;
  }

  if (bbinfo_is_new_sec_frag(cur_fixp->sec) == 1)
    cur_fixp->is_new_section = 1;

  const char* sec_name =cur_fixp->sec->name;
  if (strstr(sec_name, ".text"))
    text_fixp_cnt++;
  else if(strstr(sec_name, ".rodata"))
    rodata_fixp_cnt++;
  else if(strstr(sec_name, ".init_array"))
    init_fixp_cnt++;
  else if(strstr(sec_name, ".data.rel.ro"))
    datarel_fixp_cnt++;
  else if(strstr(sec_name, ".data"))
    data_fixp_cnt++;
}

ShuffleInfo__ReorderInfo__LayoutInfo **layout;
layout = malloc(sizeof(ShuffleInfo__ReorderInfo__LayoutInfo *) * bb_cnt);
unsigned index = 0;
unsigned obj_size = 0;
asection* last_sec = NULL;

#ifdef BBINFO_DEBUG_MSG
unsigned bb_fix_num = 0;
#endif

for(bbinfo_mbb* cur_mbb = mbbs_list_head; cur_mbb;
    cur_mbb = cur_mbb->next){

  // Bug here. The basic block does not have its parent section
  if (!cur_mbb->sec){

// debug, save the failed asm file into /tmp/bbinfo/ directory
#ifdef BBINFO_DEBUG_MSG
    as_warn(_("The basic block[%d] does not have its parent section, its size is %d"), cur_mbb->ID, cur_mbb->size);
    if (bbinfo_file_name && cur_mbb->size){
      save_to_tmp_directory(bbinfo_file_name);
      bbinfo_file_name = NULL;
    }
#endif
    continue;
  }
  if (!cur_mbb->size)
	  continue;

#ifdef BBINFO_DEBUG_MSG
  bb_fix_num += cur_mbb->num_fixs;
#endif

  layout[index] = malloc(sizeof(ShuffleInfo__ReorderInfo__LayoutInfo));

  shuffle_info__reorder_info__layout_info__init(layout[index]);
  layout[index]->has_type = 1;
  layout[index]->type = cur_mbb->type;
  layout[index]->has_bb_size = 1;
  layout[index]->bb_size = cur_mbb->size;
  layout[index]->has_bb_fallthrough = 1;
  layout[index]->bb_fallthrough = cur_mbb->fall_through;
  layout[index]->has_num_fixups = 1;
  layout[index]->num_fixups = cur_mbb->num_fixs;
  layout[index]->section_name = (char*)cur_mbb->sec->name;
  layout[index]->has_padding_size= 1;
  layout[index]->padding_size = cur_mbb->alignment;

  layout[index]->has_assemble_type = 1;
  if (cur_mbb->is_inline)
    layout[index]->assemble_type = 1;
  if (bbinfo_handwritten_file)
    layout[index]->assemble_type = 2; // current file is assemble file
  				      // so the basic block is a `fake` basic block
  // DEBUG
#ifdef BBINFO_DEBUG_MSG
  if (cur_mbb->is_inline || bbinfo_handwritten_file){
      if (bbinfo_file_name){ 
	  save_to_tmp_directory (bbinfo_file_name);
	  bbinfo_file_name = NULL;
      }
  }
  if (cur_mbb->is_inline){
    as_warn("[bbinfo]: basic block contains inline assemble code");
  }
#endif


  unsigned char is_last_bb = 0;
 /* if (index == bb_cnt - 1){
    if (layout[index]->type == 1)
      layout[index]->type = 3; // 3 represents that it is both function and object end
    else
      layout[index]->type = 2;
  }
  // the last basic block is tail of last section.
  else if (last_sec && last_sec != cur_mbb->sec){
    if (layout[index-1]->type == 1)
      layout[index-1]->type = 3;
    else
      layout[index-1]->type = 2;
  }*/
  layout[index]->has_offset = 1;
  layout[index]->offset = cur_mbb->offset;

  bbinfo_sec_last_bb* cur_sec_last = sec_last_bb_head;
  if (!cur_sec_last) {
  }
  while(cur_sec_last && cur_sec_last->sec != cur_mbb->sec){
    as_warn("sec last bb head name is %s, cur_bb name is %s", cur_sec_last->sec, cur_mbb->sec);
    cur_sec_last = cur_sec_last->next;
  }
  // the list does not record the basic block's section
  if (!cur_sec_last){
    as_warn("[bbinfo]: the basic block 0x%x section %s does not record",
		cur_mbb->offset, cur_mbb->sec->name);
    // exit(-1);
  }

  // current basic block is the end of the its section
  if(cur_sec_last && cur_sec_last->offset == cur_mbb->offset){
    if (layout[index]->type & 1) // chage it to keep the mode information
    {
      // add to keep the mode information
      layout[index]->type &= (1 << 6);
      layout[index]->type |= 3;// 3 represents that it is both function and object end
    }
    else
    {
      layout[index]->type &= (1 << 6);
      layout[index]->type |= 2;
    }
  }


#ifdef BBINFO_DEBUG_MSG
  printf("[bbinfo]: bb%d - id %d, offset 0x%x, size 0x%x, alignment is %d, fix is %d,type %d, last bb added size %lld, sec %s\n",
		  index,cur_mbb->ID, cur_mbb->offset, cur_mbb->size, cur_mbb->alignment, cur_mbb->num_fixs,cur_mbb->type, last_mbb->parent_frag->last_bb_added_size, cur_mbb->sec->name);
#endif

  index++;
  
  obj_size += cur_mbb->size;
  last_sec = cur_mbb->sec;
}

// mark the last basic block as the end of object
/*if (index > 0){
  if (layout[index-1]->type == 1)
    layout[index-1]->type = 3; // 3 represents that it is both function and object end
  else
    layout[index-1]->type = 2;
}

// FIXME: specifal case: function .cold part and its main part will seperate.
if (index > 1){
 if (layout[index-1]->offset != (layout[index-2]->offset + layout[index-2]->bb_size)){ // the last basic block may be the .cold part
#ifdef BBINFO_DEBUG_MSG
   as_warn("[bbinfo]: The last basic block offset: 0x%x may be the .cold part", layout[index-1]->offset);
#endif
   if (layout[index-2]->type == 1)
     layout[index-2]->type = 3;
   else
     layout[index-2]->type = 2;
 }
}
*/

#ifdef BBINFO_DEBUG_MSG
if (bb_fix_num != text_fixp_cnt){
  as_warn(_("basic block's fixup number[%d] does not equal to total fixups number[%d]"), bb_fix_num, text_fixp_cnt);
if (bbinfo_file_name){
    save_to_tmp_directory(bbinfo_file_name);
    bbinfo_file_name = NULL;
  }
}
#endif

binary_info.has_obj_sz = 1;
binary_info.obj_sz = obj_size;

// update layout_info
reorder_info.n_layout = index;
reorder_info.layout = layout;

ShuffleInfo__ReorderInfo__FixupInfo **fixup;
fixup = malloc(sizeof(ShuffleInfo__ReorderInfo__FixupInfo *) * 1);
fixup[0] = malloc(sizeof(ShuffleInfo__ReorderInfo__FixupInfo));
shuffle_info__reorder_info__fixup_info__init(fixup[0]);

ShuffleInfo__ReorderInfo__FixupInfo__FixupTuple **text_fixp = NULL;
ShuffleInfo__ReorderInfo__FixupInfo__FixupTuple **rodata_fixp = NULL;
ShuffleInfo__ReorderInfo__FixupInfo__FixupTuple **data_fixp = NULL;
ShuffleInfo__ReorderInfo__FixupInfo__FixupTuple **datarel_fixp = NULL;
ShuffleInfo__ReorderInfo__FixupInfo__FixupTuple **init_fixp = NULL;

if (text_fixp_cnt)
  text_fixp = malloc(sizeof(ShuffleInfo__ReorderInfo__FixupInfo__FixupTuple *) * 
    								text_fixp_cnt);
if (rodata_fixp_cnt)
  rodata_fixp = malloc(sizeof(ShuffleInfo__ReorderInfo__FixupInfo__FixupTuple *) *
    								rodata_fixp_cnt);
if (data_fixp_cnt)
  data_fixp = malloc(sizeof(ShuffleInfo__ReorderInfo__FixupInfo__FixupTuple *) *
      								data_fixp_cnt);
if (init_fixp_cnt)
  init_fixp = malloc(sizeof(ShuffleInfo__ReorderInfo__FixupInfo__FixupTuple *) *
      								init_fixp_cnt);
if (datarel_fixp_cnt)
  datarel_fixp = malloc(sizeof(ShuffleInfo__ReorderInfo__FixupInfo__FixupTuple *) *
      								datarel_fixp_cnt);
unsigned cur_text_index = 0;
unsigned cur_rodata_index = 0;
unsigned cur_data_index = 0;
unsigned cur_datarel_index = 0;
unsigned cur_init_index = 0;

for (bbinfo_fixup* cur_fixp = fixups_list_head; cur_fixp;
    					cur_fixp = cur_fixp->next){
  if (!cur_fixp->sec)
    continue;

  ShuffleInfo__ReorderInfo__FixupInfo__FixupTuple *cur_fixp_tuple =
    		malloc(sizeof(ShuffleInfo__ReorderInfo__FixupInfo__FixupTuple));
  shuffle_info__reorder_info__fixup_info__fixup_tuple__init(cur_fixp_tuple); 
  cur_fixp_tuple->offset = cur_fixp->offset;
  cur_fixp_tuple->deref_sz = cur_fixp->size;
  cur_fixp_tuple->is_rela = cur_fixp->is_rela;
  cur_fixp_tuple->section_name = (char*) cur_fixp->sec->name;
  // jump table information
  if (cur_fixp->table_size){
    cur_fixp_tuple->has_num_jt_entries = 1;
    cur_fixp_tuple->num_jt_entries = cur_fixp->table_size;
    cur_fixp_tuple->has_jt_entry_sz = 1;
    cur_fixp_tuple->jt_entry_sz = cur_fixp->entry_size;
  }

  cur_fixp_tuple->has_type = 1;
  if (cur_fixp->is_new_section){
    cur_fixp_tuple->type = 4; // let linker know if there are multiple .text sections
  }else{
    cur_fixp_tuple->type = 0; // c2c, c2d, d2c, d2d default=0; should be updated by linker
  }

  int discard_cnt = 0;
  const char* sec_name =cur_fixp->sec->name;
  if (strstr(sec_name, ".text"))
    text_fixp[cur_text_index++] = cur_fixp_tuple;  
  else if(strstr(sec_name, ".rodata"))
    rodata_fixp[cur_rodata_index++] = cur_fixp_tuple;
  else if(strstr(sec_name, ".init_array"))
    init_fixp[cur_init_index++] = cur_fixp_tuple;
  else if(strstr(sec_name, ".data.rel.ro"))
    datarel_fixp[cur_datarel_index++] = cur_fixp_tuple;
  else if(strstr(sec_name, ".data"))
    data_fixp[cur_data_index++] = cur_fixp_tuple;
}

// store the fixup information into protobuf
fixup[0]->n_text = text_fixp_cnt;
fixup[0]->text = text_fixp;
fixup[0]->n_rodata = rodata_fixp_cnt;
fixup[0]->rodata = rodata_fixp;
fixup[0]->n_data = data_fixp_cnt;
fixup[0]->data = data_fixp;
fixup[0]->n_datarel = datarel_fixp_cnt;
fixup[0]->datarel = datarel_fixp;
fixup[0]->n_initarray = init_fixp_cnt;
fixup[0]->initarray = init_fixp;

reorder_info.n_fixup = 1;
reorder_info.fixup = fixup;

bbinfo_shuffle_info_buf_len = protobuf_c_message_get_packed_size(&reorder_info); // get protobuf bytes length

bbinfo_shuffle_info_buf = malloc(bbinfo_shuffle_info_buf_len);
protobuf_c_message_pack(&reorder_info, bbinfo_shuffle_info_buf); // Pack reorder_info into buf

// free the malloced space

// free layouts
for(index = 0; index < bb_cnt; index++){
  free(layout[index]);
}
free(layout);

// free fixups
for (index = 0; index < text_fixp_cnt; index++){
  free (text_fixp[index]);
}
for (index = 0; index < data_fixp_cnt; index++){
  free (data_fixp[index]);
}
for (index = 0; index < rodata_fixp_cnt; index++){
  free (rodata_fixp[index]);
}
for (index = 0; index < init_fixp_cnt; index++){
  free (init_fixp[index]);
}
for (index = 0; index < datarel_fixp_cnt; index++){
  free (datarel_fixp[index]);
}
if (text_fixp_cnt)
 free (text_fixp); 
if (rodata_fixp_cnt)
 free (rodata_fixp);
if (data_fixp_cnt)
 free (data_fixp);
if (init_fixp_cnt)
 free (init_fixp);
if (datarel_fixp_cnt)
 free (datarel_fixp);
}
#ifdef BBINFO_DEBUG_MSG
// debug function
int count_fixup_list_num(){
  bbinfo_fixup* fixp;
  int cnt = 0;
  for (fixp = fixups_list_head; fixp; fixp = fixp->next, cnt++);
  return cnt;
}
#endif

// init the fixup struct and insert it into fixups_list serially
bbinfo_fixup* bbinfo_init_insert_fixup(asection* sec, int offset){

  bbinfo_fixup* result_fixup = malloc(sizeof(bbinfo_fixup));
  // init
  memset (result_fixup, 0, sizeof(bbinfo_fixup));


  if (fixups_list_head == NULL){
    fixups_list_head = result_fixup;
    return result_fixup;
  }

  bbinfo_fixup* prev = NULL;
  bbinfo_fixup* cur = fixups_list_head;
  // find the section that is equal to sec
  while(cur && cur->sec != sec){
    prev = cur;
    cur = cur->next;
  }

  // The list does not have section sec
  if (!cur){
    prev->next = result_fixup;
    return result_fixup;
  }

  // find the proper place accourding to its offset
  while(cur && offset > cur->offset && cur->sec == sec){
    prev = cur;
    cur = cur->next;
  }

  // insert into the head
  if (!prev){
    result_fixup->next = fixups_list_head;
    fixups_list_head = result_fixup;
    return result_fixup;
  }
  prev->next = result_fixup;
  result_fixup->next = cur;
  return result_fixup;
}

/*
// init the fixup struct
bbinfo_fixup* bbinfo_init_fixup(void){
  bbinfo_fixup *result_fixup = malloc(sizeof(bbinfo_fixup));
  // init
  memset(result_fixup, 0, sizeof(bbinfo_fixup)); 

  // put it into the global fixups list
  if (fixups_list_head == NULL){
    fixups_list_head = result_fixup;
  }else{
    fixups_list_tail->next = result_fixup;
  }
  fixups_list_tail = result_fixup;
  return result_fixup;
}*/

// check if this is the new section
// TODO(binpang). Add it into a part of function bbinfo_is_new_sec
char bbinfo_is_new_sec_frag(asection *sec){
  // TODO. add new sections, such as .ctors, .fini_array, .dtors, .eh_frame ....
  if (!sec){
    as_warn(_("[bbinfo]: in function bbinfo_is_new_sec. The section is NULL"));
    return -1;
  }
  const char* sec_name = sec->name;
  char* tmp_pointer = NULL;
  char returned_value = -1;
  if ((tmp_pointer = strstr(sec_name, ".text")) &&
      tmp_pointer == sec_name){

    if (!text_sec_frag_cnt){
      text_sec_frag_cnt++;
      bbinfo_text_sec = sec;
      returned_value = 0;
    }
    else{
      returned_value = (bbinfo_text_sec == sec) ? 0 : 1;
      if(returned_value) text_sec_frag_cnt++;
      bbinfo_text_sec = sec;
    }
    return returned_value;
  }

  if ((tmp_pointer = strstr(sec_name, ".rodata")) && 
	tmp_pointer == sec_name){

    if (!rodata_sec_frag_cnt){
      rodata_sec_frag_cnt++;
      bbinfo_rodata_sec = sec;
      returned_value = 0;
    }else{
      returned_value = (bbinfo_rodata_sec == sec) ? 0 : 1;
      if (returned_value) rodata_sec_frag_cnt++;
      bbinfo_rodata_sec = sec;
    }
    return returned_value;
   }

  if ((tmp_pointer = strstr(sec_name, ".init_array")) &&
      tmp_pointer == sec_name){
    
    if (!init_sec_frag_cnt){
      init_sec_frag_cnt++;
      bbinfo_init_sec = sec;
      returned_value = 0;
    } else {
      returned_value = (bbinfo_init_sec == sec) ? 0 : 1;
      if (returned_value) init_sec_frag_cnt++;
      bbinfo_init_sec = sec;
    }
    return returned_value;
  }

  if ((tmp_pointer = strstr(sec_name, ".data")) &&
      tmp_pointer == sec_name){

    if ((tmp_pointer = strstr(sec_name, ".data.rel.ro")) &&
	tmp_pointer == sec_name){

      if (!datarel_sec_frag_cnt){
	datarel_sec_frag_cnt++;
	bbinfo_datarel_sec = sec;
	returned_value = 0;
      } else {
	returned_value = (bbinfo_datarel_sec == sec) ? 0 : 1;
	if (returned_value) datarel_sec_frag_cnt++;
	bbinfo_datarel_sec = sec;
      }
      return returned_value;
    }

    if (!data_sec_frag_cnt){
      data_sec_frag_cnt++;
      bbinfo_data_sec = sec;
      returned_value = 0;
    } else {
      returned_value = (bbinfo_data_sec == sec) ? 0 : 1;
      if (returned_value) data_sec_frag_cnt++;
      bbinfo_data_sec = sec;
    }

    return returned_value;
  }
  return -1;
}

// if this section is the collected section
// .text, .data.xxx, .rodata.xxxx, .init.xxx, .data.rel
char bbinfo_is_collect_sec(asection *sec){
  if (!sec){
    as_warn(_("[bbinfo]: in function bbinfo_is_new_sec. The section is NULL"));
    return -1;
  }
  const char* sec_name = sec->name;
  char* tmp_pointer = NULL;
  if ((tmp_pointer = strstr(sec_name, ".text")) &&
      tmp_pointer == sec_name){
      return 1;
  }

  if ((tmp_pointer = strstr(sec_name, ".rodata")) && 
	tmp_pointer == sec_name){
	return 1;
      }

  if ((tmp_pointer = strstr(sec_name, ".init_array")) &&
      tmp_pointer == sec_name){
      return 1;
  }

  if ((tmp_pointer = strstr(sec_name, ".data")) &&
      tmp_pointer == sec_name){

    if ((tmp_pointer = strstr(sec_name, ".data.rel.ro")) &&
	tmp_pointer == sec_name){
	return 1;
    }
      return 1;
  }
#ifdef BBINFO_DEBUG_MSG
  as_warn("discard fixup in section %s", sec_name);
#endif
  return 0;
}

// init the bbinfo struct
bbinfo_mbb* init_basic_block(){
  // malloc space
  bbinfo_mbb *result_mbb = malloc(sizeof(bbinfo_mbb));
  memset(result_mbb, 0, sizeof(bbinfo_mbb));
  result_mbb->next = NULL;

  // put it into the global basic blocks list
  if (mbbs_list_head == NULL){
    mbbs_list_head = result_mbb;
  }else{
    mbbs_list_tail->next = result_mbb;
  }
  mbbs_list_tail = result_mbb;
  return result_mbb;
}


// add to record the last pc inst
bbinfo_last_pc* bbinfo_init_last_pc(fragS* _frag,int _offset){
  bbinfo_last_pc *res = malloc(sizeof(bbinfo_last_pc));
  res->frag = _frag;
  res->offset = _offset;
  res->next = NULL;
  res->symbol = NULL;
  res->size = 0;
  return res;
}

// add to create symbol list to record all symbol used by inst
bbinfo_symbol_list* bbinfo_init_symbol_list(){
  bbinfo_symbol_list *result_symbol = malloc(sizeof(bbinfo_symbol_list));
  result_symbol->next = NULL;

  // put it into the global basic blocks list
  if (symbol_list_head == NULL){
    symbol_list_head = result_symbol;
  }else{
    symbol_list_tail->next = result_symbol;
  }
  symbol_list_tail = result_symbol;
  return result_symbol;
}

// create list to save the added fixup

bbinfo_last_pc* bbinfo_init_added_fixup(){
  bbinfo_last_pc *added_fixup = malloc(sizeof(bbinfo_last_pc));
  added_fixup->next = NULL;

  // put it into the global basic blocks list
  if (added_fixups_list_head == NULL){
    added_fixups_list_head = added_fixup;
  }else{
    added_fixups_list_tail->next = added_fixup;
  }
  added_fixups_list_tail = added_fixup;
  return added_fixup;
}

//add to check the symbol whether used by inst
char bbinfo_check_symbol_use()
{
  const char* symbol_now = S_GET_NAME(last_symbol);
  bbinfo_symbol_list* i;
  char res = 0;
  for(i = symbol_list_head;i;i = i->next)
  {
    //printf("T:%s %s\n",i->symbol_name,symbol_now);
    int len1 = strlen(i->symbol_name);
    int len2 = strlen(symbol_now);
    if(len1 == len2 && strncmp(i->symbol_name,symbol_now,len1) == 0)
    {
      res = 1;
      #ifdef BBINFO_DEBUG_MSG
        printf("T:Find Used Symbol is %s\n",symbol_now);
      #endif
      break;
    }
  }
  return res;
}

char is_arm32() {
  return !strcmp(stdoutput->arch_info->arch_name, "arm");
}

char bbinfo_is_mips() {
  return !strcmp(stdoutput->arch_info->arch_name, "mips");
}

// handle bbinfo_jmptbl directive
void jmptable_bbInfo_handler(int ignored ATTRIBUTE_UNUSED){
    offsetT table_size, entry_size;
    table_size = get_absolute_expression();
    SKIP_WHITESPACE();

    entry_size = get_absolute_expression();
    if (last_symbol == NULL){
	    //printf("Sorry, the last symbol is null\n");
	    return;
    }

    //add fixup

    if(is_arm32() && bbinfo_check_symbol_use() == 0)
    {
      //printf("Now added %x symbol is %s\n",last_pc->offset,S_GET_NAME(last_symbol));
      bbinfo_last_pc* added_fixup = bbinfo_init_added_fixup();
      added_fixup->frag = last_pc->frag;
      added_fixup->offset = last_pc -> offset;
      added_fixup->size = last_pc -> size;
      added_fixup->symbol = last_symbol;
    }

    // update the jump table related information of the symbol
    S_SET_JMPTBL_SIZE(last_symbol, table_size);
    //as_warn("JMPTBL table size is %d\n", table_size);
    S_SET_JMPTBL_ENTRY_SZ(last_symbol, entry_size);
    //as_warn("T JMPTBL entrysize is %d\n", entry_size);
    // const char* symbol_name = S_GET_NAME(last_symbol);
    // as_warn("last symbol is %s", symbol_name);
    // debug
    //printf("last_symbol is %s\n", S_GET_NAME(last_symbol));
}

void handwritten_funcb_bbinfo_handler(){
  // make sure that current file is handwritten file
  if (!bbinfo_handwritten_file)
    return;
  // if the last basic block is not used, we don't need initialize another basic block
  if (mbbs_list_tail && mbbs_list_tail->is_begin)
    return;
 
  // we type the last basic block type as the end of the function
  if (mbbs_list_tail)
  {
    mbbs_list_tail->type &= (1 << 6);
    mbbs_list_tail->type |= 1;
  }
  
    bbinfo_mbb *cur_mbb = init_basic_block();
    cur_mbb->ID = cur_block_id++;
    cur_mbb->type = 0;
    cur_mbb->offset = -1;
    cur_mbb->size = 0;
    cur_mbb->alignment = 0;
    cur_mbb->num_fixs = 0;
    cur_mbb->fall_through = 0;
    cur_mbb->sec = NULL;
    cur_mbb->parent_id = cur_function_id;
    cur_mbb->is_begin = 1;
}

void handwritten_funce_bbinfo_handler(){
  if (!bbinfo_handwritten_file)
    return;
  if (!mbbs_list_tail)
     as_fatal("[bbinfo]: funce_bbinfo_handler. the mbbs_list_tail is null");
  mbbs_list_tail->type &= (1 << 6);
  mbbs_list_tail->type |= 1;
}

// handle bbinfo_funcb directive, it represents function begin
void funcb_bbInfo_handler (int ignored ATTRIBUTE_UNUSED){
    prev_function_id = cur_function_id;
    cur_function_id++;
    function_head = 1;

    // current file is c/c++ file
    if (bbinfo_handwritten_file){
      bbinfo_handwritten_file = 0;
    }

    if (mbbs_list_tail && mbbs_list_tail->is_begin)
      return;

    // Here, we initialize the bbinfo_mbb
    // For some specifal case(such as c++ non-virtual thunk to function)
    // gcc can't output basic block information
    bbinfo_mbb *cur_mbb = init_basic_block();
    cur_mbb->ID = cur_block_id++;
    cur_mbb->type = 0;
    cur_mbb->offset = -1;
    cur_mbb->size = 0;
    cur_mbb->alignment = 0;
    cur_mbb->num_fixs = 0;
    cur_mbb->fall_through = 0;
    cur_mbb->sec = NULL;
    cur_mbb->parent_id = cur_function_id;
    cur_mbb->is_begin = 1;
}

// handle bbinfo_funce directive, it represents function end
void funce_bbInfo_handler (int ignored ATTRIBUTE_UNUSED){
   cur_function_end_id++;
   if (!mbbs_list_tail){
     as_fatal("[bbinfo]: funce_bbinfo_handler. the mbbs_list_tail is null");
     exit(-1);
   }
   mbbs_list_tail->type &= (1 << 6);
   mbbs_list_tail->type |= 1;
   if (cur_function_end_id != cur_function_id)
     as_warn(_("[bbInfo]: current function end id don not match current function id")); 
}

// For handwritten file, add `fake` basic block.
void bbinfo_initbb_handwritten(void){
    bbinfo_mbb *cur_mbb = init_basic_block();

    // init the basic_block element
    cur_mbb->ID = cur_block_id++;
    cur_mbb->type = 0;
    cur_mbb->offset = -1;
    cur_mbb->size = 0;
    cur_mbb->alignment = 0;
    cur_mbb->num_fixs = 0;
    cur_mbb->fall_through = 0;
    cur_mbb->sec = NULL;
    cur_mbb->parent_id = 0;
    cur_mbb->is_begin = 1;


}

void bbinfo_init_bb() {
   // The lastest basic block doesn't contain any instruction
    // just return;
    if (mbbs_list_tail && mbbs_list_tail->is_begin == 1)
      return;
    bbinfo_mbb *cur_mbb = init_basic_block();

    // current file is c/c++ file
    if (bbinfo_handwritten_file){
      bbinfo_handwritten_file = 0;
    }
    // init the basic_block element
    cur_mbb->ID = cur_block_id++;
    cur_mbb->type = 0;
    cur_mbb->offset = -1;
    cur_mbb->size = 0;
    cur_mbb->alignment = 0;
    cur_mbb->num_fixs = 0;
    cur_mbb->fall_through = 0;
    cur_mbb->sec = NULL;
    cur_mbb->parent_id = cur_function_id;
    cur_mbb->is_begin = 1;
}

// handle bbinfo_bb directive, it represents basic block begin
void bb_bbInfo_handler (int ignored ATTRIBUTE_UNUSED){

    // The lastest basic block doesn't contain any instruction
    // just return;
    offsetT fall_through;
    fall_through = get_absolute_expression();

    if (mbbs_list_tail && mbbs_list_tail->is_begin == 1) {
      if (fall_through == 1) {
        mbbs_list_tail->fall_through = 1;
      } else {
        mbbs_list_tail->fall_through = 0;
      }
      return;
    }
    bbinfo_mbb *cur_mbb = init_basic_block();

    // current file is c/c++ file
    if (bbinfo_handwritten_file){
      bbinfo_handwritten_file = 0;
    }

    // init the basic_block element
    cur_mbb->ID = cur_block_id++;
    cur_mbb->type = 0;
    cur_mbb->offset = -1;
    cur_mbb->size = 0;
    cur_mbb->alignment = 0;
    cur_mbb->num_fixs = 0;
    if (fall_through == 1)
      cur_mbb->fall_through = 1;
    else
      cur_mbb->fall_through = 0;
    cur_mbb->sec = NULL;
    cur_mbb->parent_id = cur_function_id;
    cur_mbb->is_begin = 1;

    //if (function_head){
    //  cur_mbb->type = 1; // this basic block is the first block of a function
    //  function_head = 0;
   // }

}

// handle bbinfo_be directive, it represents basic block end
void be_bbInfo_handler (int ignored ATTRIBUTE_UNUSED){
    offsetT fall_through;
    fall_through = get_absolute_expression();
    if (fall_through == 1)
      mbbs_list_tail->fall_through = 1;
    bbinfo_handled_ee = 1;
}

void inlineb_bbInfo_handler (int ignored ATTRIBUTE_UNUSED){
    bbinfo_app = 1;  
    if (mbbs_list_tail){
      mbbs_list_tail->is_inline = 1;
    }
    #ifdef BBINFO_DEBUG_MSG
      as_warn(_("[bbInfo]: Handle .bbinfo_inlineb"));
    #endif
}

void inlinee_bbInfo_handler (int ignored ATTRIBUTE_UNUSED){
    bbinfo_app = 0;
    #ifdef BBINFO_DEBUG_MSG
      as_warn(_("[bbInfo]: Handle .bbinfo_inlinee"));
    #endif
}
