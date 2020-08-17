#ifndef PE_MAP_H
#define PE_MAP_H

#include <string>
#include <sstream>
#include <algorithm>
#include <vector>
#include <set>
#include <map>
#include <deque>

#include <boost/algorithm/string.hpp>

#include "refInf.pb.h"
#include "blocks.pb.h"

#define PEMAP_VERSION  "pemap v0.71"
#define PEMAP_CREDITS  "Copyright (C) 2015 Dennis Andriesse\n"                                       \
                        "This is free software; see the source for copying conditions. There is NO\n" \
                        "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."

#define DUMP_PARTIAL_FUNCS  1  /* set to non-zero to dump functions without signature info */

#define X86_MAX_INS_LEN  16
#define CODE_CHUNK_SIZE  4096  /* 4K ought to be enough for anybody */

#define IMAGE_SCN_CNT_CODE 0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040

#define ERROUT  stdout

/* text colors */
#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"


void verbose(int level, char const *fmt, ...);

#define bt_assert(c) assert(c)

typedef struct {
  char* pdb_fname;
  char* pe_fname;
  int fd;
  uint64_t base_addr;
  int         bits;          /* 32-bit or 64-bit    */
  uint64_t    entry;         /* PE entry point     */
} pe_data_t;


typedef enum {
  MAP_FLAG_f = 0x00,  /* b00 - false, uncertain */
  MAP_FLAG_F = 0x02,  /* b10 - false, certain   */
  MAP_FLAG_t = 0x01,  /* b01 - true , uncertain */
  MAP_FLAG_T = 0x03   /* b11 - true , certain   */
} map_flag_t;

extern int verbosity;
extern int warnings;

extern int have_llvminfo;
extern int skip_func_sigs;
extern int track_overlapping_blocks;
extern int track_funcs;
extern int guess_func_entry;
extern int guess_return;
extern int ignore_fallthrough;
extern int ignore_padding;
extern int symbols_only;
extern int allow_overlapping_ins;
extern int map_show_insbounds;
extern int map_limit_16_bytes;

struct btype {
  btype() : code(MAP_FLAG_t), insbound(MAP_FLAG_f), overlapping(MAP_FLAG_f), bbstart(MAP_FLAG_f), funcstart(MAP_FLAG_f), funcend(MAP_FLAG_f), cflow(MAP_FLAG_f), call(MAP_FLAG_f), progentry(MAP_FLAG_f), nop(MAP_FLAG_f) {}
  btype(map_flag_t code_) :   insbound(MAP_FLAG_f), overlapping(MAP_FLAG_f), bbstart(MAP_FLAG_f), funcstart(MAP_FLAG_f), funcend(MAP_FLAG_f), cflow(MAP_FLAG_f), call(MAP_FLAG_f), progentry(MAP_FLAG_f), nop(MAP_FLAG_f)
  {
    code = code_;
  }
  inline bool safe_mark(map_flag_t m, map_flag_t *curr, bool strict = false)
  {
    register bool flag, certain;

    /* we cannot change our mind about a property once we're certain
     * XXX: if the new classification is uncertain, we can safely ignore it, but 
     * if we ever get an assertion failure, it means our certainty assumptions are flawed! */
    flag = (m & 0x01); certain = (m & 0x02);
    if( flag && ((*curr) == MAP_FLAG_F)) { if(strict) bt_assert(!certain); return 0; }
    if(!flag && ((*curr) == MAP_FLAG_T)) { if(strict) bt_assert(!certain); return 0; }

    (*curr) = m;

    return 1;
  }
  bool mark(map_flag_t code_, map_flag_t insbound_ = MAP_FLAG_f, map_flag_t bbstart_ = MAP_FLAG_f, 
            map_flag_t funcstart_ = MAP_FLAG_f, map_flag_t funcend_ = MAP_FLAG_f, map_flag_t cflow_ = MAP_FLAG_f,
            map_flag_t call_ = MAP_FLAG_f, map_flag_t progentry_ = MAP_FLAG_f, map_flag_t nop_ = MAP_FLAG_f)
  {
    bool flag;

    /* data bytes cannot have code-like properties */
    flag = (code_ & 0x01);
    assert(!(!flag && (insbound_  & 0x01)));
    assert(!(!flag && (bbstart_   & 0x01)));
    assert(!(!flag && (funcstart_ & 0x01)));
    assert(!(!flag && (funcend_   & 0x01)));
    assert(!(!flag && (cflow_     & 0x01)));
    assert(!(!flag && (call_      & 0x01)));
    assert(!(!flag && (progentry_ & 0x01)));
    assert(!(!flag && (nop_       & 0x01)));

    /* entry points/exit points must start at an instruction boundary */
    flag = (insbound_ & 0x01);
    assert(!(!flag && (bbstart_   & 0x01)));
    assert(!(!flag && (funcstart_ & 0x01)));
    assert(!(!flag && (funcend_   & 0x01)));
    assert(!(!flag && (cflow_     & 0x01)));
    assert(!(!flag && (call_      & 0x01)));
    assert(!(!flag && (progentry_ & 0x01)));
    /*assert(!(!flag && (nop_       & 0x01)));*/

    if(!safe_mark(code_, &code)) return 0;

    /* special treatment if instructions may overlap */
    if(allow_overlapping_ins) {
      if(!safe_mark(insbound_, &insbound, false)) {
        if(insbound_ == MAP_FLAG_T) {
          overlapping = MAP_FLAG_T;
        }
      }
      safe_mark(bbstart_  , &bbstart  , false);
      safe_mark(funcstart_, &funcstart, false);
      safe_mark(funcend_  , &funcend  , false);
      safe_mark(cflow_    , &cflow    , false);
      safe_mark(call_     , &call     , false);
      safe_mark(progentry_, &progentry, false);
      safe_mark(nop_      , &nop      , false);
    } else {
      safe_mark(insbound_ , &insbound);
      safe_mark(bbstart_  , &bbstart);
      safe_mark(funcstart_, &funcstart);
      safe_mark(funcend_  , &funcend);
      safe_mark(cflow_    , &cflow);
      safe_mark(call_     , &call);
      safe_mark(progentry_, &progentry);
      safe_mark(nop_      , &nop);
    }

    return 1;
  }
  map_flag_t code;
  map_flag_t insbound;
  map_flag_t overlapping;
  map_flag_t bbstart;
  map_flag_t funcstart;
  map_flag_t funcend;
  map_flag_t cflow;
  map_flag_t call;
  map_flag_t progentry;
  map_flag_t nop;
};
typedef struct btype btype_t;

struct map_range {
  map_range() : addr(0), size(0), btypes() {}
  map_range(uint64_t addr_, uint64_t size_) : btypes()
  {
    addr = addr_;
    size = size_;
  }
  btype_t *get_btype(uint64_t addr_)
  {
    if((addr_ < addr) || (addr_ >= (addr + btypes.size()))) {
      return NULL;
    }
    return &btypes[addr_ - addr];
  }
  uint64_t             addr;   /* start of range            */
  uint64_t             size;   /* length of range           */
  std::vector<btype_t> btypes; /* per-byte type descriptors */
};
typedef struct map_range map_range_t;

enum BlockType { 
    OTHER = 0, // other type
    DIRECT_CALL, // direct call instruction 
    INDIRECT_CALL, // indirect call instruction 
    RET, //ret instruction 
    COND_BRANCH, //conditional jump(direct)
    DIRECT_BRANCH, //direct jump 
    INDIRECT_BRANCH, //indirect jump
    JUMP_TABLE, //jump table
    NON_RETURN_CALL, //non-return function call
    FALL_THROUGH, //fall_through
    OVERLAPPING_INST, //overlapping instruction(not used)
    TAIL_CALL, //tail call
    FALLTHROUGH_TOFUNC, // fall through to another function. these two functin share some codes
    JUMP_TOFUNC, // jump to another function start, but in current functin range. that is 			these two function share some codes
    DUMMY_JMP_TABLE // dummy jump table
};


#define SEC_TYPE_NONE      0x00
#define SEC_TYPE_PROGBITS  0x01

#define SEC_FLAG_READ   0x01
#define SEC_FLAG_WRITE  0x02
#define SEC_FLAG_EXEC   0x04

struct section_map {
  section_map() : name(""), flags(0), addr(0), size(0), map() {}
  std::string              name;   /* section name             */
  int			   idx;    /* index number */
  uint8_t                  flags;  /* rwx flags                */
  uint64_t                 off;    /* file offset              */
  uint64_t                 addr;   /* base address             */
  uint64_t                 size;   /* size in bytes            */
  std::set<uint64_t>       dismap; /* disassembled addresses   */
  std::vector<map_range_t> map;    /* code/data map of section */
};
typedef struct section_map section_map_t;


#define SYM_TYPE_FUNC    0x01
#define SYM_TYPE_OBJECT  0x02
#define SYM_TYPE_TLS     0x03

struct symbol {
  symbol(uint8_t type_, char *name_, uint64_t value_, uint64_t size_)
  {
    type  = type_;
    name  = std::string(name_);
    value = value_;
    size  = size_;
  }
  uint8_t     type;
  std::string name;
  uint64_t    value;
  uint64_t    size;
};
typedef struct symbol symbol_t;


typedef struct {
  bool is_libs_code; // if the compiler unit is dynamic library
  std::vector<std::string> path_list; // path list, seperated by path delim
  std::map<unsigned, uint64_t> line2addr; // line numbers in cu to addrs
  std::map<uint64_t, unsigned> addr2line; // addrs to line numbers
} cu_t;

struct function {
  function(std::string name_, uint64_t addr_, size_t len_)
  {
    char *demangled;

     demangled = cplus_demangle(name_.c_str(), DMGL_NO_OPTS);
    if(demangled) {
      name = std::string(demangled);
      free(demangled);
    } else {
      name = name_;
    }

    mangled_name = name_;
    cu_path      = "";
    base         = addr_;
    ranges.push_back(std::pair<uint64_t, size_t>(addr_, len_));
    startline    = 0;
    endline      = 0;
    valid_sig    = false;
    ret          = "int";
    callconv     = "";
    inlined      = false;
    nothrow      = false;
    noret        = false;
    addrtaken    = false;
    dead         = false;
    multiret     = false;

    verbose(2, "created function %s (%s) @ 0x%jx (%zu)", name.c_str(), mangled_name.c_str(), base, len_);
  }
  std::string                  name;                 /* function name                  */
  std::string                  mangled_name;         /* mangled function name          */
  std::string                  cu_path;              /* path to compile unit           */
  uint64_t                     base;                 /* base address                   */
  std::vector< std::pair<uint64_t, size_t> > ranges; /* address ranges                 */
  unsigned                     startline;            /* first line nr of function      */
  unsigned                     endline;              /* last line nr of function       */
  std::map<unsigned, uint64_t> line2addr;            /* line numbers in cu to addrs    */
  std::map<uint64_t, unsigned> addr2line;            /* addrs to line numbers in cu    */
  bool                         valid_sig;            /* return/param types are set     */
  std::string                  ret;                  /* return type                    */
  std::vector<std::string>     params;               /* parameter types                */
  std::vector<std::string>     attributes;           /* function attributes            */
  std::string                  callconv;             /* calling convention             */
  bool                         inlined;              /* true if func is inlined        */
  bool                         nothrow;              /* true if func does not throw    */
  bool                         noret;                /* true if func never returns     */
  bool                         addrtaken;            /* true if func is address taken  */
  bool                         dead;                 /* true if func is trivially dead */
  bool                         multiret;             /* true if func calls multiret fn */
};
typedef struct function function_t;


typedef struct {
  uint64_t    addr; /* address of the overlap (NOT starting address of BB) */
  function_t *f;    /* overlapping function (overlaps g)                   */
  function_t *g;    /* overlapped  function (overlapped by f)              */
} overlapping_bb_t;


typedef struct {
  std::string funcname;
  std::string cu_path;
  unsigned    start_line;
  uint64_t    start_addr;
  unsigned    end_line;
  uint64_t    end_addr;
} address_taken_bb_t;

typedef struct data_in_code_reg_s{
  std::string cu_file;
  std::map<uint32_t, uint32_t> regions; // key is start line, value is end line

  data_in_code_reg_s(){}
} data_in_code_reg_t;

typedef struct jmptbl_s{
  uint64_t base_addr_fixup; // which fixup points to base address
  uint64_t base_addr;
  uint32_t size;
  uint32_t entry_size;
  std::set<uint64_t> cases_addr;
  std::vector<uint64_t> fixups_addr;

  jmptbl_s() : base_addr_fixup(0), base_addr(0), size(0), entry_size(0){}
} jmptbl_t;

typedef struct switch_s{
  std::vector<std::string>  cu_path_list;
  std::string		cu_path;
  bool 			parse_succeed;
  bool			compiled_to_jtable; // if the switch statements compiled to jump table
  unsigned              start_line;
  uint64_t              start_addr;
  std::vector<unsigned> case_lines;
  std::vector<uint64_t> case_addrs;
  unsigned              default_line;
  uint64_t              default_addr;

  switch_s(): parse_succeed(0), compiled_to_jtable(0){}
} switch_t;

typedef struct fixup_s{
  uint64_t va; 		// fixup address
  uint64_t target;	// fixup target address
  uint32_t size; 	// fixup size
  bool to_code;
  mutable uint64_t parent;      // for code fixup, function address

  fixup_s(uint64_t va_, uint64_t target_, uint32_t size_, bool to_code_) : va(va_), target(target_), size(size_), to_code(to_code_), parent(0){}

  bool operator<(const fixup_s& rhs) const{
    return va < rhs.va;
  }

  bool operator==(const fixup_s& rhs) const{
    return va == rhs.va;
  }

  bool operator==(const uint64_t& rhs) const{
    return va == rhs;
  }

} fixup_t;

int parse_fixup_pb(const char* fixup_pb, std::set<fixup_t>&, RefInf::RefList&, std::vector<section_map_t>&);

//void filter_switch_jtable(std::vector<switch_t>&, std::multiset<fixup_t>&);
void filter_jtable(std::vector<function_t>& funcs, std::vector<jmptbl_t>&, std::set<fixup_t>&, std::set<uint64_t>&);

void roughly_pair_jtable(std::vector<jmptbl_t>&, std::map<uint64_t, blocks::BasicBlock*>&);

int parse_dataincode_info(const char*, std::vector<data_in_code_reg_t>&);

int output_pb(const char* output_pb, blocks::module&);

#endif
