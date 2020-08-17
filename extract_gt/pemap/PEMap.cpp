/*
 * pemap.C
 *
 * Reference: https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_andriesse.pdf
 *
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <assert.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <getopt.h>
#define HAVE_DECL_BASENAME 1 /* fix nameclash for basename in libiberty */
#include <libiberty/demangle.h>

#include <execinfo.h>

#ifndef EM_X86_64
#define EM_X86_64  EM_AMD64
#endif /* EM_X86_64 */

#include <capstone/capstone.h>

#include <string>
#include <sstream>
#include <algorithm>
#include <vector>
#include <set>
#include <map>
#include <deque>
#include <fstream>
#include <cmath>
#include <iostream>

#include <boost/algorithm/string.hpp>

#include "PEMap.h"
#include "blocks.pb.h"
#include "refInf.pb.h"

int verbosity = 2;
int warnings  = 1;

int have_llvminfo            = 0;
int skip_func_sigs           = 0;
int track_overlapping_blocks = 0;
int track_funcs              = 0;
int guess_func_entry         = 0;
int guess_return             = 0;
int ignore_fallthrough       = 0;
int ignore_padding           = 0;
int symbols_only             = 0;
int allow_overlapping_ins    = 0;
int map_show_insbounds       = 0;
int map_limit_16_bytes       = 0;


std::set<uint64_t> ud2_insts;

void __bt_assert(bool c);
#define bt_assert(c) assert(c)

void
verbose(int level, char const *fmt, ...)
{
  va_list args;

  if(verbosity >= level) {
    va_start(args, fmt);
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
  }
}


void
print_warn(char const *fmt, ...)
{
  va_list args;

  if(warnings) {
    va_start(args, fmt);
    fprintf(ERROUT, "WARNING: ");
    vfprintf(ERROUT, fmt, args);
    fprintf(ERROUT, "\n");
    va_end(args);
  }
}


void
print_err(char const *fmt, ...)
{
  va_list args;

  va_start(args, fmt);
  fprintf(ERROUT, "ERROR: ");
  vfprintf(ERROUT, fmt, args);
  fprintf(ERROUT, "\n");
  va_end(args);
}


bool check_string_blank(std::string cur_line_str){
  return std::all_of(cur_line_str.cbegin(), cur_line_str.cend(), [](char c){
      return std::isspace(c);
      });
}

// check current string is `blank` or `line addr`
bool check_line_addr_line(std::string cur_line_str){
  return std::all_of(cur_line_str.cbegin(), cur_line_str.cend(), [](char c){
      return (std::isspace(c) || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'));
      });
}

unsigned long
hash_str_to_int(std::string s)
{
  unsigned long h;

  h = 5381;
  for(auto cc : s) {
    h = (h << 5) + h + cc;
  }

  return h;
}


std::string
hash_path(std::string s)
{
  char *c, *bname;
  std::string hash;
  unsigned long h;
  std::stringstream stream;

  h = 5381;
  for(auto cc : s) {
    h = (h << 5) + h + cc;
  }
  stream << std::hex << h;

  c = strdup(s.c_str());
  if(!c) {
    return "";
  }
  bname = basename(c);
  hash = "h" + stream.str().substr(0, 6) + "_" + std::string(bname);
  std::replace(hash.begin(), hash.end(), '.', '_');
  free(c);

  return hash;
}


std::string
vecjoin(std::vector<std::string> *v, std::string sep)
{
  size_t i;
  std::stringstream ss;

  for(i = 0; i < v->size(); i++) {
    if(i > 0) {
      ss << sep;
    }
    ss << v->at(i);
  }

  return ss.str();
}


void
__bt_assert(bool c)
{
#ifndef NDEBUG
  int i, p, tracelen;
  void *trace[32];
  char **msg, cmd[256];

  if(!c) {
    print_err("Assertion failed");

    tracelen = backtrace(trace, 32);
    msg = backtrace_symbols(trace, tracelen);
    if(!msg) {
      print_err("failed to get backtrace");
      exit(1);
    }

    for(i = 0; i < tracelen; i++) {
      fprintf(ERROUT, "    #%d %s", i, msg[i]);
      p = 0;
      while(msg[i][p] != '(' && msg[i][p] != ' ' && msg[i][p] != 0) {
        p++;
      }
      sprintf(cmd, "addr2line %p -e %.*s 1>&2", trace[i], p, msg[i]);
      if(system(cmd) != 0) {
      }
    }

    exit(1);
  }
#endif
}

bool
addr_in_map_range(map_range_t *range, uint64_t addr)
{
  return (addr >= range->addr) && (addr < (range->addr + range->size));
}


map_range_t*
map_range_by_addr(section_map_t *smap, uint64_t addr)
{
  size_t i;

  for(i = 0; i < smap->map.size(); i++) {
    if(addr_in_map_range(&smap->map[i], addr)) {
      return &smap->map[i];
    }
  }

  return NULL;
}


inline bool
addr_in_section_map(section_map_t *smap, uint64_t addr)
{
  return (addr >= smap->addr) && (addr < (smap->addr + smap->size));
}


section_map_t*
section_map_by_addr(std::vector<section_map_t> *smaps, uint64_t addr)
{
  register size_t i;

  for(i = 0; i < smaps->size(); i++) {
    if(addr_in_section_map(&smaps->at(i), addr)) {
      return &smaps->at(i);
    }
  }

  return NULL;
}


map_range_t*
section_map_range_by_addr(std::vector<section_map_t> *smaps, uint64_t addr)
{
  section_map_t *s;

  s = section_map_by_addr(smaps, addr);
  if(s) {
    return map_range_by_addr(s, addr);
  } else {
    return NULL;
  }
}


btype_t*
btype_by_addr(std::vector<section_map_t> *smaps, uint64_t addr)
{
  map_range_t *map;
  btype_t *b;

  map = section_map_range_by_addr(smaps, addr);
  if(!map) {
    return NULL;
  }
  b = map->get_btype(addr);
  assert(b);

  return b;
}

int
read_pe_section_by_off(pe_data_t *pe, off_t off, uint8_t *dst, size_t *len, char const **err)
{
  int ret;
  off_t saved_off;

  saved_off = lseek(pe->fd, 0, SEEK_CUR);

  if(lseek(pe->fd, off, SEEK_SET) != off) {
    (*err) = "failed to seek to offset in PE binary";
    goto fail;
  }

  (*len) = read(pe->fd, dst, (*len));
  if((*len) < 1) {
    (*err) = "failed to read bytes from PE binary";
    goto fail;
  }

  if(lseek(pe->fd, saved_off, SEEK_SET) != saved_off) {
    (*err) = "failed to seek to offset in PE binary";
    goto fail;
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  return ret;
}


int
read_pe_section_by_addr(pe_data_t *pe, std::vector<section_map_t> *smaps, uint64_t addr, uint8_t *dst, size_t *len, char const **err){
  int ret;
  off_t saved_off, off;
  section_map_t *sec;

  saved_off = lseek(pe->fd, 0, SEEK_CUR);

  sec = section_map_by_addr(smaps, addr);
  if(!sec) {
    (*err) = "address points outside mapped sections (1)";
    goto fail;
  }

  off = sec->off + (addr - sec->addr);
  if(lseek(pe->fd, off, SEEK_SET) != off) {
    (*err) = "failed to seek to offset in PE binary";
    goto fail;
  }

  (*len) = read(pe->fd, dst, (*len));
  if((*len) < 1) {
    (*err) = "failed to read bytes from PE binary";
    goto fail;
  }

  if(lseek(pe->fd, saved_off, SEEK_SET) != saved_off) {
    (*err) = "failed to seek to offset in PE binary";
    goto fail;
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  return ret;
}


bool check_nonreturn_func(std::set<uint64_t>& nonret_funcs_addr, uint64_t target){
  if (nonret_funcs_addr.find(target) != nonret_funcs_addr.end()){
    verbose(1, "[non-return]: nonret_func size is %d, target 0x%lx is non-return function", nonret_funcs_addr.size(), target);
    return true;
  }
  return false;
}

int
is_cs_nop_ins(cs_insn *ins)
{
  switch(ins->id) {
  case X86_INS_NOP:
  case X86_INS_FNOP:
  case X86_INS_INT3:
    return 1;
  default:
    return 0;
  }
}

int is_cs_terminate_ins(cs_insn *ins){
	switch (ins->id){
		case X86_INS_UD2:
		case X86_INS_HLT:
			verbose(1, "insturction at 0x%llx is a termiante instruction!\n", ins->address);
			return 1;
		default:
			return 0;
	}
}


int
is_cs_cflow_group(uint8_t g)
{
  return (g == CS_GRP_JUMP) || (g == CS_GRP_CALL) || (g == CS_GRP_RET) || (g == CS_GRP_IRET);
}

/*
 * parse terminator instruction
 *
 * ret: true or false
 *
 * args:
 * 	ins: parsed instruction
 * 	target: direct call or jump targets
 * 	type: terminator type
 */
int parse_terminator(cs_insn *ins, uint64_t &target, uint32_t &type, csh &handler, std::set<uint64_t>& nonret_funcs_addr){
  int i, j;
  uint8_t g;
  bool is_jump = false;
  bool is_call = false;
  bool is_ret = false;
  bool is_indirect = false;
  const char* reg_name = NULL;

  cs_x86_op *op;

  for (i = 0; i < ins->detail->groups_count; i++){
    g = ins->detail->groups[i];
    if (g == CS_GRP_JUMP){
      is_jump = true;
      break;
    } else if (g == CS_GRP_CALL){
      is_call = true;
      break;
    } else if (g == CS_GRP_RET || g == CS_GRP_IRET){
      is_ret = true;
      break;
    }
  }

  if (is_ret){
    type = BlockType::RET;
    return true;
  }

  if (is_jump || is_call) {
    for (j = 0; j < ins->detail->x86.op_count; j++){
      op = &ins->detail->x86.operands[j];
      
      // may be indirect
      if (op->type == X86_OP_REG){
	reg_name = cs_reg_name(handler, op->reg);

	// do not consider this as indirect type
	if (!strcmp(reg_name, "rip") || !strcmp(reg_name, "eip") || 
	    !strcmp(reg_name, "RIP") || !strcmp(reg_name, "EIP")){
	  continue;
	}
	is_indirect = true;
      } else if (op->type == X86_OP_MEM && op->mem.index != 0){
	is_indirect = true;
      } else if (op->type == X86_OP_IMM){
	target = op->imm;
      }

      if (is_indirect){
	if (is_jump)
	  type = BlockType::INDIRECT_BRANCH;
	else if (is_call)
	  type = BlockType::INDIRECT_CALL;
	return true;
      }
    }

    // until here, the terminator is direct call/jump
    if (is_jump){
      if (strstr(ins->mnemonic, "jmp"))
	type = BlockType::DIRECT_BRANCH;
      else
	type = BlockType::COND_BRANCH;
    }
    // function call
    else{
      if (check_nonreturn_func(nonret_funcs_addr, target)){
	type = BlockType::NON_RETURN_CALL;
	verbose(1, "non_return bb type is 0x%lx", ins->address);
      }
      else
	type = BlockType::DIRECT_CALL;
    }

    return true;
  }
  type = BlockType::FALL_THROUGH;
  return true;
}

int
is_cs_cflow_ins(cs_insn *ins)
{
  size_t i;

  for(i = 0; i < ins->detail->groups_count; i++) {
    if(is_cs_cflow_group(ins->detail->groups[i])) {
      return 1;
    }
  }

  return 0;
}


int
is_cs_call_ins(cs_insn *ins)
{
  switch(ins->id) {
  case X86_INS_CALL:
  case X86_INS_LCALL:
    return 1;
  default:
    return 0;
  }
}


int
is_cs_ret_ins(cs_insn *ins)
{
  size_t i;
  uint8_t g;
  for (i = 0; i < ins->detail->groups_count; i++){
    g = ins->detail->groups[i];
    if (g == CS_GRP_RET || g == CS_GRP_IRET)
      return 1;
  }
  return 0;
  /*
  switch(ins->id) {
  case X86_INS_RET:
  case X86_INS_IRET:
  case X86_INS_IRETD:
  case X86_INS_IRETQ:
  case X86_INS_RETF:
  case X86_INS_RETFQ:
    return 1;
  default:
    return 0;
  }*/
}


int
is_cs_unconditional_jmp_ins(cs_insn *ins)
{
  switch(ins->id) {
  case X86_INS_JMP:
  case X86_INS_LJMP:
    return 1;
  default:
    return 0;
  }
}


int
is_cs_conditional_cflow_ins(cs_insn *ins)
{
  /* XXX: it is crucial to use whitelisting here to guarantee correctness */
  switch(ins->id) {
  case X86_INS_JAE:
  case X86_INS_JA:
  case X86_INS_JBE:
  case X86_INS_JB:
  case X86_INS_JCXZ:
  case X86_INS_JECXZ:
  case X86_INS_JE:
  case X86_INS_JGE:
  case X86_INS_JG:
  case X86_INS_JLE:
  case X86_INS_JL:
  case X86_INS_JNE:
  case X86_INS_JNO:
  case X86_INS_JNP:
  case X86_INS_JNS:
  case X86_INS_JO:
  case X86_INS_JP:
  case X86_INS_JRCXZ:
  case X86_INS_JS:
    return 1;
  case X86_INS_JMP:
  default:
    return 0;
  }
}

int
safe_disasm_linear(pe_data_t *pe, std::vector<section_map_t> *smaps, std::set<uint64_t> *targets,
                   uint64_t addr, uint8_t *code, size_t len, std::set<uint64_t>& nonret_funcs_addr_set, std::set<uint64_t> &all_targets, std::set<uint64_t> &prefix_ins, const char **err)
{
  /*
   * Run conservative linear disassembly from the given address. 
   */

  int ret, jmp, init, cflow, call, nop, only_nop;
  csh dis;
  cs_mode mode;
  cs_insn *ins;
  section_map_t *sec;
  const uint8_t *pc;
  uint64_t t, pcaddr;
  size_t i, j, d, n, ndisassembled;
  btype_t *b;
  cs_x86_op *op;

  init = 0;
  ins  = NULL;

  if(pe->bits == 64) {
    mode = CS_MODE_64;
  } else {
    mode = CS_MODE_32;
  }
  if(cs_open(CS_ARCH_X86, mode, &dis) != CS_ERR_OK) {
    (*err) = "failed to initialize libcapstone";
    goto fail;
  }
  init = 1;
  cs_option(dis, CS_OPT_DETAIL, CS_OPT_ON);
  cs_option(dis, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

  ins = cs_malloc(dis);

  sec = section_map_by_addr(smaps, addr);
  if(!sec) {
    (*err) = "address points outside mapped sections (2)";
    goto fail;
  }
  sec->dismap.insert(addr);

  verbose(2, "disassembling %zu bytes at address 0x%jx (linear)", len, addr);
  pc = code;
  pcaddr = addr;
  n = len;
  d = 0;
  ndisassembled = 0;
  only_nop = 0;
  while(cs_disasm_iter(dis, &pc, &n, &pcaddr, ins)) {
    /* basic sanity checks on the disassembled instruction */
    if(!ins->address || !ins->size) {
      break;
    }

    d     = d + ins->size;
    nop   = is_cs_nop_ins(ins);
    ret   = is_cs_ret_ins(ins);

    jmp   = is_cs_unconditional_jmp_ins(ins);
    cflow = is_cs_cflow_ins(ins);
    call  = is_cs_call_ins(ins);
    t = 0;

    if (is_cs_terminate_ins(ins))
	    ud2_insts.insert(ins->address);

    ndisassembled++;

    if(only_nop && !nop) {
      /* we've reached the end of the padding after a function */
      break;
    }

    /* ins->address is definitely an instruction boundary */
    b = btype_by_addr(smaps, ins->address);
    if(!b) {
      print_warn("suspected code byte at 0x%jx is outside selected sections", ins->address);
      if(ndisassembled > 1) {
        /* we've fallen through an instruction into nothing... this shouldn't normally happen */
        break;
      } else {
        (*err) = "instruction address points outside selected sections (1)";
        goto fail;
      }
    }
    b->mark(MAP_FLAG_T, MAP_FLAG_T, b->bbstart, b->funcstart, ret ? MAP_FLAG_t : b->funcend, cflow ? MAP_FLAG_T : MAP_FLAG_F, call ? MAP_FLAG_T : MAP_FLAG_F, b->progentry, nop ? MAP_FLAG_T : MAP_FLAG_F);

    /* every other instruction byte is definitely code, and definitely
     * NOT any kind of boundary byte */
    for(i = (ins->address+1); i < (ins->address+ins->size); i++) {
      b = btype_by_addr(smaps, i);
      if(!b) {
        (*err) = "instruction address points outside selected sections (2)";
        goto fail;
      }
      verbose(3, "marking code byte at 0x%jx", i);
      b->mark(MAP_FLAG_T, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, nop ? MAP_FLAG_T : MAP_FLAG_F);
    }

    /* special treatment for control-flow instructions to guarantee that we
     * proceed or stop in a reliable way */
    cflow = 0;
    for(i = 0; i < ins->detail->groups_count; i++) {
      if(is_cs_cflow_group(ins->detail->groups[i])) {
        /* queue direct control-flow targets to be recursively disassembled */
        for(j = 0; j < ins->detail->x86.op_count; j++) {
          op = &ins->detail->x86.operands[j];
          if(op->type == X86_OP_IMM) {
            t = op->imm;
            sec = section_map_by_addr(smaps, t);
            if(sec && !sec->dismap.count(t)) {
              verbose(1, "queueing control flow target 0x%jx (0x%jx -> 0x%jx) for recursive disassembly", t, ins->address, t);
              targets->insert(t);
	      all_targets.insert(t);
            }
          }
        }
        if((ret && !ignore_padding) || (jmp && !ignore_padding)) {
          /* keep looking for padding (NOPs) after the ret or jmp */
          only_nop = 1;
          break;
        }
        if(is_cs_conditional_cflow_ins(ins) && !ignore_fallthrough) {
          /* we can safely assume fallthrough blocks for conditional jumps,
           * unless there may be opaque predicates (then -j should be passed) */
	  all_targets.insert(ins->address + ins->size);
	  break;
        }
	// non return handle
        if(is_cs_call_ins(ins) && guess_return && \
	    !check_nonreturn_func(nonret_funcs_addr_set, t)) {
          /* if guess_return is true, we assume calls return to the following 
           * instruction (XXX: may not be true for malicious code or leaf functions) */
          break;
        }
        cflow = 1;
        break;
      }
    }
    if(cflow) {
      break;
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(ins) {
    cs_free(ins, 1);
  }
  if(init) {
    cs_close(&dis);
  }
  return ret;
}


int
safe_disasm(pe_data_t *pe, std::vector<section_map_t> *smaps, uint64_t addr, std::set<uint64_t>& nonret_funcs_addr, std::set<uint64_t>&all_targets, std::set<uint64_t> &prefix_ins, char const **err)
{
  int ret;
  uint8_t code[CODE_CHUNK_SIZE];
  size_t len;
  std::set<uint64_t> targets;
  uint64_t t;

  targets.insert(addr);
  while(!targets.empty()) {
    t = (*targets.begin());
    targets.erase(t);

    len = CODE_CHUNK_SIZE;
    if(read_pe_section_by_addr(pe, smaps, t, code, &len, err) < 0) {
      goto fail;
    }

    if(safe_disasm_linear(pe, smaps, &targets, t, code, len, nonret_funcs_addr, all_targets, prefix_ins, err) < 0) {
      goto fail;
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  return ret;
}

int
safe_disasm_entry_point(pe_data_t *pe, std::vector<section_map_t> *smaps, std::set<uint64_t>& nonret_funcs_addr, std::set<uint64_t>& all_targets, std::set<uint64_t> &prefix_ins, char const **err)
{
  /*
   * Mark PE entry point and use it as a disassembly starting point.
   */

  int ret;
  btype *b;

  if(!pe->entry) {
    (*err) = "cannot find PE entry point";
    goto fail;
  }

  b = btype_by_addr(smaps, pe->entry);
  verbose(1, "marking PE entry point at 0x%jx", pe->entry);
  if(!b) {
    (*err) = "pe entry point is outside selected sections";
    goto fail;
  }

  b->mark(MAP_FLAG_T, MAP_FLAG_T, MAP_FLAG_T, MAP_FLAG_T, b->funcend, b->cflow, b->call, MAP_FLAG_T, b->nop);

  /* let's see how much of the binary we can conservatively reach from the entry point */
  if(safe_disasm(pe, smaps, pe->entry, nonret_funcs_addr, all_targets, prefix_ins, err) < 0) {
    goto fail;
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  return ret;
}

int
safe_disasm_symbols(pe_data_t *pe, std::vector<section_map_t> *smaps, std::vector<symbol_t> *syms, std::set<uint64_t>& nonret_funcs_addr, std::set<uint64_t>& all_targets, std::set<uint64_t>& prefix_ins, char const **err)
{
  /* 
   * Disassemble/mark functions and data pointed to by symbols, if available.
   */

  int ret; 
  size_t i, j;
  btype *b;
  symbol_t *sym;

  for(i = 0; i < syms->size(); i++) {
    sym = &syms->at(i);
    b = btype_by_addr(smaps, sym->value);
    if(!b && (sym->type == SYM_TYPE_FUNC)) {
      (*err) = "FUNC symbol points outside selected sections";
      goto fail;
    } else if(!b) {
      /* just ignore data symbols which point outside the PROGBITS sections */
      continue;
    }

    if(sym->type == SYM_TYPE_FUNC) {
      verbose(2, "marking function %s pointed to by FUNC symbol at 0x%jx", sym->name.c_str(), sym->value);
      b->mark(MAP_FLAG_T, MAP_FLAG_T, MAP_FLAG_T, MAP_FLAG_T, b->funcend, b->cflow, b->call, b->progentry, b->nop);

      if(safe_disasm(pe, smaps, sym->value, nonret_funcs_addr, all_targets, prefix_ins, err) < 0) {
        goto fail;
      }
    } else {
      verbose(2, "marking data object %s pointed to by symbol at 0x%jx (%ju bytes)", sym->name.c_str(), sym->value, sym->size);
      for(j = sym->value; j < (sym->value+sym->size); j++) {
        b = btype_by_addr(smaps, j);
        if(!b) {
          break;
        }
        b->mark(MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F);
      }
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  return ret;
}

int
init_section_maps(pe_data_t *pe, std::vector<section_map_t> *smaps, char const **err)
{
  /*
   * Initialize section maps with suspected code/data markers based on section
   * read/write/execute flags. The maps are later refined.
   */

  size_t i, j;
  map_flag_t code;

  for(i = 0; i < smaps->size(); i++) {
    smaps->at(i).map.push_back(
      map_range_t(smaps->at(i).addr, smaps->at(i).size)
    );
    for(j = 0; j < smaps->at(i).size; j++) {
      if(smaps->at(i).flags & SEC_FLAG_EXEC) {
        code = MAP_FLAG_t;
      } else {
        code = MAP_FLAG_F;
      }
      smaps->at(i).map[0].btypes.push_back(btype_t(code));
    }
  }
  return 0;
}

bool parse_section_headers(pe_data_t pe, std::vector<section_map_t> *smaps){
  // iter over sections.
  // store the script cmd
  char* pdb_fname = pe.pdb_fname;
  char tmp_str[1024];
  FILE *fsec_header = NULL;
  int sec_id = 0;
  uint64_t virtual_size = 0x0;
  uint64_t virtual_addr = 0x0;
  uint64_t file_offset = 0x0;
  uint64_t flags = 0x0;
  std::string sec_name;
  char* token = NULL;
  char* eptr = NULL;


  const char* tmp_output = "/tmp/RaNdoM_secHeaders.log";
  memset(tmp_str, 0, sizeof(tmp_str));

  strcat(tmp_str, "llvm-pdbutil dump -section-headers ");
  strcat(tmp_str, pdb_fname);
  strcat(tmp_str, " > ");
  strcat(tmp_str, tmp_output);

  if(system(tmp_str) == -1){
    print_err("execute llvm-pdbutil dump section headers error!\n");
    return false;
  }

  memset(tmp_str, 0, sizeof(tmp_str));
  fsec_header = fopen(tmp_output, "r");

  if (!fsec_header){
    print_err("open section header file error!\n");
    return false;
  }

  memset(tmp_str, 0, sizeof(tmp_str));
  while (fgets(tmp_str, sizeof(tmp_str), fsec_header) != NULL) {
    if (strstr(tmp_str, "SECTION HEADER")){
      token = strtok(tmp_str, "#");
      token = strtok(NULL, "#");
      sec_id = atoi(token);

      // get the section idx
      verbose(1, "DEBUG: we find section id is %d\n", sec_id);

      // get section name
      if (!fgets(tmp_str, sizeof(tmp_str), fsec_header)){
	print_err("can't get section name line!");
	return false;
      }
      token = strtok(tmp_str, " ");
      verbose(1, "DEBUG: section name is %s\n", token);
      sec_name = std::string(token);

      // get virtual size
      if (!fgets(tmp_str, sizeof(tmp_str), fsec_header)){
	print_err("can't get virtual size line!");
	return false;
      }
      token = strtok(tmp_str, " ");
      virtual_size = strtol(token, &eptr, 16);
      verbose(1, "DEBUG: section virtual size is 0x%x\n", virtual_size);

      // get virtual address
      if (!fgets(tmp_str, sizeof(tmp_str), fsec_header)){
	print_err("can't get virtual address line!");
	return false;
      }
      token = strtok(tmp_str, " ");
      virtual_addr = strtol(token, &eptr, 16);
      verbose(1, "DEBUG: section virtual addr is 0x%x\n", virtual_addr);

      // get file offset
      fgets(tmp_str, sizeof(tmp_str), fsec_header);
      if (!fgets(tmp_str, sizeof(tmp_str), fsec_header)){
	print_err("can't get file pointer line!");
	return false;
      }
      token = strtok(tmp_str, " ");
      file_offset = strtol(token, &eptr, 16);
      verbose(1, "DEBUG: section file offset is 0x%x\n", file_offset);

      // get flags
      while(fgets(tmp_str, sizeof(tmp_str), fsec_header) != NULL) {
	if (strstr(tmp_str, "flags")){
	  token = strtok(tmp_str, " ");
	  flags = strtol(token, &eptr, 16);
	  verbose(1, "get section flags 0x%x\n", flags);
	  break;
	}
      }

      if (flags & IMAGE_SCN_CNT_CODE || flags & IMAGE_SCN_CNT_INITIALIZED_DATA){
	smaps->push_back(section_map_t());
	smaps->back().name = sec_name;
	smaps->back().off = file_offset;
	smaps->back().size = virtual_size;
	smaps->back().addr = virtual_addr + pe.base_addr;
	smaps->back().idx = sec_id;
	if (flags & IMAGE_SCN_CNT_CODE){
	  smaps->back().flags = SEC_FLAG_READ | SEC_FLAG_EXEC;
	} else {
	  smaps->back().flags = SEC_FLAG_READ | SEC_FLAG_WRITE;
	}
      }
    }
  }
  fclose(fsec_header);

  /* Move .text section to the front of the vector for optimization
   * (it needs to be looked up most often) */
  for(int i = 1; i < smaps->size(); i++) {
    if(smaps->at(i).name == ".text") {
      verbose(2, "moving section %zu (.text) to front of list", i);
      iter_swap(smaps->begin(), smaps->begin()+i);
      break;
    }
  }
  return true;
}

void split_pathes(char *path, const char* delims, std::vector<std::string>& path_list){
  char* token;
  int index = 0;
  std::string cur_string;
  token = strtok(path, delims);
  while (token){
    cur_string = std::string(token);
    // to lower case
    std::transform(cur_string.begin(), cur_string.end(), cur_string.begin(), [](unsigned char c){ return std::tolower(c); });
    path_list.push_back(cur_string);
    token = strtok(NULL, delims);
  }
}

bool is_library_code(char* cu_file){
  char* token = strstr(cu_file, "f:\\binaries\\Intermediate\\vctools");
  if (token == cu_file)
    return true;
  token = strstr(cu_file, "f:\\dd\\vctools\\crt");
  if (token == cu_file)
    return true;
  return false;
}

bool parse_pe_debug_lines(pe_data_t& pe, std::vector<section_map_t> *smaps, std::vector<cu_t>& srcmaps, std::set<uint64_t>& nonret_funcs_addr, std::set<uint64_t>& all_targets, std::vector<data_in_code_reg_t>& data_in_code_regs, std::set<uint64_t> &prefix_ins, std::vector<jmptbl_t>& jtables, const char **err){
  btype_t* b;
  char* pdb_fname = pe.pdb_fname;
  bool start = false;
  char tmp_str[1024];
  FILE *fline_info = NULL;
  int cur_sec_id = 0;
  int cur_src_line = 0;
  std::set<uint64_t> addr_set; // store all the binary address to be disassembled
  uint64_t cur_sec_base_addr = -1;
  uint64_t cur_address = 0;
  uint64_t cur_line_num = 0;
  std::string cur_source;
  std::string cur_mod;
  std::string cur_line_str;
  char* token = NULL;
  char* eptr = NULL;
  bool in_data_region = false;
  data_in_code_reg_t* cur_data_in_code_reg = NULL;
  // if the file contains data in code regions
  uint32_t data_in_code_size = 0;
  data_in_code_size = data_in_code_regs.size();

  const char* tmp_output = "/tmp/RaNdoM_dEBugLines.log";
  memset(tmp_str, 0, sizeof(tmp_str));

  strcat(tmp_str, "llvm-pdbutil dump -l ");
  strcat(tmp_str, pdb_fname);
  strcat(tmp_str, " > ");
  strcat(tmp_str, tmp_output);

  if(system(tmp_str) == -1){
    print_err("execute llvm-pdbutil dump section headers error!\n");
    return false;
  }
  memset(tmp_str, 0, sizeof(tmp_str));
  fline_info = fopen(tmp_output, "r");

  while (fgets(tmp_str, sizeof(tmp_str), fline_info) != NULL) {
    // find a mod. example:
    // Mod 0018 | `f:\binaries\Intermediate\vctools\libcmt.nativeproj__851063217\objr\amd64\_initsect_.obj`:
    if (strstr(tmp_str, "Mod ") && strstr(tmp_str, "`")){
      start = true;
      token = strtok(tmp_str, "`");
      token = strtok(NULL, "`");
      if (token){
	verbose(1, "find a mod %s\n", token);
	cur_mod = std::string(token);
      }
    } else if (eptr = strstr(tmp_str, "(MD5: ")){ // find a input file
      *(eptr - sizeof(char))= 0x0;
      verbose(1, "find a input source file %s\n", tmp_str);
      cur_source = std::string(tmp_str);
      cur_data_in_code_reg = NULL;

      srcmaps.push_back(cu_t());

      if (is_library_code(tmp_str)){
	srcmaps.back().is_libs_code = true;
      } else{
	srcmaps.back().is_libs_code = false;
      }

      split_pathes(tmp_str, "\\", srcmaps.back().path_list);
      if (data_in_code_size > 0){
	for (auto cur_b_file_iter = data_in_code_regs.begin(); 
	    cur_b_file_iter < data_in_code_regs.end(); cur_b_file_iter++){
	  if (cur_b_file_iter->cu_file == srcmaps.back().path_list.back()){
	    cur_data_in_code_reg = &*cur_b_file_iter;
	    break;
	  }
	}
      }

    } else if (eptr = strstr(tmp_str, "unknown file name offset")){ // unkown source
      cur_source = std::string("unkown name");
    }else if (strstr(tmp_str, " line/addr entries = ") || 
      strstr(tmp_str, " line/column/addr entries = ")) { // get a section id
      token = strtok(tmp_str, ":");
      cur_sec_id = strtol(token, &eptr, 16);
      verbose(1, "find section id %s\n", tmp_str);

      // get section base addr
      cur_sec_base_addr = -1;
      for (int i = 0; i < smaps->size(); i++){
	if (smaps->at(i).idx == cur_sec_id){
	  cur_sec_base_addr = smaps->at(i).addr;
	}
      }

      if (cur_sec_base_addr == -1){
	print_err("[parse_pe_debug_lines]: can't find proper section base address for input source %s", cur_source.c_str());
	return false;
      }
    } else {
      if (!start)
	continue;
      cur_line_str = std::string(tmp_str);
      // check if the line is blank
      if (!check_string_blank(cur_line_str)){
	// get all line info
	token = strtok(tmp_str, "! ");
	while (token){
	  // current line number, sometimes, the token is 'NSI'
	  cur_line_num = strtol(token, &eptr, 10);

	  // current binary address
	  token = strtok(NULL, "! ");
	  if (!token){
	    break;
	  }

	  in_data_region = false;
	  if (cur_data_in_code_reg){
	    for (auto cur_region : cur_data_in_code_reg->regions){
	      if (cur_line_num >= cur_region.first && cur_line_num <= cur_region.second){
		in_data_region = true;
		break;
	      }
	    }
	  }

	  cur_address = strtol(token, &eptr, 16);
	  cur_address += cur_sec_base_addr;
	  // check if is in jump table region
	  if (!in_data_region){
	    for (auto jmptbl : jtables){
	      if (cur_address >= jmptbl.base_addr && cur_address < jmptbl.base_addr + jmptbl.size * jmptbl.entry_size){
		in_data_region = true;
		break;
	      }
	    }
	  }
	  
	  if (in_data_region){
	    verbose(1, "current line number %d is in data region!", cur_line_num);
	    token = strtok(NULL, "! ");
	    continue;
	  }

	  if (cur_line_num != 0){
	    srcmaps.back().line2addr[cur_line_num] = cur_address;
	    srcmaps.back().addr2line[cur_address] = cur_line_num;
	  }

	  verbose(1, "debug: line info %d: 0x%llx", cur_line_num, cur_address);
	  addr_set.insert(cur_address);

	  verbose(1, "marking instruction boundary (2) at 0x%jx (%s: %u)", cur_address, cur_source.c_str(), cur_line_num);

	  b = btype_by_addr(smaps, cur_address);
	  if(!b) {
	    print_warn("skipping dangling DWARF instruction mapping at 0x%jx (%s: %u)", cur_address, cur_source.c_str(), cur_line_num);
	    token = strtok(NULL, "! ");
	    continue;
	  }

	  b->mark(MAP_FLAG_T, MAP_FLAG_T, b->bbstart, b->funcstart, b->funcend, b->cflow, b->call, b->progentry, b->nop);

	  token = strtok(NULL, "! ");
	}
      } // end handle line info
    }
  } // end while
  fclose(fline_info);

  for(auto cur_addr: addr_set){
    // disassemble the code from cur_addr
    /* this is an instruction boundary, so it's a safe start for conservative disassembly */
  if(safe_disasm(&pe, smaps, cur_addr, nonret_funcs_addr, all_targets, prefix_ins, err) < 0) {
    print_err("safe disasm line info error!");
    return false;
  }
}
  return true;
}

bool parse_pe_info(pe_data_t& pe){
  char* pe_fname = pe.pe_fname;
  char tmp_str[1024];
  bool succeed = true;
  FILE* open_file = NULL;
  uint64_t base_addr = 0x0;
  uint64_t entry_addr = 0x0;
  uint32_t machine_type = 0x0; // 32 or 64 bits
  char* token;
  char *eptr;
  const char* tmp_output = "/tmp/RanDOM_parSePeInfo.log";

  memset(tmp_str, 0, sizeof(tmp_str));
  strcat(tmp_str, "llvm-readelf -h ");
  strcat(tmp_str, pe_fname);
  strcat(tmp_str, " | grep \"Machine\\|ImageBase\\|AddressOfEntryPoint\" > ");
  strcat(tmp_str, tmp_output);

  printf("execute string is %s\n", tmp_str);

  if (system(tmp_str) == -1){
    print_err("execute llvm-readelf -h error!\n");
    return false;
  }

  open_file = fopen(tmp_output, "r");
  while(fgets(tmp_str, sizeof(tmp_str), open_file)){
    // get machine type
    if (strstr(tmp_str, "Machine")){
      if(strstr(tmp_str, "AMD64")){
	machine_type = 64;
	pe.bits = 64;
	verbose(1, "The machine type is AMD64\n");
      } else if (strstr(tmp_str, "I386")){
	machine_type = 32;
	pe.bits = 32;
	verbose(1, "The machine type is i386\n");
      } else {
	print_err("Can't handle the machine type\n");
	succeed = false;
      }
    } else if (strstr(tmp_str, "ImageBase")) { // handle imagebase
      token = strtok(tmp_str, ":");
      token = strtok(NULL, ":");
      base_addr = strtol(token, &eptr, 16);
      verbose(1, "base address is 0x%llx\n", base_addr);
    } else if (strstr(tmp_str, "AddressOfEntryPoint")){
      token = strtok(tmp_str, ":");
      token = strtok(NULL, ":");
      entry_addr = strtol(token, &eptr, 16);
      verbose(1, "entry address is 0x%x\n", entry_addr);
    }
  }

  pe.base_addr = base_addr;
  pe.entry = base_addr + entry_addr;
  fclose(open_file);
  return succeed;

}

char*
parse_llvminfo_preamble(char *line, unsigned minlen, std::string &modulepath, char const **err)
{
  char *tok;

  line = strchr(line, ' ');
  if(!line || (strlen(line) < minlen)) {
    (*err) = "bad line in llvm info file (parse_llvminfo_preamble, 1)";
    return NULL;
  }
  line++;

  tok = strchr(line, '\n');
  if(tok) (*tok) = '\0';

  tok = strchr(line, '\t');
  if(!tok) {
    (*err) = "bad line in llvm info file (parse_llvminfo_preamble, 2)";
    return NULL;
  }
  modulepath = std::string(line, tok-line);
  assert(!modulepath.empty());

  return line;
}

int get_nonret_funcs_addr(std::vector<symbol_t>& syms, std::set<std::string>& non_ret_funcs, std::set<uint64_t>& non_ret_funcs_addr, char const** err){

  std::set<std::string>::iterator cur_iter;
  for (auto cur_sym : syms){
    cur_iter = non_ret_funcs.find(cur_sym.name);

    if (cur_iter != non_ret_funcs.end()){
      verbose(1, "current non-return function is %s, address is 0x%lx", cur_sym.name.c_str(), cur_sym.value);
      non_ret_funcs_addr.insert(cur_sym.value);
    }
  }
  return 1;
}

int parse_llvminfo_nonreturn(char* line, std::set<std::string>& non_ret_funcs, char const** err){
  std::string func_name;
  char *tok;
  char *demangled_;

  line = strchr(line, ' ');

  if (!line){
    (*err) = "bad line in llvm info file(parse_llvminfo_nonreturn)";
    return -1;
  }

  line++;

  tok = strchr(line, '\n');

  if (tok){
    (*tok) = '\0';
  }

  demangled_ = cplus_demangle(line, DMGL_NO_OPTS);

  if (!demangled_)
    demangled_ = line;

  func_name = std::string(demangled_);
  non_ret_funcs.insert(func_name);

  verbose(1, "current non-return function is %s", func_name.c_str());
  return 1;
}

int
parse_llvminfo_switch(char *line, std::vector<switch_t> *switches, char const **err)
{
  int ret;
  char *tok;
  unsigned startline, defaultline, caseline;
  std::string modulepath;
  switch_t *s;
  char tmp_str[1024];

  if(!(line = parse_llvminfo_preamble(line, 8, modulepath, err))) {
    goto fail;
  }

  tok = strchr(line, '\t');

  startline = strtoul(tok+1, NULL, 0);
  tok = strchr(tok+1, '\t');
  if(!tok) {
    (*err) = "bad line in llvm info file (parse_llvminfo_switch, 1)";
    goto fail;
  }

  defaultline = strtoul(tok+1, NULL, 0);
  tok = strchr(tok+1, '\t');
  if(!tok) {
    (*err) = "bad line in llvm info file (parse_llvminfo_switch, 2)";
    goto fail;
  }

  switches->push_back(switch_t());
  s = &switches->back();
  strcpy(tmp_str, modulepath.c_str());
  split_pathes(tmp_str, "/\\", s->cu_path_list);
  s->cu_path = modulepath;
  s->start_line = startline;
  s->default_line = defaultline;
  while(tok) {
    if((*(tok+1) >= '0') && (*(tok+1) <= '9')) {
      caseline = strtoul(tok+1, NULL, 0);
      s->case_lines.push_back(caseline);
    }
    tok = strchr(tok+1, ' ');
  }
  verbose(1, "llvminfo_switch: parsed line mod='%s' start='%u' default='%u'", 
          s->cu_path.c_str(), s->start_line, s->default_line);

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  return ret;
}

int
parse_llvminfo(char *llvminfo_fname, std::vector<function_t> *funcs, 
               std::vector<switch_t> *switches, std::set<std::string>& non_ret_funcs, char const **err)
{
  int ret;
  FILE *f;
  char *linebuf, *tok;
  size_t buflen;

  f        = NULL;
  linebuf  = NULL;

  verbose(2, "parsing llvm info file '%s'", llvminfo_fname);
  f = fopen(llvminfo_fname, "r");
  if(!f) {
    (*err) = "failed to open llvm info file";
    goto fail;
  }

  buflen = 4096;
  linebuf = (char*)malloc(buflen);
  if(!linebuf) {
    (*err) = "out of memory";
    goto fail;
  }

  while(getline(&linebuf, &buflen, f) > 0) {
    if(strlen(linebuf) < 3) continue;
    if(linebuf[0] == '#') continue;
    tok = strchr(linebuf, '\n');
    if(tok) (*tok) = '\0';
    verbose(4, "parsing llvm info line '%s'", linebuf);

    if(!strncmp(linebuf, "SW", 2)){
      if (parse_llvminfo_switch(linebuf, switches, err) < 0) goto fail;
    }   

    if (!strncmp(linebuf, "NR", 2)){
      verbose(1, "current line buf is %s", linebuf);
      if (parse_llvminfo_nonreturn(linebuf, non_ret_funcs, err) < 0) {
	goto fail;
      }
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(f) {
    fclose(f);
  }
  if(linebuf) {
    free(linebuf);
  }

  return ret;
}


void
dump_btype(btype_t *b)
{
  if(!(b->code & 0x01)) {
    /* XXX: 'd'-16*(b->code & 0x02) == 'D' if the certain bit is set, 'd' otherwise */
    printf("%c", 'd'-16*(b->code & 0x02));
  } else {
    if(   !(b->insbound  & 0x01) && !(b->overlapping & 0x01)
       && !(b->bbstart   & 0x01) && !(b->funcstart   & 0x01) 
       && !(b->funcend   & 0x01) && !(b->cflow       & 0x01)
       && !(b->call      & 0x01) && !(b->progentry   & 0x01) && !(b->nop & 0x01)) {
      printf("%c", 'c'-16*(b->code & 0x02));
    } else {
      printf("[");
      printf("%c", 'c'-16*(b->code & 0x02));
      if(b->insbound    & 0x01) printf("%c", 'i'-16*(b->insbound    & 0x02));
      if(b->overlapping & 0x01) printf("%c", 'o'-16*(b->overlapping & 0x02));
      if(b->bbstart     & 0x01) printf("%c", 'b'-16*(b->bbstart     & 0x02));
      if(b->funcstart   & 0x01) printf("%c", 'f'-16*(b->funcstart   & 0x02));
      if(b->funcend     & 0x01) printf("%c", 'r'-16*(b->funcend     & 0x02));
      if(b->cflow       & 0x01) printf("%c", 'j'-16*(b->cflow       & 0x02));
      if(b->call        & 0x01) printf("%c", 'x'-16*(b->call        & 0x02));
      if(b->progentry   & 0x01) printf("%c", 'e'-16*(b->progentry   & 0x02));
      if(b->nop         & 0x01) printf("%c", 'n'-16*(b->nop         & 0x02));
      printf("]");
    }
  }
}

void disassemble_according_jtables(pe_data_t& pe, std::vector<section_map_t>* smaps, std::set<uint64_t>& nonret_funcs_addr, std::set<uint64_t>& all_targets, std::set<uint64_t> &prefix_ins, std::vector<jmptbl_t>& jtables, const char** err){
  btype_t* b;
  for (auto cur_jtable : jtables){
    for(auto cur_case : cur_jtable.cases_addr){
      b = btype_by_addr(smaps, cur_case);
      if (!b){
	print_warn("skiping disassembling indirect jump targets 0x%x", cur_case);
	continue;
      }

      b->mark(MAP_FLAG_T, MAP_FLAG_T, MAP_FLAG_T, b->funcstart, b->funcend, b->cflow, b->call, b->progentry, b->nop);

      safe_disasm(&pe, smaps, cur_case, nonret_funcs_addr, all_targets, prefix_ins, err);
    }
  }
}

/*
 * we roughly pair jump table with indirect jump.
 * This *may* not accurate.
 * We just store all the jump table targets to a indirect jump target
 */
void roughly_pair_jtable(std::vector<jmptbl_t>& jtables, std::map<uint64_t, blocks::BasicBlock*>& indirect_jumps){

  verbose(1, "indirect jump number is %d, jump table number is %d", indirect_jumps.size(), jtables.size());
  uint64_t cur_switch_addr;
  uint64_t min_diff;
  uint64_t cur_indirect_addr;
  blocks::BasicBlock* min_bb;
  blocks::Child* bb_child;
  for (auto cur_jtable : jtables){

    cur_switch_addr = cur_jtable.base_addr_fixup;
    min_diff = -1;
    min_bb = NULL;

    for (auto cur_indir_jmp : indirect_jumps){
      if (cur_indir_jmp.first - cur_switch_addr < min_diff){
	min_diff = cur_indir_jmp.first - cur_switch_addr;
	min_bb = cur_indir_jmp.second;
	cur_indirect_addr = cur_indir_jmp.first;
      }
    }

    verbose(1, "[pair jtable]: 0x%lx -> 0x%lx", cur_switch_addr, cur_indirect_addr);
    assert(min_bb);

    // add successors!
    for (auto case_addr : cur_jtable.cases_addr){
      bb_child  = min_bb->add_child(); 
      bb_child->set_va(case_addr);
    }
    min_bb->set_type(BlockType::DUMMY_JMP_TABLE);
    indirect_jumps.erase(cur_indirect_addr);
  }
}

bool
construct_cfg(pe_data_t* pe, std::vector<section_map_t> *smaps, blocks::module& module, std::map<uint64_t, blocks::BasicBlock*>& indirect_jumps, std::set<uint64_t>& nonret_funcs_addr, std::set<uint64_t>& all_targets, std::set<uint64_t>& prefix_ins, std::vector<function_t>& funcs_list)
{
  size_t i, j, k, n, c;

  blocks::Function* cur_func;
  blocks::BasicBlock* cur_bb;
  blocks::Instruction* cur_inst;
  blocks::Child* bb_child;
  btype_t *cur_byte;
  bool last_ins_prefix = false; // if last instruction contains prefix
  size_t dis_len = 64;
  uint8_t code[64]; // store one instruction
  uint64_t cur_addr;
  uint32_t cur_bb_size = 0;
  uint32_t cur_inst_size = 0;
  uint32_t cur_padding_size = 0;
  std::map<uint64_t, function_t*> all_funcs_map;
  
  bool tmp_bool = 0;
  function_t *cur_func_t;

  std::vector<function_t>::iterator func_iter;
  std::map<uint64_t, function_t*>::iterator map_func_iter;

  bool nop_byte = false;
  char const **err;
  size_t len = 64;

  const uint8_t *pc;
  uint64_t pcaddr;

  uint64_t target = 0x0;
  uint32_t type = 0;

  cs_mode mode;
  cs_insn *ins;
  cs_x86_op *op;
  csh dis;

  if (pe->bits == 64){
    mode = CS_MODE_64;
  } else {
    mode = CS_MODE_32;
  }

  if (cs_open(CS_ARCH_X86, mode, &dis) != CS_ERR_OK) {
    print_err("failed to initialize libcapstone");
    return false;
  }

  cs_option(dis, CS_OPT_DETAIL, CS_OPT_ON);
  cs_option(dis, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
  
  ins = cs_malloc(dis);


  for (func_iter = funcs_list.begin(); func_iter != funcs_list.end(); func_iter++){
    all_funcs_map.insert(std::make_pair(func_iter->ranges[0].first, &*func_iter));
  }


  for(i = 0; i < smaps->size(); i++) {
    if(!smaps->at(i).size) {
      printf("\n");
      continue;
    }

    // reset
    cur_func = NULL;
    cur_bb = NULL;
    cur_inst = NULL;

    cur_bb_size = 0;
    cur_inst_size = 0;
    cur_padding_size = 0;
    target = 0x0;
    type = 0;

    n = 0;
    c = 0;
    
    // iter every section
    for(j = 0; j < smaps->at(i).map.size(); j++) {
      for(k = 0; k < smaps->at(i).map[j].btypes.size(); k++) {
	cur_addr = smaps->at(i).map[j].addr + k;
        //dump_btype(&smaps->at(i).map[j].btypes[k]);
        n++;
        if(smaps->at(i).map[j].btypes[k].code & 0x02) {
          c++;
        }

	cur_byte = &smaps->at(i).map[j].btypes[k];
	if (!((cur_byte->code & 0x01) && (cur_byte->code & 0x2))){
	  continue;
	}

	if (cur_byte->nop & 0x1 && cur_byte->nop & 0x02){
	  nop_byte = true;
	} else {
	  nop_byte = false;
	}

	// current address is function start
	if (cur_byte->funcstart & 0x1 && cur_byte->funcstart & 0x2){
	  cur_func = module.add_fuc();
	  cur_func->set_va(cur_addr); 

	  map_func_iter = all_funcs_map.find(cur_addr);

	  // can't find proper function.
	  if (map_func_iter == all_funcs_map.end()){
	    cur_func_t = NULL;
	  } else {
	    cur_func_t = (map_func_iter->second);
	  }

	  verbose(1, "Function: 0x%lx", cur_addr);
	}

	// current address is basic block start
	if ((cur_byte->bbstart & 0x1 && cur_byte->bbstart & 0x2) || all_targets.find(cur_addr) != all_targets.end()) {

	  if (!cur_func){
	    cur_func = module.add_fuc();
	    cur_func->set_va(0x0);
	    cur_func->set_type(1); // dummy function
	  }

	  if (cur_bb){
	    verbose(1, "previous bb size %d, padding size %d", cur_bb_size, cur_padding_size);
	    cur_bb->set_size(cur_bb_size);
	    cur_bb->set_padding(cur_padding_size);

	    // fall through edge
	    if (type == BlockType::COND_BRANCH || type == BlockType::DIRECT_CALL || 
		type == BlockType::FALL_THROUGH || type == BlockType::INDIRECT_CALL){
	      bb_child = cur_bb->add_child();
	      bb_child->set_va(cur_addr);
	      verbose(1, "add fallthrough edge 0x%lx -> 0x%lx", cur_bb->va(), cur_addr);
	    }
	    // direct jump edge
	    if (type == BlockType::COND_BRANCH || type == BlockType::DIRECT_CALL ||
		type == BlockType::NON_RETURN_CALL || type == BlockType::DIRECT_BRANCH){
	      bb_child = cur_bb->add_child();
	      bb_child->set_va(target);
	    }

	    // check if the type is tail call
	    tmp_bool = false;
	    if (type == BlockType::COND_BRANCH || type == BlockType::DIRECT_BRANCH){
	      if (all_funcs_map.find(target) != all_funcs_map.end()){
		tmp_bool = true;
		// jump to func type
		if (cur_func_t && cur_func_t->ranges[0].first < target && \
		    target < cur_func_t->ranges[0].second + cur_func_t->ranges[0].first){
		  cur_bb->set_type(BlockType::JUMP_TOFUNC);
		} else { // tail call
		  cur_bb->set_type(BlockType::TAIL_CALL);
		}
	      }
	    }

	    // check if the basic block call fall through the function type
	    if (tmp_bool && (type == BlockType::COND_BRANCH || type == BlockType::FALL_THROUGH)){
	      cur_bb->set_type(BlockType::FALLTHROUGH_TOFUNC);
	    }
	  }

	  verbose(1, "Basic Block: 0x%lx", cur_addr);
	  cur_padding_size = 0;
	  cur_bb_size = 0;
	  cur_bb = cur_func->add_bb();
	  cur_bb->set_parent(cur_func->va());
	  cur_bb->set_va(cur_addr);
	}

	// handle instruction(don't consider nop instruction)
	if ((cur_byte->insbound & 0x1) && (cur_byte->insbound & 0x2) && (!nop_byte)) {
	  if (!cur_func){
	    cur_func = module.add_fuc();
	    cur_func->set_va(0x0);
	    cur_func->set_type(1); // dummy function
	  }

	  if (!cur_bb){
	    cur_bb = cur_func->add_bb();
	    cur_bb->set_parent(cur_func->va());
	    cur_bb->set_va(cur_addr);
	  }

	  if (cur_inst){
	    cur_inst->set_size(cur_inst_size);
	  }

	  // default is fall through edge
	  type = BlockType::FALL_THROUGH;
	  verbose(1, "current instruction is 0x%llx", cur_addr);
	  cur_inst_size = 0;
	  if (ud2_insts.find(cur_addr) != ud2_insts.end()){
		  cur_bb->set_terminate(1);
		  verbose(1, "set termiante type of basic block 0x%llx\n", cur_bb->va());
	  }

	  cur_inst = cur_bb->add_instructions();
	  cur_inst->set_va(cur_addr);
	  if ((cur_byte->call & 0x2) && (cur_byte->call & 0x1)){
	    cur_inst->set_call_type(1); // call instruction. need to confirm if this is indirect call
	  }

	// control flow instruction
	if ((cur_byte->cflow & 0x1) && (cur_byte->cflow & 0x2)){
	  if (read_pe_section_by_addr(pe, smaps, cur_addr, code, &len, err) < 0){
	    continue;
	  }

	  pcaddr = cur_addr;
	  pc = code;
	  dis_len = 64;
	  // parse the instruction
	  if (cs_disasm_iter(dis, &pc, &dis_len, &pcaddr, ins)){
	    if (!ins->address || !ins->size){
	      continue;
	    }

	    if (parse_terminator(ins, target, type, dis, nonret_funcs_addr)){
	      if (type == BlockType::INDIRECT_BRANCH){
		indirect_jumps.insert(std::make_pair(cur_addr, cur_bb));
	      }
	    }
	  } // end if(cs_disasm_iter)
	} // end if(b->cflow)

	      cur_bb->set_type(type);
	}

	// count padding
	if (nop_byte){
	  cur_padding_size++;
	  verbose(1, "current padding address is 0x%llx", cur_addr);
	} else {
	  cur_inst_size++;
	  cur_bb_size++;
	}
      }

      printf("\n");
    }
    // handle last instruction
    if (cur_inst){
      cur_inst_size++;
      cur_inst->set_size(cur_inst_size);
    }

    if (cur_bb){
      cur_bb_size++;
      cur_bb->set_size(cur_bb_size);
      cur_bb->set_padding(cur_padding_size);
      verbose(1, "previous bb size %d, padding size %d", cur_bb_size, cur_padding_size);
    }

    printf("# %zu/%zu certain (%.2f%%)\n\n", c, n, ((double)c/n*100.0));
  }
 
  return true;
}

void
dump_section_maps(std::vector<section_map_t> *smaps)
{
  size_t i, j, k, n, c;

  for(i = 0; i < smaps->size(); i++) {
    if (!(smaps->at(i).flags & SEC_FLAG_EXEC)){
      continue;
    }
    printf("*************** map for section %s ***************\n", smaps->at(i).name.c_str());
    printf("<section %s, addr 0x%016jx, size %ju>\n", 
           smaps->at(i).name.c_str(), smaps->at(i).addr, smaps->at(i).size);
    if(!smaps->at(i).size) {
      printf("\n");
      continue;
    }
    n = 0;
    c = 0;
    for(j = 0; j < smaps->at(i).map.size(); j++) {
      printf("@0x%016jx: ", smaps->at(i).map[j].addr);
      for(k = 0; k < smaps->at(i).map[j].btypes.size(); k++) {
        if(k > 0 && ((((smaps->at(i).map[j].btypes[k].insbound & 0x01) || (smaps->at(i).map[j].btypes[k].overlapping & 0x01)) && map_show_insbounds) 
                     || (!(k % 16) && map_limit_16_bytes))) {
          printf("\n@0x%016jx: ", smaps->at(i).map[j].addr+k);
        }
        dump_btype(&smaps->at(i).map[j].btypes[k]);
        n++;
        if(smaps->at(i).map[j].btypes[k].code & 0x02) {
          c++;
        }
      }
      printf("\n");
    }
    printf("# %zu/%zu certain (%.2f%%)\n\n", c, n, ((double)c/n*100.0));
  }
}


void
dump_functions(std::vector<function_t> *funcs)
{
  size_t i, j;
  function_t *f;

  for(i = 0; i < funcs->size(); i++) {
    f = &funcs->at(i);
    if(!DUMP_PARTIAL_FUNCS && !f->valid_sig) continue;
    printf("F ");
    for(j = 0; j < f->ranges.size(); j++) {
      printf("0x%016jx %-6zu ", f->ranges[j].first, f->ranges[j].second);
    }
    printf("%-40s ", f->mangled_name.c_str());
    if(f->valid_sig) {
      printf("(..) [%s] %s%s(" , f->callconv.c_str(), f->inlined ? "inline " : "", f->ret.c_str());
      for(j = 0; j < f->params.size(); j++) {
        printf("%s%s", f->params[j].c_str(), ((j+1) < f->params.size()) ? ", " : "");
      }
      printf(") ");
      for(j = 0; j < f->attributes.size(); j++) {
        printf("%s ", f->attributes[j].c_str());
      }
    }
    printf("\n");
  }
  printf("\n");
}

/*
 * check if path1 partly equal path2
 */
bool path_equals(std::vector<std::string>& path1, std::vector<std::string>& path2, int number = 1){
  uint32_t size1 = path1.size();
  uint32_t size2 = path2.size();
  assert(size1 > 0);
  assert(size2 > 0);

  uint32_t cur_idx1 = size1 - 1;
  uint32_t cur_idx2 = size2 - 1;

  if (size1 < number)
    number = size1;
  if (size2 < number)
    number = size2;
  while(number > 0){
    if (path1.at(cur_idx1) != path2.at(cur_idx2)){
      return false;
    }
    cur_idx1--;
    cur_idx2--;
    number--;
  }
  return true;
}

// if can't find the proper line, return -1
uint64_t get_addr_by_line(std::map<unsigned, uint64_t>& line2addr, unsigned line){
  std::map<unsigned, uint64_t>::iterator cur_iter = line2addr.find(line);
  if (cur_iter != line2addr.end())
    return cur_iter->second;
  return -1;
}

uint64_t try_get_line(std::map<unsigned, uint64_t>& line2addr, unsigned line, int threshod){
  uint64_t result = -1;
  int cur_idx = 0;
  while(result == -1 && cur_idx < threshod){
    result = get_addr_by_line(line2addr, line + cur_idx);
    cur_idx++;
  }
  return result;
}

/*
void
switch_line2addr(std::vector<switch_t> *switches, std::vector<cu_t> *cus)
{
  size_t i, j, k;
  switch_t *s;
  cu_t *cu;
  uint64_t tmp_addr;
  bool error = false;

  for(i = 0; i < switches->size(); i++) {
    s = &switches->at(i);
    for(j = 0; j < cus->size(); j++) {
      cu = &cus->at(j);
      if (cu->is_libs_code) continue;
      if(!path_equals(cu->path_list, s->cu_path_list)) continue;

      tmp_addr = try_get_line(cu->line2addr, s->start_line, 10);

      if (tmp_addr == -1){
	print_err("Can't find proper line2addr for switch. src %s:%d", s->cu_path.c_str(), s->start_line);
	error = true;
	break;
      }

      s->start_addr = tmp_addr;

      tmp_addr = try_get_line(cu->line2addr, s->default_line, 10);


      if (tmp_addr == -1){
	verbose(1, "Can't find proper line2addr for switch. src %s:%d", s->cu_path.c_str(), s->default_line);
	error = true;
	break;
      }

      s->default_addr = tmp_addr;

      error = false;
      for(k = 0; k < s->case_lines.size(); k++) {
	tmp_addr = try_get_line(cu->line2addr, s->case_lines[k], 10);
	if (tmp_addr == -1){
	  verbose(1, "Can't find proper line2addr for switch. src %s:%d", s->cu_path.c_str(), s->case_lines[k]);
	  error = true;
	  break;
	}
        s->case_addrs.push_back(tmp_addr);
      }
      break;
    }

    if(j < cus->size() && !error) {
      s->parse_succeed = true;
    } else {
      s->parse_succeed = false;
    }
  }
}
*/

bool
sort_funcs_by_name(function_t f, function_t g)
{
  if(f.base && !g.base) return true;
  else if(!f.base && g.base) return false;
  else if(!f.line2addr.empty() &&  g.line2addr.empty()) return true;
  else if( f.line2addr.empty() && !g.line2addr.empty()) return false;
  else return (f.name < g.name);
}


void
print_usage(char *prog)
{
  printf(PEMAP_VERSION"\n");
  printf(PEMAP_CREDITS"\n");
  printf("\n%s [-vwhjRpsSOixdEBFlfg] -e <pe>\n", prog);
  printf("  -e : target PE binary (must be x86 or x86-64)\n");
  printf("  -F : list functions (and if applicable, their switches and AT blocks) after the code map\n");
  printf("  -E : assume functions are entered at their lowest address\n");
  printf("       (ignored if better entry point data is available from DWARF)\n");
  printf("  -j : don't follow fallthrough for conditional jumps; this option is\n");
  printf("       needed if there may be opaque predicates\n");
  printf("       (fallthroughs for unconditional jumps are never taken)\n");
  printf("  -R : assume return to the instruction following a call\n");
  printf("  -p : don't try to mark function/basic block padding bytes\n");
  printf("  -s : don't try to parse function signatures from DWARF info\n");
  printf("  -S : scan symbols only, ignoring DWARF\n");
  printf("  -O : allow overlapping instructions\n");
  printf("  -i : insert linebreak in map at each instruction boundary\n");
  printf("  -x : insert linebreak in map after every 16 bytes\n");
  printf("  -d <style>\n");
  printf("     : function name demangling style (as defined in demangle.h)\n");
  printf("  -f <file>\n");
  printf("     : dump auxiliary output files (function mapping, overlaps, ...)\n");
  printf("  -g <file>\n");
  printf("     : dump graphs of the results\n");
  printf("  -v : verbose\n");
  printf("  -w : disable warnings\n");
  printf("  -r <fixup protobuf> : fixup protobuf path\n");
  printf("  -P <pdb debug file> : pdb debug file path\n");
  printf("  -b <black list> : data in code range in assembly file\n");
  printf("  -h : help\n");
  printf("The following is a good default config:\n");
  printf("  ./PEMap -iwRFE -P <pdb info> -r <fixup> -e <pe> -o <saved result>\n");
  printf("\n");
}

bool parse_pe_symbols(pe_data_t& pe, std::vector<section_map_t> *smaps, std::vector<symbol_t> *syms, std::set<uint64_t>& non_rets){

  char* pdb_fname = pe.pdb_fname;
  char tmp_str[1024];
  char* delim = ":,=";
  int nread;
  unsigned len = 0;
  char* line = NULL;
  int cur_idx = 0;
  int index = 0;
  int offset = 0;
  int code_size = 0;
  std::string func_name;
  char* token;

  memset(tmp_str, 0, sizeof(tmp_str));
  strcat(tmp_str, "llvm-pdbutil dump -symbols ");
  strcat(tmp_str, pdb_fname);
  strcat(tmp_str, " | grep 'S_[L|G]PROC' -A2 > /tmp/RaNdOM_sYms.log");

  if (system(tmp_str) != -1){

      FILE* filted_funcs = fopen("/tmp/RaNdOM_sYms.log", "r");

      if (!filted_funcs){
        printf("open filted funcs file error!\n");
        return false;
      }
      
      memset(tmp_str, 0, sizeof(tmp_str));
      while (fgets(tmp_str, sizeof(tmp_str), filted_funcs) != NULL) {

	if (strstr(tmp_str, "S_LPROC") || strstr(tmp_str, "S_GPROC")){

	  // parsing function symbol: like
	  // S_GPROC32 [size = 64] `BZ2_hbMakeCodeLengths`
	  token = strstr(tmp_str, "`");
	  if (token){
	    token += sizeof(char);
	    char* end_ptr = token + (strlen(token) -2) * sizeof(char);
	    *(end_ptr) = 0;
	    verbose(1, "current function name is %s\n", token);
	    func_name = std::string(token);
	  }
	
	if(!fgets(tmp_str, sizeof(tmp_str), filted_funcs)){
	  printf("parsing error! can't get next line of function %s symbol\n", func_name.c_str());
	  return false;
	}

	// parsing next line, like
	// parent = 0, end = 1568, addr = 0001:38420, code size = 962
	token = strtok(tmp_str, delim);
	index = 0;
	cur_idx = 0;
        while (token){
	  switch (cur_idx){
	      case 5:
		index = atoi(token);
		break;
	      case 6:
		offset = atoi(token);
		break;
	      case 8:
		code_size = atoi(token);
		break;
	    }
	    cur_idx++;

	    token = strtok(NULL, delim);
	  }

	  verbose(1, "debug: current index is %d, offset is %d, code size is %d\n", index, offset, code_size);

	uint64_t sec_base = -1;
	for (int i = 0; i < smaps->size(); i++){
	  if (smaps->at(i).idx == index){
	    sec_base = smaps->at(i).addr;
	    break;
	  }
	}

	// can't find its parent section
	if (sec_base == -1){
	  print_err("can't find the symbol(offset 0x%x) parent(idx:%d) base address", offset, index);
	  return false;
	}
	// TODO. get function name
	strcpy(tmp_str, func_name.c_str());
	syms->push_back(symbol_t(SYM_TYPE_FUNC, tmp_str, offset + sec_base, code_size));

	if(!fgets(tmp_str, sizeof(tmp_str), filted_funcs)){
	  printf("parsing error! can't get function flags %s\n", func_name.c_str());
	  return false;
	}

	if (strstr(tmp_str, "noreturn")){
	  non_rets.insert(offset + sec_base);
	  verbose(1, "add noreturn function at 0x%lx", (offset + sec_base));
	}
      }
    }
      fclose(filted_funcs);
    } else {
      printf("fileter function error!\n");
      return false;
    }
  return true;
}

/*
 * Use heuristic methods to filter jump tables.
 * May not exactly *accurate*. Need to confirm by hand!
 * */
void filter_jtable(std::vector<function_t>& funcs, std::vector<jmptbl_t>& jtables, std::set<fixup_t>& fixups, std::set<uint64_t>& all_targets){
  uint64_t cur_addr;
  uint32_t size;
  std::set<fixup_t>::iterator cur_iter;
  std::set<fixup_t>::iterator prev_iter;
  std::set<fixup_t> filted_fixups;
  std::map<uint64_t, uint64_t> targets_set;
  std::map<uint64_t, uint64_t>::iterator targets_iter;
  std::vector<jmptbl_t>::iterator jmptbl_iter;
  uint32_t cnt = 0;
  uint32_t tmp_cnt = 0;
  bool data_sec = false;
  uint32_t fixup_size = 0;

  // heuristic 1: all jump table entries must point to same function
  for (cur_iter = fixups.begin(); cur_iter != fixups.end(); cur_iter++){
    targets_set[cur_iter->target] = cur_iter->va;

    if (!cur_iter->to_code)
      continue;

    /*
    if (cur_iter->va % 4 != 0)
      continue;
      */

    for (auto cur_func: funcs){
      cur_addr = cur_func.ranges[0].first;
      size = cur_func.ranges[0].second;

      if (cur_iter->target > cur_addr && cur_iter->target < cur_addr + size){
	cur_iter->parent = cur_addr;
	filted_fixups.insert(*cur_iter);
	break;
      }
    }
  }

  if (filted_fixups.size() == 0)
    return;

  jtables.push_back(jmptbl_t());
  prev_iter = filted_fixups.begin();
  cur_iter = filted_fixups.begin();
  fixup_size = cur_iter->size;
  cur_iter++;

  jtables.back().cases_addr.insert(prev_iter->target);
  jtables.back().fixups_addr.push_back(prev_iter->va);

  // heuristic 2: all jump table entries must be continuous and their size are same
  while(cur_iter != filted_fixups.end()){
    if (cur_iter->va != prev_iter->va + prev_iter->size ||
	cur_iter->size != cur_iter->size || cur_iter->parent != prev_iter->parent || 
	targets_set.find(cur_iter->va) != targets_set.end() /*split multiple jump tables*/){
      jtables.push_back(jmptbl_t());
    }
    jtables.back().cases_addr.insert(cur_iter->target);
    jtables.back().fixups_addr.push_back(cur_iter->va);
    prev_iter = cur_iter;
    cur_iter++;
  }

  jmptbl_iter = jtables.begin();
  while (jmptbl_iter != jtables.end()){
    // heuristic 3: at least 2 entries
    if (jmptbl_iter->fixups_addr.size() < 2){
      jmptbl_iter = jtables.erase(jmptbl_iter);
      
    // heuristic 4: must have reference points to the base address.
    // FIXME. We assume that base address is at begin or at end of jump table
    } else {
      targets_iter = targets_set.find(jmptbl_iter->fixups_addr.front());
      if (targets_iter == targets_set.end()){
	targets_iter = targets_set.find(jmptbl_iter->fixups_addr.back());
      }
      if (targets_iter != targets_set.end()){
	jmptbl_iter->base_addr = targets_iter->first;
	jmptbl_iter->base_addr_fixup = targets_iter->second;
	jmptbl_iter->size = jmptbl_iter->fixups_addr.size();
	jmptbl_iter->entry_size = fixup_size;
	jmptbl_iter++;
      } else {
	jmptbl_iter = jtables.erase(jmptbl_iter);
      }
    }
  }

  for (jmptbl_iter = jtables.begin(); jmptbl_iter != jtables.end(); jmptbl_iter++){
    verbose(1, "jump table base address 0x%lx, fixup base address 0x%llx size is %d", jmptbl_iter->base_addr, jmptbl_iter->base_addr_fixup, jmptbl_iter->size);
    for (auto case_addr: jmptbl_iter->cases_addr){
      all_targets.insert(case_addr);
      verbose(1, "jmptbl entry 0x%lx", case_addr);
    }
  }
}
  
// parse fixup information
int parse_fixup_pb(const char* fixup_pb, std::set<fixup_t>& fixups, RefInf::RefList& reflist, std::vector<section_map_t>& smaps){
  std::fstream input(fixup_pb, std::ios::in | std::ios::binary);
  bool to_code = false;
  uint64_t target_va;
  std::vector<section_map_t*> code_secs;
  if (!input){
    print_err("Can't open the fixup protobuf error! the path is %s", fixup_pb);
    return 0;
  }

  if (!reflist.ParseFromIstream(&input)){
    print_err("Parse RefInf protobuf error!");
    return 0;
  }

  for (auto sec_iter = smaps.begin(); sec_iter < smaps.end(); sec_iter++){
    if (sec_iter->flags & SEC_FLAG_EXEC)
      code_secs.push_back(&*sec_iter);
  }

  for (int i = 0; i < reflist.ref_size(); i++){
    const RefInf::Reference& cur_ref = reflist.ref(i);
    target_va = cur_ref.target_va();
    to_code = false;
    for (auto cur_sec: code_secs){
      if (target_va >= cur_sec->addr &&
	  target_va < cur_sec->addr + cur_sec->size){
	to_code = true;
	break;
      }
    }
    fixups.insert(fixup_t(cur_ref.ref_va(), cur_ref.target_va(), cur_ref.ref_size(), to_code));
    verbose(1, "current fixup 0x%lx -> target 0x%lx (size %d)", \
	cur_ref.ref_va(), cur_ref.target_va(), cur_ref.ref_size());
  }

  input.close();
  return 1;
}

void mark_jtable_entry(const char* ref_name, RefInf::RefList& reflist, std::vector<jmptbl_t>& jtables){
  bool changed = 0;
  std::set<uint64_t> all_entries;
  for (auto jmptbl_iter = jtables.begin(); jmptbl_iter != jtables.end(); jmptbl_iter++){
    for (auto fixup_addr : jmptbl_iter->fixups_addr){
      all_entries.insert(fixup_addr);
    }
  }

  for (int i = 0; i < reflist.ref_size(); i++){
    RefInf::Reference* cur_ref = reflist.mutable_ref(i);
    if (all_entries.find(cur_ref->ref_va()) != all_entries.end()){
      cur_ref->set_jt_entry(1);
      verbose(1, "mark jump table entry at 0x%lx", cur_ref->ref_va());
      changed = 1;
    } else{
      cur_ref->set_jt_entry(0);
    }
  }

  if (changed){
    std::fstream output(ref_name, std::ios::out | std::ios::trunc | std::ios::binary);
    if (!reflist.SerializeToOstream(&output)){
      print_err("save ref info file error!");
    }
    output.close();
  }
}

int parse_dataincode_info(const char* b_fname, std::vector<data_in_code_reg_t>& regs){
  FILE *f;
  char *linebuf, *tok;
  size_t buflen = 4096;
  uint32_t start_line;
  uint32_t end_line;
  std::string cu_path;
  int ret;
  f = NULL;
  linebuf = NULL;

  verbose(2, "parsing data in code info file '%s'", b_fname);

  f = fopen(b_fname, "r");
  if (!f){
    print_err("Failed to open data in code info file '%s'", b_fname);
    ret = -1;
    goto cleanup;
  }

  linebuf = (char*)malloc(buflen);
  if (!linebuf){
    print_err("out of memory");
    ret = -2;
    goto cleanup;
  }


  while(getline(&linebuf, &buflen, f) > 0){
    if (strlen(linebuf) < 3) continue;
    if (linebuf[0] == '#') continue;

    tok = strchr(linebuf, '\n');
    if (tok) (*tok) = '\0';

    verbose(2, "[parse dataincode info]: current line is %s", linebuf);
    tok = strtok(linebuf, " ");
    if (!tok){
      print_err("[parse dataincode info]: can't parse file name!");
      ret = -3;
      goto cleanup;
    }

    regs.push_back(data_in_code_reg_t());
    regs.back().cu_file = std::string(tok);
    std::transform(regs.back().cu_file.begin(), regs.back().cu_file.end(), regs.back().cu_file.begin(), [](unsigned char c){return std::tolower(c); });
    verbose(1, "[parse dataincode info]: current cu file is %s", tok);


    tok = strtok(NULL, " ");
    while(tok){
      if ((tok[0] >= '0') && (tok[0] <= '9')){
	start_line = atoi(tok);

	tok = strtok(NULL, " ");
	if (!tok || tok[0] < '0' || tok[0] > '9'){
	  print_err("[parse dataincode info]: parsing end line error!");
	  ret = -4;
	  goto cleanup;
	}
	end_line = atoi(tok);

	regs.back().regions[start_line] = end_line;
	verbose(1, "[parse dataincode info]: from %d to %d", start_line, end_line);

	tok = strtok(NULL, " ");
      }
    }

  }

  ret = 0;

cleanup:
  if (f){
    fclose(f);
  }

  if (linebuf){
    free(linebuf);
  }

  return ret;
}

int output_pb(const char* pb_output, blocks::module& module){
  std::fstream output(pb_output, std::ios::out | std::ios::trunc | std::ios::binary);
  if (!module.SerializeToOstream(&output)){
    print_err("output pb file error!");
    return -1;
  }
  return 0;
}

int
main(int argc, char *argv[])
{
  /*
   * Dump a map file for the given PE(Portable Executable) binary that describes the type of each
   * byte in the PROGBITS sections (lower letters denote suspected type, while
   * their uppercase equivalents denote confirmed types):
   *
   *   d - data
   *   c - code
   *   i - instruction boundary
   *     Note that if a byte is an instruction boundary (start of an instruction),
   *     this implies that it is a code byte
   *   o - instruction boundary (start of overlapping instruction)
   *   b - basic block start
   *   f - function start
   *   e - program entry point (i.e., start of main)
   *   r - function end (return, tail call, etc.)
   *   j - control-flow instruction (jmp, call, ret, ...)
   *   x - crossref/call instruction
   *   n - NOP or other function padding
   *
   * The format of the map file is as follows:
   *
   *   @0x0100: ccc[CIFB]CCCC
   *   @0x0200: dddDDDDDDDDDD
   *
   * I.e., each line starts with the address of the first byte in that line,
   * followed by type descriptors for each byte. A byte with multiple type 
   * descriptors is delimited by square brackets. A new line start + address
   * indicator is mandatory if there is a gap in the address range. I.e., all
   * listed bytes are assumed to be sequential unless an address indicator
   * explicitly states otherwise. Address indicators may also be inserted every 
   * few bytes for human readability of the map file.
   *
   * The map files are based on DWARF and symbol information. As an extra refinement of 
   * the results, we run a recursive disassembly of each function and entry point found 
   * using DWARF/symbol data, parsing only guaranteed correct instructions (i.e., we stop 
   * for things like jump types where we're not 100% sure how to proceed). This provides 
   * a very conservative ground truth.
   */
  int pe_fd, opt, ret;
  size_t i;
  char *pe_fname, *llvminfo_fname, *aux_fname, *graph_fname, *pdb_fname, *pb_output, *fixup_pb, *blacklist_fname;
  char const *err;
  const char *sectype;
  char optstr[] = "vwhjRpsSOixd:EFf:g:l:e:P:o:r:b:";
  pe_data_t pe;
  enum demangling_styles demangle_style;
  std::vector<section_map_t> smaps;
  std::vector<cu_t> cumaps;
  std::vector<symbol_t> syms;
  std::vector<function_t> funcs;
  std::vector<switch_t> switches;
  std::vector<address_taken_bb_t> at_blocks;
  std::vector<overlapping_bb_t> overlaps;
  std::map<uint64_t, blocks::BasicBlock*> indirect_jumps;
  std::set<uint64_t> non_ret_funcs_addr;
  std::set<uint64_t> all_targets;
  std::set<uint64_t> prefix_ins;
  std::vector<jmptbl_t> jtables;
  std::vector<data_in_code_reg_t> data_in_code_regs;

  // store all fixups information. to help filter indirect jumps
  std::set<fixup_t> fixups;
  RefInf::RefList refs_list;
  // saved protobuf module
  blocks::module module;

  pe_fd         = -1;
  pe_fname      = NULL;
  llvminfo_fname = NULL;
  aux_fname      = NULL;
  graph_fname    = NULL;
  blacklist_fname = NULL;
  pb_output = NULL;

  demangle_style = auto_demangling;

  opterr = 0;
  while((opt = getopt(argc, argv, optstr)) != -1) {
    switch(opt) {
    case 'v':
      verbosity++;
      break;

    case 'w':
      warnings = 0;
      break;

    case 'E':
      guess_func_entry = 1;
      break;
    case 'F':
      track_funcs = 1;
      break;

    case 'j':
      ignore_fallthrough = 1;
      break;

    case 'R':
      guess_return = 1;
      break;

    case 'p':
      ignore_padding = 1;
      break;

    case 's':
      skip_func_sigs = 1;
      break;

    case 'S':
      symbols_only = 1;
      break;

    case 'O':
      allow_overlapping_ins = 1;
      break;

    case 'i':
      map_show_insbounds = 1;
      break;

    case 'x':
      map_limit_16_bytes = 1;
      break;

    case 'f':
      aux_fname = strdup(optarg);
      break;

    case 'g':
      graph_fname = strdup(optarg);
      break;

    case 'e':
      pe_fname = strdup(optarg);
      break;

    case 'l':
      have_llvminfo  = 1;
      llvminfo_fname = strdup(optarg);
      break;

    case 'P':
      pdb_fname = strdup(optarg);
      break;

    case 'o':
      pb_output = strdup(optarg);
      break;

    case 'r':
      fixup_pb = strdup(optarg);
      break;

    case 'b':
      blacklist_fname = strdup(optarg);
      break;

    case 'h':
    default:
      print_usage(argv[0]);
      return 0;
    }
  }

  if(!pe_fname) {
    print_err("missing target pe (arg for -e)");
    goto fail;
  }

  if(!pdb_fname) {
    print_err("missing target .pdb database (arg for -p)");
    goto fail;
  }


  if (!pb_output){
    pb_output = "/tmp/pe_blocks.pb";
  }

  cplus_demangle_set_style(demangle_style);

  /* dump argument list for later reference in saved map files */
  printf("# ");
  for(opt = 0; opt < argc; opt++) {
    printf("%s ", argv[opt]);
  }
  printf("\n\n");

  verbose(1, "opening '%s'", pe_fname);
  pe_fd = open(pe_fname, O_RDONLY);

  if(pe_fd < 0) {
    print_err("failed to open '%s'", pe_fname);
  }

  pe.fd = pe_fd;
  pe.pdb_fname = pdb_fname;
  pe.pe_fname = pe_fname;

  parse_pe_info(pe);

  ret = parse_section_headers(pe, &smaps);
  if(!ret) {
    goto fail;
  }

  ret = parse_pe_symbols(pe, &smaps, &syms, non_ret_funcs_addr);

  if(!ret) {
    goto fail;
  }

  ////////////////////////////////////////////////////////////////
  //////////until here, parse sections and symbols////////////////
  ///////////////////////////////////////////////////////////////

  verbose(2, "");

  verbose(1, "*************** interesting PE sections ***************");
  verbose(1, "%-4s  %-20s %-10s %-5s %-18s %s", "idx", "name", "type", "flags", "addr", "size");
  for(i = 0; i < smaps.size(); i++) {
    verbose(1, "[%-2u]  %-20s %-10s %s%s%s   0x%016jx %ju", 
            i, smaps[i].name.c_str(), "PROGBITS",
            smaps[i].flags & SEC_FLAG_READ  ? "r" : "-",
            smaps[i].flags & SEC_FLAG_WRITE ? "w" : "-",
            smaps[i].flags & SEC_FLAG_EXEC  ? "x" : "-",
            smaps[i].addr, smaps[i].size);
  }
  verbose(1, "");

  ret = init_section_maps(&pe, &smaps, &err);
  if(ret < 0) {
    print_err("%s", err);
    goto fail;
  }

  verbose(1, "*************** suspected section types ***************");
  for(i = 0; i < smaps.size(); i++) {
    if(smaps[i].map[0].btypes.empty()) {
      sectype = "none";
    } else {
      sectype = (smaps[i].map[0].btypes[0].code & 0x01) ? "code" : "data";
    }
    verbose(1, "[%-2u]  %-20s %s (%ju bytes)", 
            i, smaps[i].name.c_str(), sectype, smaps[i].map[0].btypes.size());
  }
  verbose(1, "");

  /* discard. we use debug information to parse non-return function
  if (have_llvminfo) {

    ret = parse_llvminfo(llvminfo_fname, &funcs, &switches, non_ret_funcs, &err);
    if(ret < 0) {
      print_err("%s", err);
      goto fail;
    }

    ret = get_nonret_funcs_addr(syms, non_ret_funcs, non_ret_funcs_addr, &err);
    if (ret < 0){
      print_err("%s", err);
      goto fail;
    }
  }*/

  // parse blacklist_fname, it records data in code regions.
  // format is `filename start_line1 end_line1 start_line2 end_line2`
  if (blacklist_fname){
    if(parse_dataincode_info(blacklist_fname, data_in_code_regs) < 0){
      verbose(1, "parse data in code error");
      goto fail;
    }
  }

  if (!parse_fixup_pb(fixup_pb, fixups, refs_list, smaps)){
    print_err("parse fixup pb error");
    goto fail;
  }


  ret = safe_disasm_entry_point(&pe, &smaps, non_ret_funcs_addr, all_targets, prefix_ins, &err);
  if(ret < 0) {
    print_err("%s", err);
  }

  ret = safe_disasm_symbols(&pe, &smaps, &syms, non_ret_funcs_addr, all_targets, prefix_ins, &err);
  if(ret < 0) {
    print_err("%s", err);
  }

  if(track_funcs || track_overlapping_blocks) {
    for(i = 0; i < syms.size(); i++) {
      if(syms[i].type == SYM_TYPE_FUNC) {
        funcs.push_back(function_t(syms[i].name, syms[i].value, syms[i].size));
      }
    }
  }


  filter_jtable(funcs, jtables, fixups, all_targets);

  if(!symbols_only) {
    // disassemble instructions according to lines info
    ret = parse_pe_debug_lines(pe, &smaps, cumaps, non_ret_funcs_addr, all_targets, data_in_code_regs, prefix_ins, jtables, &err);
    if(!ret) {
      print_err("%s", err);
    }
  }

  disassemble_according_jtables(pe, &smaps, non_ret_funcs_addr, all_targets, prefix_ins, jtables, &err);

  construct_cfg(&pe, &smaps, module, indirect_jumps, non_ret_funcs_addr, all_targets, prefix_ins, funcs);

  for (auto indirect: indirect_jumps){
    verbose(1, "indirect jump at 0x%lx", indirect.first);
  }

  roughly_pair_jtable(jtables, indirect_jumps);

  if (output_pb(pb_output, module) < 0){
    goto fail;
  }

  mark_jtable_entry(fixup_pb, refs_list, jtables);

  ret = 0;
  goto cleanup;

fail:
  ret = 1;

cleanup:

  if(pe_fd >= 0) {
    close(pe_fd);
  }
  if(pe_fname) {
    free(pe_fname);
  }
  if(pdb_fname) {
    free(pdb_fname);
  }
  if(llvminfo_fname) {
    free(llvminfo_fname);
  }
  if(aux_fname) {
    free(aux_fname);
  }
  if(graph_fname) {
    free(graph_fname);
  }

  return ret;
}
