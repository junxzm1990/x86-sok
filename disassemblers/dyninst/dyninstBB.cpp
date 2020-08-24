/* Reference: https://github.com/trailofbits/mcsema/blob/master/tools/mcsema_disass/dyninst/
 * Date: 10/10/2019
 * Author: binpang
 *
 * Extract the cfg from dyninst
 *
 * Build: make
 */

#include <stdio.h>
#include <sstream>
#include <fstream>
#include <set>
#include <cstdint>

#include "CodeObject.h"
#include "Function.h"
#include "Symtab.h"
#include "Instruction.h"

#include "glog/logging.h"
#include "gflags/gflags.h"

#include "blocks.pb.h"

using namespace Dyninst;
DEFINE_string(binary, "", "Path to striped binary file");
DEFINE_string(output, "/tmp/dyninst.pb", "Path to output file");
DEFINE_string(statics, "/tmp/Stat_dyninst.log", "Path to statics file");
DEFINE_int32(speculative, 1, "The mode of speculative parsing. 0 represents do not parse. 1 represents using idiom, 2 represents using preamble, 3 represents using both. default is 1");
std::set<uint64_t> matchingFunc;
int total_funcs = 0;

void dumpCFG(blocks::module &pbModule,
		Dyninst::ParseAPI::CodeObject &codeobj){
  std::set<Dyninst::Address> seen;
  // Set to record the function matching functions
  for (auto func: codeobj.funcs()){
    if (seen.count(func->addr()))
      continue;
    total_funcs++;
    seen.insert(func->addr());
    DLOG(INFO)<< "Get Function Addr: " << std::hex << func->addr() 
	    << ". Its type is " << func->src()
	    << ". Ret status is " << func->retstatus() << std::endl;
    //The function start from gap heuristics
    if (func->src() == 2){
      matchingFunc.insert(func->addr());
    }

    blocks::Function* pbFunc = pbModule.add_fuc();
    pbFunc->set_va(func->addr());
    for (auto block: func->blocks()){
      //DLOG(INFO) << "\tGet Basic Block Addr: " << std::hex << block->start() << std::endl;
	    std::cout << "\tGet Basic Block Addr: " << std::hex << block->start() << std::endl;
      blocks::BasicBlock* pbBB = pbFunc->add_bb();
      pbBB->set_va(block->start()); 
      pbBB->set_parent(func->addr());
      Dyninst::ParseAPI::Block::Insns instructions;
      block->getInsns(instructions);
      unsigned cur_addr = block->start();

      // get instructions
      for(auto p: instructions){
	Dyninst::InstructionAPI::InstructionPtr inst = p.second;
	DLOG(INFO) << "\t\t Get instruction Addr: " << std::hex << cur_addr << std::endl;
	blocks::Instruction* pbInst = pbBB->add_instructions();
	pbInst->set_va(cur_addr);
	pbInst->set_size(inst->size());
	cur_addr += inst->size();
      }

      // get successors
      for( auto succ : block->targets()){
	blocks::Child* pbSuc = pbBB->add_child();
	pbSuc->set_va(succ->trg()->start());
	DLOG(INFO) << "\t\t Get edge: "
	  << std::hex << succ->src()->start()
	  << " -> "
	  << std::hex << succ->trg()->start() << std::endl;
      }
    }
  }
}

void outputMatchingFunc(const char* output_sta){
  auto input_string = FLAGS_binary.data();
  auto input_file = const_cast<char* >(input_string);
  std::fstream output(output_sta, std::ios::out | std::ios::trunc);
  output << "===================Function Matching Information:==========================\n";
  DLOG(INFO) << "===================Function Matching Information:==========================\n";
  int count = 0;
  for (auto func: matchingFunc){
    DLOG(INFO) << "Matching Func#" << count << ": " << std::hex << func << std::endl;
    output << "Func #" << count << ": " << std::hex << func << std::endl;
    count++;
  }
  output << "All function numbers: " << total_funcs << std::endl;
  output << "Function matching numbers: " << count << std::endl;
  output << "Function matching rate: " << (float)count / total_funcs << std::endl;
  output.close();
}

int main(int argc, char** argv){

  std::stringstream ss;
  ss << " " << argv[0] << "\\" << std::endl
    << "      --binary INPUT_FILE \\" << std::endl
    << "      --output OUTPUT PB FILE \\" << std::endl
    << "      --speculative SPECULATIVE MODE \\" << std::endl
    << "      --statics STATICS DATA" << std::endl;

  FLAGS_logtostderr = 1;
  // Parse the command line arguments
  google::InitGoogleLogging(argv[0]);
  google::SetUsageMessage(ss.str());
  google::ParseCommandLineFlags(&argc, &argv, true);
  CHECK(!FLAGS_binary.empty()) << "Input file need to be specified!";
  LOG(INFO) << "Config: binary path " << FLAGS_binary << "\n"
    << "output file is " << FLAGS_output << "\n"
    << "speculative mode is " << FLAGS_speculative << "\n" << std::endl;
  
  auto input_string = FLAGS_binary.data();
  auto input_file = const_cast<char* >(input_string);
  auto symtab_cs = std::make_shared<ParseAPI::SymtabCodeSource>(input_file);
  CHECK(symtab_cs) << "Error during creation of ParseAPI::SymtabCodeSource!";


  auto code_obj = std::make_shared<ParseAPI::CodeObject>(symtab_cs.get());
  CHECK(code_obj) << "Error during creation of ParseAPI::CodeObject";

  code_obj->parse();

  // module pb
  blocks::module pbModule;
  // Use some speculative parsing to do function matching
  auto preamble = Dyninst::ParseAPI::GapParsingType::PreambleMatching;
  auto idiom = Dyninst::ParseAPI::GapParsingType::IdiomMatching;
  if (FLAGS_speculative){
    for (auto &reg: symtab_cs->regions()) {
      switch(FLAGS_speculative){
	case 1:
	  code_obj->parseGaps(reg, idiom);
	  break;
	case 2:
	  code_obj->parseGaps(reg, preamble);
	  break;
	case 3:
	  code_obj->parseGaps(reg, idiom);
	  code_obj->parseGaps(reg, preamble);
	  break;
	default:
	  break;
      }
    }
  }
  dumpCFG(pbModule, *code_obj);

  auto output_sta = const_cast<char* >(FLAGS_statics.data());
  outputMatchingFunc(output_sta);

  auto output_file = const_cast<char* >(FLAGS_output.data());
  std::fstream output(output_file, std::ios::out | std::ios::trunc | std::ios::binary);
  // save the protobuf file
  if (!pbModule.SerializeToOstream(&output)) {
    LOG(FATAL) << "Failed to write the address block" << std::endl;
    return -1;
  }
  output.close();
  return 0;
}
