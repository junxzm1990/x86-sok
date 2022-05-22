# Compiler

OracleGT supports two open-source compilers(gcc, llvm/clang) to collect the ground truth of binary disassembly(i.e., instruction recovery, function entry detection and jump table reconstruction) when compiling. Here we dissect every part insider compiler, assembler, and linker to illustrate how to port new compilers.

## Porting to LLVM/Clang

In LLVM, `MachineFunction` represents the function and `MachineMasicBlock` holds a sequence of `MachineInstr`s which represent instructions of specific
architecture. `MCFragment` represents continuous bytecodes inside the generated `Object`. In order to mark the boundary of `Function` and `Basic Block`(`Instruction`) inside `Object`, we borrow the design of [CCR](https://github.com/kevinkoo001/CCR) which traces the boundary from `MachineBasicBlock` level to `MCFragment`.

```

 ===============       ================       ================      ==========      ==============      ==========
||              ||    ||               ||    ||              ||    ||        ||    ||            ||    ||        ||
||    Machine   || => ||    Machine    || => || MachineInstr || => || MCInst || => || MCFragment || => || Object ||
||   Function   ||    ||   BasicBlock  ||    ||              ||    ||        ||    ||            ||    ||        ||
||              ||    ||               ||    ||              ||    ||        ||    ||            ||    ||        ||
 ===============       ================       ================      ==========      ==============      ==========
                                                     MC Componment
```

Specifically, we leverage `MachineBasicBlock` as the basic unit of codes. In `MCAsmInfo`, we bookkeep information of `MachineBasicBlocks` to trace the information of every basic block when assembling.

```c++
class MCAsmInfo {
...
//Essential bookkeeping information for reordering in the future (installation time)
  // (a) MachineBasicBlocks (map)
  //    * MFID_MBBID: <size, offset, # of fixups within MBB, alignments, type, sectionName, contains inline assemble>
  //    - The type field represents when the block is the end of MF or Object where MBB = 0, MF = 1, Obj = 2, and if now block is special mode all type add 1 << 6 such as TBB(thumb basic block) = 64 and TF(thumb function) = 65
  //    - The sectionOrdinal field is for C++ only; it tells current BBL belongs to which section!
  //      MBBSize, MBBoffset, numFixups, alignSize, MBBtype, sectionName, assembleType
  mutable std::map<std::string, std::tuple<unsigned, unsigned, unsigned, unsigned, unsigned, std::string, unsigned>> MachineBasicBlocks;
  //    * MFID: fallThrough-ability
  mutable std::map<std::string, bool> canMBBFallThrough;
  //    * MachineFunctionID: size
...
}
```

`MachineBasicBlocks` is a `map`, the key is the uniqe identifier of every basic block and the value is a pair of informations:
- size of basic block
- offset of basic block inside section of `Object`
- the number of fixups
- type of basic block: is the current basic block is the boundary of function or if the basic block has special mode(such as thumb mode)
- section name
- type of assembly codes

Next, we are going to introduce how to collect those informations at the backend of LLVM.

### Recording the information of basic block

In order to record the size of basic block and the offset inside fragment, we trace the process of assembling `MCInst` into `bytes`. Specifically, `MCELFStreamer` is the basic class that assemble
`MCInst` into `MCFragment`.

```c++
void MCELFStreamer::EmitInstToData(const MCInst &Inst,
                                       const MCSubtargetInfo &STI) {
  // current offset inside DF fragment
  unsigned FragOffset = DF->getContents().size();
  // emit current instruction into DF Fragment
  DF->getContents().append(Code.begin(), Code.end());
  ...
  // Obtain the parent of this instruction (MFID_MBBID)
  std::string ID = Inst.getParent(); // get the unique identifier of its parent basic block
  unsigned EmittedBytes = Code.size();
  unsigned numFixups = Fixups.size();
  const MCAsmInfo *MAI = Assembler.getContext().getAsmInfo();
  // check if current basic block is in special mode. such as thumb mode.
  bool SpecialMode = STI.getSpecialMode();
  // upate the size of current instruction and the number of fixups
  bool initFlag = MAI->updateByteCounter(ID, EmittedBytes, numFixups, /*isAlign=*/ false, /*isInline=*/ false, /*isSpecialMode*/SpecialMode);
  if (initFlag) // if current instruction is the start of basic block, update the offset inside fragment
    MAI->updateOffset(ID,FragOffset);
}
```

The size of some instructions(relexable instructions, such as `jmp .label`) could not determined in `EmitInstToData`, we trace the size of relexable instructions in `MCAssembler::relaxInstruction`:

```c++
bool MCAssembler::relaxInstruction(MCAsmLayout &Layout,
                                   MCRelaxableFragment &F) {
    std::string ID = F.getInst().getParent();
    unsigned relaxedBytes = F.getRelaxedBytes();
    unsigned fixupCtr = F.getFixup();
    unsigned curBytes = F.getInst().getByteCtr();
    if (relaxedBytes < curBytes) {
        // RelaxableFragment always contains relaxedBytes and fixupCtr variable
        // for the adjustment in case of re-evaluation (simple hack but tricky)
        // not here
        MAI->updateByteCounter(ID, curBytes - relaxedBytes, 1 - fixupCtr,
                              /*isAlign=*/ false, /*isInline=*/ false , /*isSpecialMode*/SpecialMode);
        F.setRelaxedBytes(curBytes);
        F.setFixup(1);
        // If this fixup points to Jump Table Symbol, update it.
        F.getFixups()[0].setFixupParentID(ID);
      }
}
```

To update the offset of basic block inside final `object`, we hook the process of organizing fragments into object by operating `MCAsmLayout`:

```c++
void updateReorderInfoValues(const MCAsmLayout &Layout) {
  const MCAsmInfo *MAI = Layout.getAssembler().getContext().getAsmInfo();
  const MCObjectFileInfo *MOFI = Layout.getAssembler().getContext().getObjectFileInfo();
  for (MCSection &Sec : Layout.getAssembler()) {
    MCSectionELF &ELFSec = static_cast<MCSectionELF &>(Sec);
    std::string tmpSN, sectionName = ELFSec.getSectionName();
    if (sectionName.find(".text") == 0) {
        // Per each fragment in a .text section
      unsigned nowFragOffset = 0;
      for (MCFragment &MCF : Sec) {
        nowFragOffset = MCF.getOffset();
        for (std::string ID : MCF.getAllMBBs()) {
          std::get<1>(MAI->MachineBasicBlocks[ID]) += nowFragOffset; // update the offset of current basic block
          ...
        }
      }
      std::get<5>(MAI->MachineBasicBlocks[ID]) = sectionName; // update section name
    }
    ...
```

### Recording information of jump table

To trace the information of jump tables, we record the information into relocation in `EmitInstToData`:

```c++
void MCELFStreamer::EmitInstToData(const MCInst &Inst,
                                   const MCSubtargetInfo &STI) {
	  std::string ID = Inst.getParent(); //Declared in MCInst.h,(MFID_MBBID)
    ...
    for fixup in fixups
    {
        //This part needs special treatment according to different architectures
        //1.Different jump table prefixes
        //2.Different fixup types require special handling
        if(".LJTI" in fixup.sym or "$JTI" in fixup.sym)
        {
            fixups[i].setIsJumpTableRef(true); //Set the fixup to be associated with a jump table
          	fixups[i].setSymbolRefFixupName(fixup.sym);
        }
    }
    for fixup in addedfixups // handle special instruction such as tbb
    {
            fixups[i].setIsJumpTableRef(true);
          	fixups[i].setSymbolRefFixupName(fixup.sym);
    }
}
```

### Writing ground truth to binary

To store the ground truth information, the tool creates a new section `.gt` in the binary

```c++
void ELFObjectWriter::writeSectionData(const MCAssembler &Asm, MCSection &Sec,
                                       const MCAsmLayout &Layout) {
  ...
  if (section name is ".gt") {
    Asm.WriteRandInfo(Layout); // write addtion info into .rand section
  }
  ...
}                                      
void WriteRandInfo(Layout)
{
    ...
	if(section name is ".text") // force on .text section
    {
        for fragment in fragments
        {
            totalOffset = fragment.offset
            for BB in BBs
            {
                BB.updateOffset(totalOffset)//update the offset with BBsize and fragment offset
                totalOffset += BB.size
           		function.size += BB.size
               	if BB is function end
                    BB.updateType(func_type) //if BB is func end, update the BB type
            }
        }
    }
    ...
}
Void Layout(layout)
{
    for section in sections
        for fragment in fragments
        {
            for fixup in fixups
                if(jumptable) // if fixup is related to a jumptable,update the info to fixuplist declared in MCAsmInfo.h
                    updateFixuplist();
            for fixup in addedfixups // handle special fake fixup, to record the jumptable
                if(jumptable)
                    updateFixuplist();
        }
}
```

## Porting to GCC

In order to pass information from `GCC` compiler to `GNU Assembler`, The tool defines some `directives`[1] to mark basic block information, function information, inline information and jump table information

| Label          | Information                           |
| -------------- | ------------------------------------- |
| bbInfo_BB      | mark the basic block begin location   |
| bbInfo_BE      | mark the basic block end location     |
| bbInfo_FUNB    | mark the function start location      |
| bbInfo_FUNE    | mark the function end location        |
| bbInfo_JMPTBL  | mark the jump table information       |
| bbInfo_INLINEB | mark the asm inline start information |
| bbInfo_INLINEE | mark the asm inline end information   |

The assembly code generated by instrumented `GCC` is shown as follows:

```assembly
.LFB5:
        .cfi_startproc
        .bbInfo_FUNB
        .bbInfo_BB 0
        pushq   %rbp
        .cfi_def_cfa_offset 16
        .cfi_offset 6, -16
        movq    %rsp, %rbp
        .cfi_def_cfa_register 6
        leaq    .LC0(%rip), %rdi
        call    puts@PLT
        movl    $-1, %edi
        .bbInfo_BE 0
        call    exit@PLT
        .cfi_endproc
.LFE5:
        .bbInfo_FUNE
....
.L10:
        .bbInfo_JMPTBL 35 4
        .long   .L39-.L10
        .long   .L8-.L10
        .long   .L38-.L10
        .long   .L8-.L10
        .long   .L8-.L10
        .long   .L37-.L10
        .long   .L36-.L10
        .long   .L8-.L10
....
```

In order to output these labels, the tool created `bbinfo2asm.c` and instrumented `final.c` and `cfg.c`.

In `bbinfo2asm`, the tool defines the following functions:

```c
// output the basic block begin label
extern void bbinfo2_asm_block_begin(uint32_t);

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

```

```c
//final.c
final_start_function_1()
{
    ...
    bbinfo2_asm_func_begin();//Output the bbInfo_FUNC Label
    ...
}
final_end_function()
{
    ...
    bbinfo2_asm_func_end();//Output the bbInfo_FUNE Label
    ,,,
}

dump_basic_block_mark(inst)
{
    flag = 0;
    for edge in edges
        if(edge_fall_through(edge))
			flag = 1;
 	if inst is the first instruction of BB
        bbinfo2_asm_block_begin(flag);//Output the bbInfo_BB Label
    if inst is the last instruction of BB
        bbinfo2_asm_block_end(flag);//Output the bbInfo_BE Label
}
final_1()
{
    ...
    for inst in insts
        dump_basic_block_mark(inst);
    ...
}
app_enable()
{	
    ...
    if (! app_on)
    {
        ...
    	bbinfo2_asm_inline_start();//Output the bbInfo_INLINEB Label
    	...
    }
    ...
}
app_app_disable()
{	
    ...
    if (app_on)
    {
        ...
    	bbinfo2_asm_inline_end();//Output the bbInfo_INLINEE Label
    	...
    }
    ...
}
//And to get basic block information, comment out flag_debug_asm.
```

```c
//cfg.c
// if the edge is fall through, return true
edge_fall_through(edge e){
	if(e.flag is fallthrough)
        return true;
   	return false;
}
```

# Assembler

## Porting to GNU Assembler(GAS)

> Recommendation: Assembler is not related to compiler optimizations, we could leave the `GAS` as it is until it is not fit in new GCC compilers.

The process of assembling could be deemed as a state machine: when processing `directive`, it defines current state and triger the specific action to handle following sequence bytes. So we could add specific `directives` to pass information from compiler to assembler and represent the specific state inside assembler.

Specifically, in order to migrate to new gas, we could do following modifications:

### Define Handler for Directives

```c
const pseudo_typeS bbInfo_pseudo_table[] = {
    {"bbinfo_jmptbl", jmptable_bbInfo_handler, 0}, // handle jump table
    {"bbinfo_funb", funcb_bbInfo_handler, 0},   // handler start of a function
    {"bbinfo_fune", funce_bbInfo_handler, 0},   // handle end of a function
    {"bbinfo_bb", bb_bbInfo_handler, 0},    // handle start of a basic block(bb)
    {"bbinfo_be", be_bbInfo_handler, 0},    // handler end of a bb
    {"bbinfo_inlineb", inlineb_bbInfo_handler, 0},  // handle start of inline pseudo-bb
    {"bbinfo_inlinee", inlinee_bbInfo_handler, 0},  // handle end of inline pseudo-bb
    {NULL, NULL, 0}
};
```

The modified `GCC` emits corresponding `directives` to pass the boundary of function, basic block and the information of jump tables. At the assembler side, we could reconstruct these information when handling specific directive. In order to represent these informaton, we could use following structures:

```c
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
  uint8_t is_begin; // if current instruction is the first instruction of this basic block
  uint8_t is_inline; // if current basic block contains inline assemble code or current basic block
  fragS *parent_frag; // this basic block belongs to which frag.
};
```

The tool uses `basic_block` to represent the basic unit that contains continuous instructions. When met `bbinfo_bb`, the tool initializes a new `basic_block`:

- Update the `fall_through` field according to the value obtained by `bbinfo_bb` directive.
- `Fragment` is the basic unit inside assembler, it represents continuous fixed regions. The tool associates `basic_block` with fragment when initializing and update the offset inside current fragment.
- Update `sec` field which represents which section it belongs to.

### Record Instructions

The tool hooks the process of emitting instructions into fragment, and record every instruction in current `basic_block`. In `gas/config` directory, it defines architecture related functions to emit insturctions into fragment. For example, for `AArch64`, `gas/config/tc-aarch64.c::output_inst(struct aarch64_inst *new_inst)` function do that work.

```c
// in gas/config/tc-aarch64.c
static void
output_inst (struct aarch64_inst *new_inst)
{
    ...
    frag_now->last_bb = mbbs_list_tail;
    if (mbbs_list_tail) {
        mbbs_list_tail->size += INSN_SIZE; // update current instuction to current basic block
    }
    ...
}
```

### Store Jump Table Information

The tool leverages `fixup` to record the information of jump table. Specifically, when met `bbinfo_jmptbl` directive, it could obtain the information of jump table(The size of jump table and the size of every jump table entry) and associates the information with last `fixup`.

```c
// handle bbinfo_jmptbl directive
void jmptable_bbInfo_handler(int ignored ATTRIBUTE_UNUSED){
    offsetT table_size, entry_size;
    table_size = get_absolute_expression();
    SKIP_WHITESPACE();

    entry_size = get_absolute_expression();
    if (last_symbol == NULL){
	    as_warn("Sorry, the last symbol is null\n");
	    return;
    }

    // update the jump table related information of the symbol
    S_SET_JMPTBL_SIZE(last_symbol, table_size);
    //as_warn("JMPTBL table size is %d\n", table_size);
    S_SET_JMPTBL_ENTRY_SZ(last_symbol, entry_size);
}
```

# Linker

## Porting to Gold Linker

> Recommendation: Linker is not related to compiler optimizations, we could leave the `gold as` it is until it is not fit in new compilers.

Linker integrates object files(.o) into one executable file and updates informations of final executable file(such as relocations). The tool hooks the process of
Gold to updates the offset of every basic block. Specifically, when link finalizes the integration of object files, we update the offsets.

```c++
// in gold/layout.cc
off_t
Layout::finalize(const Input_objects* input_objects, Symbol_table* symtab,
		 Target* target, const Task* task)
{
    ...
    // Run the relaxation loop to lay out sections.
  do
    {
      off = this->relaxation_loop_body(pass, target, symtab, &load_seg,
				       phdr_seg, segment_headers, file_header,
				       &shndx);
      pass++;
    }
  while (target->may_relax()
	 && target->relax(pass, input_objects, symtab, this, task));

  // the part added
  bool is_big_endian = parameters->target().is_big_endian();
  int binary_format_size = parameters->target().get_size();
  if (is_big_endian && binary_format_size == 64){
    this->update_shuffleInfo_layout<64, true>();
  } else if (!is_big_endian && binary_format_size == 64){
    this->update_shuffleInfo_layout<64, false>();
  } else if (is_big_endian && binary_format_size == 32){
    this->update_shuffleInfo_layout<32, true>();
  } else if (!is_big_endian && binary_format_size == 32){
    this->update_shuffleInfo_layout<32, false>();
  }
  ...
}
```

In `update_shuffleInfo_layout()`, the tool iterates every basic block and update its offsets inside executable file.

Finally, the tool hooks the process of generating sections and add section `.gt` to store ground truth of binary disassembly.

```c++
// in gold/main.cc
 std::string rand(".gt=");
  std::string opt_2 = rand+shuffle_bin_gz;
  // binpang, support the `-r` option
  if (parameters->options().relocatable()){
    opt_2 = rand+shuffle_bin;
  }
  char * const add_section[] = {"objcopy", "--add-section", (char *)opt_2.c_str(), (char *)target.c_str(), (char*)NULL};
  if(fork()){
  int status;
  wait(&status);
  }else{
  //child exec the objcopy to integrate shufflebin into target
  execvp("objcopy", add_section);
  _exit(0);
  }

```

# References

- [1] Assembler Directives: https://eng.libretexts.org/Bookshelves/Electrical_Engineering/Electronics/Implementing_a_One_Address_CPU_in_Logisim_(Kann)/02%3A_Assembly_Language/2.03%3A_Assembler_Directives#:~:text=Assembler%20directives%20are%20directions%20to,not%20translated%20into%20machine%20code.
- [2] Intro to the LLVM MC Project: http://blog.llvm.org/2010/04/intro-to-llvm-mc-project.html