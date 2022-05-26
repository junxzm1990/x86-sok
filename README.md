# OracleGT

Overview of the source code:

```console
.
|-- artifact_eval   # steps to reproduce results of Usenix Paper.
|-- ccr			# source code of ccr/randomizer
|-- compare		# scripts that compare the result between gt and disassembler
|-- extract_gt		# scripts that extract ground truth from binary
|-- disassemblers       # scripts that we use to extract disassemblers' result
|-- gt			# modified gcc/clang toolchain
|-- protobuf_def	# protobuf definitions that defines disassembly information and x-ref information
|-- README.md
`-- testsuite		# coreutils and findutils that compiled by gcc/clang toolchain

```

## Supported architectures

Our toolchains were tested in x64 Ubuntu18.04/20.04 and they could (cross-)compile binaries of following architectures.

- x86/x64
- arm32
- aarch64
- mipsle/mips64le

## Dataset

We shared dataset of x86/arm/mips compiled by gcc-8.1.0 and clang-6.0 and disassembly results of popular disassemblers.

- [x86/x64 dataset](https://zenodo.org/record/6566082/files/x86_dataset.tar.xz?download=1). Decompressed size is ~56GB.
- [mips arm dataset](https://zenodo.org/record/6566082/files/arm_mips_dataset.tar.gz?download=1). Decompressed size is ~35GB.

## The Framework of compilers

We modified compilers(gcc/clang) to collect the information of basic blocks and reconstruct the information of binary code.
And we want to extract executable file's basic block, jump table, fixup/reference and function information in compilation tool and can help to evaluate disassemblers.

For clang, we re-use the implemenation of [CCR](https://github.com/kevinkoo001/CCR).

```
                                                              |
 ===============       ===============       ===============  |     =============
||             ||     ||             ||     ||             || |    ||           ||
|| preprocess  ||  +  ||   compile   ||  +  ||  assemble   || | +  ||   link    ||  => executable
||             ||     ||             ||     ||             || |    ||           ||
 ===============       ===============       ===============  |     =============
               llvm/clang              MC Componment          |      linker(gold)

```

For gcc, we modifed gcc and gas(GNU assembler).
Modifications can be found at [gcc modification](https://github.com/junxzm1990/x86-sok/blob/master/gt/gcc/gcc-8.1.0/patch_f4eef700) and [gas modification](https://github.com/junxzm1990/x86-sok/blob/master/gt/binutils/patch_as_2_30).


```
                                        |                      |
 ===============       ===============  |     ===============  |     =============
||             ||     ||             || |    ||             || |    ||           ||
|| preprocess  ||  +  ||   compile   || | +  ||  assemble   || | +  ||   link    ||  => executable
||             ||     ||             || |    ||             || |    ||           ||
 ===============       ===============  |     ===============  |     =============
                  gcc                   |      assembler(gas)  |      linker(gold)

```

There exist some differences between llvm toolchains(based on ccr) and gcc toolchains. In llvm, it has [MC componment](http://blog.llvm.org/2010/04/intro-to-llvm-mc-project.html) that combines `compilation` and `assembling` together internally. While gcc outputs the .s file after compilation, and invoke `assembler(gas)` to assemble the .s file into object. So it is easier to extract the basic block and jump table information in compilation and store this information in object file after assembling in llvm toolchains when comparing to gcc toolchains.

As basic block, function, and jump table information can only be collected in compilation stage, so firstly, we output the related information into .s file, and then we reconstruct these information in assembler(gas).


## Build && Use the Compilers

### x86/x64
We provide two ways to build the toolchains of compilers in x86/x64: ubuntu18.04 and docker.

#### Ubuntu 18.04

If you are using Ubuntu 18.04, we recommend you to build the toolchain in your computer:

```console
$ git clone git@github.com:junxzm1990/x86-sok.git
$ cd x86-sok/gt
$ bash x86/build.sh
```

The gcc/g++ are installed in `gt/build/executable_gcc/bin`, clang/clang++ are installed in `gt/build/build_clang/bin`. We also build glibc by using our toolchain so that the compiled glibc contains the information emitted by compiler. Glibc is installed in `gt/build/glibc_build_32` or `gt/build/glibc_build_64`.

For convenience, we provide config scripts to set `CC`, `CXX`, `CFLAGS`, `CXXFLAGS`, `LDFLAGS`. These configs are `gt/gcc64.rc`, `gt/gcc32.rc`, `gt/clang64.rc` and `gt/clang32.rc`.

Before compiling, we can  set proper configures by:

```console
# for example, we want to compile the source code by gcc
$ source gcc64.rc

# set the proper optimization level
$ export CFLAGS="-O2 $CFLAGS" && export CXXFLAGS="-O2 $CXXFLAGS"
```


#### Docker

If you prefer to use Docker, we also provides script to build docker image.

```console
# install docker firstly
$ curl -fsSL https://get.docker.com/ | sudo sh
$ sudo usermod -aG docker [user_id]

# build our toolchain
$ git clone git@github.com:junxzm1990/x86-sok.git
$ cd x86-sok/gt
$ docker build -t x86_gt ./

# check the image
$ docker image ls
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
x86_gt              latest              85f6fb2d4257        2 minutes ago       1.4GB

# launch the image
$ docker run --rm -it x86_gt:latest /bin/bash

# configure CC, CXX, CFLAGS, CXXFLAGS, LDFLAGS inside container
root@fc44258775ac:/gt_x86# source ./gcc64.rc
root@fc44258775ac:/gt_x86# export CFLAGS="-O2 $CFLAGS" && export CXXFLAGS="-O2 $CXXFLAGS"
```

Or pull the image from Docker Hub:

```console
$ docker pull bin2415/x86_gt:0.1

# check the image
$ docker image ls
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
bin2415/x86_gt      0.1                 85f6fb2d4257        3 minutes ago       20.5GB

# launch the image
$ docker run --rm -it bin2415/x86_gt:0.1 /bin/bash

# configure CC, CXX, CFLAGS, CXXFLAGS, LDFLAGS inside container
root@fc44258775ac:/gt_x86# source ./gcc64.rc
root@fc44258775ac:/gt_x86# export CFLAGS="-O2 $CFLAGS" && export CXXFLAGS="-O2 $CXXFLAGS"
```

### ARM

We cross compiled arm32 and aarch64 binaries in x86/x64 architecture. We need to install qemu:

```console
sudo apt-get install qemu binfmt-support qemu-user-static
```

#### arm32

```console
$ docker pull z472421519/arm32_gt

$ docker image ls
REPOSITORY                   TAG        IMAGE ID       CREATED         SIZE
z472421519/arm32_gt          latest     beb7bba8d960   7 hours ago     5.11GB

$ docker run --rm -it z472421519/arm32_gt /bin/bash

# configure CC, CXX, CFLAGS, CXXFLAGS, LDFLAGS inside container
root@32380fe55c2a:/gt_arm32# source gcc32_arm.rc
root@32380fe55c2a:/gt_arm32# export CFLAGS="-O2 $CFLAGS" && export CXXFLAGS="-O2 $CXXFLAGS"

# mthumb
root@32380fe55c2a:/gt_arm32# source gcc32_arm_mthumb.rc
```

#### aarch64

```console
$ docker pull z472421519/aarch64_gt

$ docker image ls
REPOSITORY                   TAG        IMAGE ID       CREATED         SIZE
z472421519/aarch64_gt        latest     aae089d22450   4 hours ago     5.25GB

$ docker run --rm -it z472421519/aarch64_gt /bin/bash

# configure CC, CXX, CFLAGS, CXXFLAGS, LDFLAGS inside container
root@5e9ee548ff5d:/gt_aarch64# source gcc64_arm.rc
root@5e9ee548ff5d:/gt_aarch64# export CFLAGS="-O2 $CFLAGS" && export CXXFLAGS="-O2 $CXXFLAGS"
```

### Mips

We cross compiled mips binaries in x86/x64 architecture. We need to install qemu:

#### mipsle 32

```console
$ docker pull z472421519/mips32_gt

$ docker image ls
REPOSITORY                   TAG        IMAGE ID       CREATED         SIZE
z472421519/mips32_gt         latest     9c708cc17998   25 hours ago    4.42GB

$ docker run --rm -it z472421519/mips32_gt /bin/bash

# configure CC, CXX, CFLAGS, CXXFLAGS, LDFLAGS inside container
root@7605562e48b3:/gt_mips32# source gcc32_mips.rc
root@7605562e48b3:/gt_mips32# export CFLAGS="-O2 $CFLAGS" && export CXXFLAGS="-O2 $CXXFLAGS"
```

#### mipsle 64

```console
$ docker pull z472421519/mips64_gt

$ docker image ls
REPOSITORY                   TAG        IMAGE ID       CREATED         SIZE
z472421519/mips64_gt         latest     0eaaf0cfacc3   20 hours ago    5.48GB

$ docker run --rm -it z472421519/mips64_gt /bin/bash

# configure CC, CXX, CFLAGS, CXXFLAGS, LDFLAGS inside container
root@76ca6fcc9f1d:/gt_mips# source gcc64_mips.rc
root@76ca6fcc9f1d:/gt_mips# export CFLAGS="-O2 $CFLAGS" && export CXXFLAGS="-O2 $CXXFLAGS"
```

#### Compile binary with our toolchain

Here are examples that explain how to use our x86/x64 toolchain to compile binary(arm and mips toolchains are same with x86/x64).

- Example 1: a simple c code

  ```console
  root@5e8606df7f20:/gt_x86# cd test

  root@5e8606df7f20:/gt_x86/test# source ../gcc64.rc

  root@5e8606df7f20:/gt_x86/test# export CFLAGS="-O0 $CFLAGS"

  root@5e8606df7f20:/gt_x86/test# $CC $CFLAGS -o test_switch test_switch.c
  [bbinfo]: DEBUG, the target binary format is: size 64, is big endian 0
  Update shuffleInfo Done!
  Successfully wrote the ShuffleInfo to the .rand section!

  # check the .rand section in the executable
  root@5e8606df7f20:/gt_x86/test# readelf -S test_switch | grep -A1 rand
  [35] .rand             PROGBITS         0000000000000000  000034ec
        000000000000025b  0000000000000000           0     0     1
  ```

- Example 2: compile coreutils
  ```console
  # download coreutils
  root@1a16bbde2f79:/gt_x86/test# wget -c https://mirror.powerfly.ca/gnu/coreutils/coreutils-8.30.tar.xz
  root@1a16bbde2f79:/gt_x86/test# tar -xvf coreutils-8.30.tar.xz && cd coreutils-8.30
  root@1a16bbde2f79:/gt_x86/test/coreutils-8.30# mkdir build_gcc_O2 && cd build_gcc_O2
  root@1a16bbde2f79:/gt_x86/test/coreutils-8.30/build_gcc_O2# source /gt_x86/gcc64.rc && export CFLAGS="-O2 $CFLAGS"
  root@1a16bbde2f79:/gt_x86/test/coreutils-8.30/build_gcc_O2# export FORCE_UNSAFE_CONFIGURE=1 && ../configure --prefix=$PWD
  root@1a16bbde2f79:/gt_x86/test/coreutils-8.30/build_gcc_O2# make -j && make install

  # the compiled binaries are installed in /gt_x86/test/coreutils-8.30/build_gcc_O2/bin
  root@1a16bbde2f79:/gt_x86/test/coreutils-8.30/build_gcc_O2# ls bin
  '['         cat     chroot   cut    dircolors   expand   fold     install   logname   mknod    nohup    pathchk    ptx        rmdir       sha256sum   sleep    stty   tee       true       unexpand   vdir
  b2sum      chcon   cksum    date   dirname     expr     groups   join      ls        mktemp   nproc    pinky      pwd        runcon      sha384sum   sort     sum    test      truncate   uniq       wc
  base32     chgrp   comm     dd     du          factor   head     kill      md5sum    mv       numfmt   pr         readlink   seq         sha512sum   split    sync   timeout   tsort      unlink     who
  base64     chmod   cp       df     echo        false    hostid   link      mkdir     nice     od       printenv   realpath   sha1sum     shred       stat     tac    touch     tty        uptime     whoami
  basename   chown   csplit   dir    env         fmt      id       ln        mkfifo    nl       paste    printf     rm         sha224sum   shuf        stdbuf   tail   tr        uname      users      yes
  ```

## Exatract Ground truth from binary

### Linux

We use the example of `test_switch` to show how to extract ground truth.

```console
# copy the gt info from binary
root@5e8606df7f20:/gt_x86/test#  objcopy --dump-section .rand=test_switch.gt.gz test_switch && gzip -d test_switch.gt.gz

# there has test_switch.gt in current directory
root@5e8606df7f20:/gt_x86/test# ls
test_switch  test_switch.c  test_switch.gt

# extract disassembly result, and the result is saved in /tmp/gtBlock_test_switch.pb
root@5e8606df7f20:/gt_x86/test# python3 ../../extract_gt/extractBB.py -b test_switch -m test_switch.gt -o /tmp/gtBlock_test_switch.pb
...
...
INFO:=======================================================
INFO:[Summary]: padding cnt is 9
INFO:[Summary]: handcoded bytes is 0
INFO:[Summary]: handcoded number is 0
INFO:[Summary]: Jump tables is 1
INFO:[Summary]: Tail indirect call is 2
INFO:[Summary]: overlapping instructions is 0
INFO:[Summary]: Non-returning function is 2
INFO:[Summary]: Multi-entry function is 0
INFO:[Summary]: overlapping functions is 0
INFO:[Summary]: tail call count is is 1

# extract x-ref result, the result is saved in /tmp/gtRef_test_switch.pb
root@5e8606df7f20:/gt_x86/test# python3 ../../extract_gt/extractXref.py -b test_switch -m test_switch.gt -o /tmp/gtRef_test_switch.pb
```

Note that the definition of disassembly and x-ref result is in `protobuf_def/blocks.proto` and `protobuf_def/refInf.proto`.

We provide script to extract ground truth in batch. It searchs all the binaries in a directory.

```console
ubuntu@ubuntu:/x86-sok/extract_gt: bash run_extract_linux.sh -d <directory> -s ./extractBB.py -p gtBlock
ubuntu@ubuntu:/x86-sok/extract_gt: bash run_extract_linux.sh -d <directory> -s ./extractXref.py -p gtRef
```

### Windows

We prepare an example in `extract_gt/pemap/test`to explain how to extract ground truth.

```console

# extract fixup info, this step must be completed in windows, as we need to use dumpbin tool
windows@windows:/extract_gt/pemap# python3 dumpfixup.py -p ./test/7zDec.pdb -b ./test/7zDec.exe -o ./test/gtRef_7zDec.pb

# extract disassembly info. Note that we need the fixup info
windows@windows:/extract_gt/pemap# make
windows@windows:/extract_gt/pemap# ./PEMap -iwRFE -P ./test/7zDec.pdb -r ./test/gtRef_7zDec.pb -e ./test/7zDec.exe -o ./test/gtBlock_7zDec.pb
```

## Compare the result

Install dependencies:

```console
apt-get update && \
    apt-get install -y \
    build-essential \
    cmake \
    git \
    sqlite3 \
    wget \
    bison \
    zlib1g-dev \
    python3 \
    python3-pip
pip3 install protobuf \
    capstone \
    pyelftools \
    sqlalchemy
```

We can use scripts in `compare` folder to compare results between ground truth and comapred tools.

For example, if we want to compare instructions, we can use `compareInsts.py`:

```console
ubuntu@ubuntu:/x86_sok/compare# python3 compareInsts.py -b <binary path> -g <ground truth> -c <compared>
```

Note that before comparring the non-return, we need to extend the non-return lists based on ground truth:
```console
# extend the non-rets
ubuntu@ubuntu:/x86_sok/compare# python3 findNonRets.py -b <binary path> -g <ground truth> -o <ground truth with extended non-rets>
# compare
ubuntu@ubuntu:/x86_sok/compare# python3 compareNonRet.py -b <binary path> -g <ground turht with extended non-rets> -c <compared>
```

## Porting to New Compilers

OracleGT supports two open-source compilers(gcc, llvm/clang) to collect the ground truth of binary disassembly(i.e., instruction recovery, function entry detection and jump table reconstruction) when compiling. Here we dissect every part insider compiler, assembler, and linker to illustrate how to port new compilers.

### Porting to LLVM/Clang

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

#### Recording the information of basic block

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

#### Recording information of jump table

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

#### Writing ground truth to binary

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

### Porting to GCC

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

### Assembler

#### Porting to GNU Assembler(GAS)

> Recommendation: Assembler is not related to compiler optimizations, we could leave the `GAS` as it is until it is not fit in new GCC compilers.

The process of assembling could be deemed as a state machine: when processing `directive`, it defines current state and triger the specific action to handle following sequence bytes. So we could add specific `directives` to pass information from compiler to assembler and represent the specific state inside assembler.

Specifically, in order to migrate to new gas, we could do following modifications:

#### Define Handler for Directives

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

#### Record Instructions

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

#### Store Jump Table Information

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

### Linker

#### Porting to Gold Linker

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

### References

- [1] Assembler Directives: https://eng.libretexts.org/Bookshelves/Electrical_Engineering/Electronics/Implementing_a_One_Address_CPU_in_Logisim_(Kann)/02%3A_Assembly_Language/2.03%3A_Assembler_Directives#:~:text=Assembler%20directives%20are%20directions%20to,not%20translated%20into%20machine%20code.
- [2] Intro to the LLVM MC Project: http://blog.llvm.org/2010/04/intro-to-llvm-mc-project.html

## License

MIT License.

## Citation

If your research find one or several components of this work useful, please cite the following paper:

@INPROCEEDINGS {sok-x86,\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;author = {Chengbin Pang and Ruotong Yu and Yaohui Chen and Eric Koskinen and Georgios Portokalidis and Bing Mao and Jun Xu},\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;booktitle = {42nd IEEE Symposium on Security and Privacy (SP)},\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;title = {SoK: All You Ever Wanted to Know About x86/x64 Binary Disassembly But Were Afraid to Ask},\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;year = {2021},\
}

