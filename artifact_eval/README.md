We provide large-scale dataset built by our toolchains for x86/x64, arm32/mthumb/aarch64 and mips32/mips64. To reproduce the result in our Usenix paper easily, we also provide corresponding scripts.

## Download datasets
 - [x86 dataset](https://zenodo.org/record/6566082/files/x86_dataset.tar.xz?download=1). Decompressed size is ~56GB.
 - [mips arm dataset](https://zenodo.org/record/6566082/files/arm_mips_dataset.tar.gz?download=1). Move the `testsuite.tar` to table\_7 directory. Decompressed size is ~35GB.

## Set up environment

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

## XDA(~1h)

**Steps to reproduce results in Usenix paper Table 3:**

### set up environment of XDA

```console
git clone https://github.com/CUMLSec/XDA XDA_repo
conda create -n xda python=3.7 numpy scipy scikit-learn colorama
conda activate xda
conda install pytorch torchvision torchaudio cudatoolkit=11.0 -c pytorch
pip install --editable .
```

We prepared our finturned models [here](https://drive.google.com/file/d/1Y4cSe-ggywbYHcpAS9y_Dot-K7q49bdK/view?usp=sharing). Decompress and put them into `XDA_repo/checkpoints/`. Download `data-bin` [here](https://drive.google.com/file/d/1F1k5z2dPcyCMP6bUuB7vrxsDZDH6ueC2/view?usp=sharing) and put them into `XDA_repo/data-bin`.

```console
cp xda/eval_pair_inst_bound.py XDA_repo/scripts/play
cp xda/*.sh XDA_repo
cp -r xda/XDAInstTest/ XDA_repo
cd XDA_repo
```

### run

```console
bash run_oracle.sh
bash run_elfmap.sh
```

### check the result

```console
bash calculate_oracle.sh
bash calculate_elfmap.sh
```

## Performance of Dyninst on Complex Constructs(~40mins)

**Steps to reproduce results in Usenix paper Table 4:**

The result of `Manual` in Table 4 is direct from paper [Binary Code is Not Easy](http://www.paradyn.org/papers/Meng15Parsing.pdf) Table 3.

The result of `Oracle` in `Tail Call` column is direct paper [sok](https://arxiv.org/pdf/2007.14266.pdf) Table XIII.

To reproduce the result of `Oracle` in `Embeded`(Column 3, Row 3 and Column 5, Row 3):

```console
# compare dyninst with oracle on embeded instructions
bash ../script/run_comp_inst_openssl.sh -d x86_dataset/openssl-1.1.0l_execs -s ../compare/compareInstsX86.py -p "BlockDyninst932" -o result/insts_openssl/dyninst -g "gtBlock"
pushd $PWD && cd result/insts_openssl/dyninst
# collect results
grep "Recall" -r . | awk '{sum += $2; cnt += 1} END {print sum/cnt}'
grep "Precision" -r . | awk '{sum += $2; cnt += 1} END {print sum/cnt}'
popd
```
As we have `Precision` and `Recall`, F1-Score is calculated by `2*Precision*Recall/(Precision + Recall)`

To reproduce the result of `Oracle` in `JMPTBL`:

```console
# compare dyninst with oracle on jump tables
bash ../script/run_comp_inst_no_O1.sh -d x86_dataset/linux -s ../compare/compareJmpTableX86.py -p "BlockDyninst932" -o result/jmptbl/dyninst
pushd $PWD && cd result/jmptbl/dyninst
grep "Recall" -r . | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
grep "Precision" -r . | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
popd
```
As we have `Precision` and `Recall`, F1-Score is calcualted by `2*Precision*Recall/(Precision + Recall)`

## Performance of ZAFL on Instruction Recovery(~1h)

**Steps to reproduce results in Usenix paper Table 5:**

```console
# compare zafl with oracleGT
bash ../script/run_comp_inst_zafl.sh -d x86_dataset/linux -s ../compare/compareInstsX86.py -p "ridaInst" -g "gtBlock" -o result/insns/oracle/zafl
# compare zafl with objdump with sym; This could run parallelly
bash ../script/run_comp_inst_zafl.sh -d x86_dataset/linux -s ../compare/compareInstsX86.py -p "ridaInst" -g "objdumpBB" -o result/insns/objdump_syms/zafl
# compare zafl with objdump without sym; This could run parallelly
bash ../script/run_comp_inst_zafl_strip.sh -d x86_dataset/linux -s ../compare/compareInstsX86.py -p "ridaInst" -o result/insns/objdump_no_syms/zafl

# check the results.
bash collect_table_5.sh
```

## Distribution of precision of IDA(~20mins)

**Steps to reproduce results in Usenix paper Figure 2:**

```console
bash ../script/run_comp_inst_ida.sh -d x86_dataset/linux -s ../compare/compareJmpTableX86.py -p "BlockIda" -o result/jmptbl/ida
grep "Precision" -r result/jmptbl/ida | grep -v O1 > /tmp/ida_precision.log
python3 write_csv.py /tmp/ida_precision.log ./ida_pre.log  "Precision"
# need to install pandas,matplotlib and seaborn: pip3 install pandas matplotlib seaborn
# the result is stored into ./ida_pre_distribution.pdf
python3 plot_violin_seaborn_jmptbl_ida.py ./ida_pre.log ./ida_pre_distribution.pdf
```

## Accuracy of popular disassemblers on recovering instructions(~20mins)

**Steps to reproduce results in Usenix paper Figure 3:**

```console
# scripts to compare populer disassemblers with oracle
bash run_figure_3.sh
bash collect_figure_3.sh
```

## Accuracy of popular disassemblers on recovering jump tables from glibc(~10mins)

**Steps to reproduce results in Usenix paper Figure 5:**

```console
# scripts to compare popular disassemblers with oracle
bash run_figure_5.sh
bash collect_figure_5.sh
```

## Compare result of arm and mips disassemblers result (~3h)

**Steps to reproduce results in Usenix paper Table 7:**

### run

```console
cd table_7
tar -xvf testsuites.tar.gz
bash run_table_7.sh
```

And the compare result will be saved in table_7/res.log

## ORACLEGT v.s. Compilation Metadata (~20mins)

**Steps to reproduce results in Usenix paper Table 6:**

```console
# compare compilation metadata with oracle
bash ../script/run_comp_elfmap_gt.sh -d ./x86_dataset/linux/ -s ../compare/compareInstsX86.py -p "elfMapInst" -o result/insns/elfmap
bash collect_table_6.sh
```

## How to build new testsuite

In this section, we give an example that explains how to use our toolchains to build new testsuite with our toolchains and compare disassembler with our ground truth. We provide five docker images for [x86-x64](https://hub.docker.com/r/bin2415/x86_gt), [arm32](https://hub.docker.com/r/z472421519/arm32_gt),
[aarch64](https://hub.docker.com/r/z472421519/aarch64_gt), [mipsle32](https://hub.docker.com/r/z472421519/mips32_gt), and [mipsle64](https://hub.docker.com/r/z472421519/mips64_gt).

At the begining, we have some dependencies of deploying the toolchiains:

```console
# install docker firstly
$ curl -fsSL https://get.docker.com/ | sudo sh
$ sudo usermod -aG docker [user_id]

# install qemu
sudo apt-get install qemu binfmt-support qemu-user-static
```

### Build coretuils

Here is the example that use our arm32 toolchain to cross compile coreutils:

```console
## pull the docker image
$ docker pull z472421519/arm32_gt

$ docker image ls
REPOSITORY                   TAG        IMAGE ID       CREATED         SIZE
z472421519/arm32_gt          latest     beb7bba8d960   7 hours ago     5.11GB

$ docker run --rm -it -v $PWD:/opt/shared z472421519/arm32_gt /bin/bash

## insider docker
## configure CC, CXX, CFLAGS and CXXFLAGS
root@32380fe55c2a:/gt_arm32# source gcc32_arm.rc
root@32380fe55c2a:/gt_arm32# export CFLAGS="-O2 $CFLAGS" && export CXXFLAGS="-O2 $CXXFLAGS"
root@32380fe55c2a:/gt_arm32# cd /opt/shared
## download coreutils
root@32380fe55c2a:/opt/shared# wget -c https://mirror.powerfly.ca/gnu/coreutils/coreutils-8.30.tar.xz && tar -xvf coreutils-8.30.tar.xz && cd coreutils-8.30
root@32380fe55c2a:/opt/shared/coreutils-8.30# mkdir build_gcc_O2 && cd build_gcc_O2
root@32380fe55c2a:/opt/shared/coreutils-8.30/build_gcc_O2# export FORCE_UNSAFE_CONFIGURE=1 && ../configure --prefix=$PWD
root@32380fe55c2a:/opt/shared/coreutils-8.30/build_gcc_O2# make -j && make install
## The compiled binary is installed in /opt/shared/coreutils-8.30/build_gcc_O2/bin
```

### Extract ground truth

```console
## outside docker. suppose we are currently in `artifact_eval` directory, and the built binaries is in `./coreutils-8.30/build_gcc_O2/bin`
## we want to extract ground truth of `./coreutils-8.30/build_gcc_O2/bin`
bash ../script/run_extract_linux.sh -d ./build_gcc_O2/bin/ls -s ../extract_gt/extractBB.py

## the extracted ground truth is `./coreutils-8.30/build_gcc_O2/bin/gtBlock_ls.pb`
```

### Compare with disassembler

Here, we compare angr with our ground truth. The steps of extracting disassembly result of angr is shown as following:

```console
# install angr
pip3 install angr

# strip targeted binary: ls
cp ./coreutils-8.30/build_gcc_O2/bin/ls ./coreutils-8.30/build_gcc_O2/bin/ls.strip && strip ./coreutils-8.30/build_gcc_O2/bin/ls.strip
# extract disassembly result of angr
python3 ../disassemblers/angr/angrBlocks.py -b ./coreutils-8.30/build_gcc_O2/bin/ls.strip -o ./coreutils-8.30/build_gcc_O2/bin/BlockAngr_ls.pb
```

#### Compare instruction

```console
python3 ../compare/compareInstsArmMips.py -b ./build_gcc_O2/bin/ls -c ./build_gcc_O2/bin/BlockAngr_ls.pb -g ./build_gcc_O2/bin/gtBlock_ls.pb

# the result is shown:
...
[Result]:The total instruction number is 17558
[Result]:Instruction false positive number is 68, rate is 0.003873
[Result]:Instruction false negative number is 5, rate is 0.000285
[Result]:Padding byte instructions number is 5, rate is 0.000284
[Result]:Precision 0.996142
```

#### Compare Function

```console
python3 ../compare/compareFuncsArmMips.py -b ./build_gcc_O2/bin/ls -c ./build_gcc_O2/bin/BlockAngr_ls.pb -g ./build_gcc_O2/bin/gtBlock_ls.pb

# the result is shown:
...
[Result]:The total Functions in ground truth is 288
[Result]:The total Functions in compared is 329
[Result]:False positive number is 55
[Result]:False negative number is 17
[Result]:Precision 0.832827
[Result]:Recall 0.951389
```

#### Compare Jump Table

```console
python3 ../compare/compareJmpTableArmMips.py -b ./build_gcc_O2/bin/ls -c ./build_gcc_O2/bin/BlockAngr_ls.pb -g ./build_gcc_O2/bin/gtBlock_ls.pb

# the result is shown:
...
[Result]:The total jump table in ground truth is 19
[Result]:The total jump table in compared is 128
[Result]:False negative number is 0
[Result]:False positive number is 109
[Result]:Wrong successors number is 19
[Result]: Recall: 1.000000
[Result]: Precision: 0.148438
```
