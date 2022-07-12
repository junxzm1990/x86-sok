We provide large-scale dataset built by our toolchains for x86/x64, arm32/mthumb/aarch64 and mips32/mips64. To reproduce the result in our Usenix paper easily, we also provide corresponding scripts.

## Download datasets
 - [x86 dataset](https://zenodo.org/record/6566082/files/x86_dataset.tar.xz?download=1). Decompressed size is ~56GB.
 - [mips arm dataset](https://zenodo.org/record/6566082/files/arm_mips_dataset.tar.gz?download=1). Move the `testsuite.tar` to table\_7 directory. Decompressed size is ~35GB.

## Set up environment

There are two ways to setting up the environments: 1) in your machine(we have tested in Ubuntu 20.04) or 2) Docker

### Ubuntu 20.04

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

### Docker

```console
docker pull bin2415/py_gt
```

## Byteweight(~40mins)

### Reproduction of trained model

> Attention: the decompressed space is ~130GB.
**Steps to reproduce results in Table 2:**

We prepared a vm image of Virtualbox. The trained model is in the vm. The steps to reproduce is:

- Download the byteweight image: [image](https://drive.google.com/file/d/1Cv4Yf8f2_eXOvMtxFg00l3DGXD2jaLPb/view?usp=sharing).

- Import the image in Virtualbox.

```
# The username and password of the vm are: byteweight:password
# mount the disk
sudo mount /dev/sdb /work
```

- Test the model of byteweight:

```
cd ~/ByteWeight/code/script
## collect the Recall and Precision of Symbol information(Row 2 and Row 4 in the table)
bash run_compare_symbol.sh && bash run_symbol.sh
## collect the Recall and Precision of Oracle(Row 3 and Row 5 in the table)
bash run_compare_oracle.sh && bash run_oracle.sh
```

### Train a new model

Here we use `coreutils` of our x86/x64 dataset to train the ByteWeight model as the example.

#### Preprocess

```console
## bash byteweight/preprocess.sh <path of coreutils> <dst path of preprocessed dataset>
bash byteweight/preprocess.sh ./x86_dataset/linux/utils/coreutils ./result/byteweight/dataset
```

Two folders(oracle and symbol) are generated in `result/byteweight/dataset`

#### Train

Copy the two folders into virtual machine and run following instructions.

```
$ cd ~/ByteWeight/code/script
# train oracle dataset
$ bash experiment_lin.sh <path of dataset/oracle>
# train symbol dataset
$ bash experiment_lin.sh <path of dataset/symbol>
```

#### Test

Overwrite the `dataset/symbol/binary` with `dataset/oracle/binary` at first.

```console
cp dataset/oracle/binary/* dataset/symbol/binary/*
```

And refer to the `~/ByteWeight/code/script/run_compare_oracle.sh` test the trained model.


## XDA(~1h)

**Steps to reproduce results in Usenix paper Table 3:**

### set up environment of XDA

```console
git clone https://github.com/CUMLSec/XDA XDA_repo
# install conda
wget -c https://repo.anaconda.com/archive/Anaconda3-2022.05-Linux-x86_64.sh
bash ./Anaconda3-2022.05-Linux-x86_64.sh
# environment setup
conda create -n xda python=3.7 numpy scipy scikit-learn colorama
conda activate xda
conda install pytorch torchvision torchaudio cudatoolkit=11.0 -c pytorch
cd XDA_repo && pip install --editable .
```

We prepared our finturned models [here](https://drive.google.com/file/d/1Y4cSe-ggywbYHcpAS9y_Dot-K7q49bdK/view?usp=sharing). Decompress and put them into `XDA_repo/checkpoints/`. Download `data-bin` [here](https://drive.google.com/file/d/1F1k5z2dPcyCMP6bUuB7vrxsDZDH6ueC2/view?usp=sharing) and put them into `XDA_repo/data-bin`.

```console
cp xda/eval_pair_inst_bound.py XDA_repo/scripts/play
cp xda/*.sh XDA_repo
cp -r xda/XDAInstTest/ XDA_repo
cd XDA_repo
```

### Reproduction of Trained Model

#### run

```console
bash run_oracle.sh
bash run_elfmap.sh
```

#### check the result

```console
# get the result of `Oracle` line of table 3
bash calculate_oracle.sh

# get the result of `Debug` line of table 3
bash calculate_elfmap.sh
```


### Train a New Model

If you want to train the a new model, we also provide following instructions.

#### Preprocess the dataset

Here we use `coreutils` of our x86/x64 dataset to train the XDA model as the example.

```console
## bash xda/runOracleGTXDA.sh -d <dataset> -o <the path to save the preprocessed data> -s xda/OracleGTXDA.py -p <prefix of ground truth>
## here, we use the `coreutils` as example
## convert ground truth of `Oracle`
$ bash xda/runOracleGTXDA.sh -d ./x86_dataset/linux/utils/coreutils -s xda/OracleGTXDA.py -p "gtBlock" -o ./result/xda/preprocess/oracleGT
## convert ground truth of `elfMap`
$ bash xda/runOracleGTXDA.sh -d ./x86_dataset/linux/utils/coreutils -s xda/OracleGTXDA.py -p "elfMapInst" -o ./result/xda/preprocess/elfmapGT
```

Select the dataset of training randomly.

```console
ls ./result/xda/preprocess/oracleGT > /tmp/dataset.list
# select 9/10 of dataset to train
shuf -n 567 /tmp/dataset.list > result/xda/train64.list
```

Collect the training dataset and validing dataset into files like [them](https://github.com/CUMLSec/XDA/tree/main/data-src/funcbound).

```console
## training dataset of Oracle ground truth
## python3 xda/preprocess.py -t <path to train64.list> -i <folder of preprocessed data> -o <path to data-src inside xda_repo>
$ mkdir -p XDA_repo/data-src/instbound_oracle
$ python3 xda/preprocess.py -t result/xda/train64.list -i ./result/xda/preprocess/oracleGT -o XDA_repo/data-src/instbound_oracle/train

## training dataset of elfmap ground truth
$ mkdir -p XDA_repo/data-src/instbound_elfmap
$ python3 xda/preprocess.py -t result/xda/train64.list -i ./result/xda/preprocess/elfmapGT -o XDA_repo/data-src/instbound_elfmap/train

## validing dataset of Oracle ground truth
$ python3 xda/preprocess.py -t result/xda/train64.list -i ./result/xda/preprocess/oracleGT -o XDA_repo/data-src/instbound_oracle/valid -v

## validing dataset of elfmap ground truth
$ python3 xda/preprocess.py -t result/xda/train64.list -i ./result/xda/preprocess/oracleGT -o XDA_repo/data-src/instbound_elfmap/valid -v
```

Preprocess the data:

```console
$ conda activate xda
$ cp xda/preprocess_scripts/* xda_repo/scripts/finetune
$ cd xda_repo
$ bash scripts/finetune/preprocess_oracle.sh
$ bash scripts/finetune/preprocess_elfmap.sh
```

#### Training

As we only train the finetuned models, we reused the pretrained model of XDA. Please download the pretrained model [here](https://drive.google.com/file/d/1PLoRMYKUnsa2NJbmpOOkOeeQjjHm3sy4/view?usp=sharing) and put it in `XDA_repo/checkpoints/pretrain_all/`.

```console
# train the model of oracle ground truth
bash scripts/finetune/finetune_inst_oracle.sh

# train the model of elfmap ground truth
bash scripts/finetune/finetune_inst_elfmap.sh
```


#### Testing

Please refer this [step](https://github.com/junxzm1990/x86-sok/tree/master/artifact_eval#run)

## Performance of Dyninst on Complex Constructs(~40mins)

**Steps to reproduce results in Usenix paper Table 4:**

The result of `Manual` in Table 4 is direct from paper [Binary Code is Not Easy](http://www.paradyn.org/papers/Meng15Parsing.pdf) Table 3.

The result of `Oracle` in `Tail Call` column 5(Column 5, Row 3 and Column 5, Row 5) is direct paper [sok](https://arxiv.org/pdf/2007.14266.pdf) Table XIII.

To reproduce the result of `Oracle` in `Embeded`(Column 3, Row 3 and Column 3, Row 5):

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

To reproduce the result of `Oracle` in `JMPTBL`(Column 4, Row 3 and Column 4 and Row 5):

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

## Collect Results of Disassemblers and Extract Ground Truth(Optional)

We put the results of binary disassemblers and ground truth into dataset. So this step is optional and it takes **several days** to process.

### Collect Results of Disassemblers

We built popular open-source disassemblers(radare2, angr, bap, ghidra, dyninst, and objdump) in docker image `bin2415/py_gt`.

```console
$ docker pull bin2415/py_gt
$ docker run -it --privileged --name py_gt -v $PWD/x86-sok:/opt bin2415/py_gt /bin/bash

## prepare striped binaries
/opt/artifact_eval$ bash ../script/extract_strip.sh ./x86_dataset
/opt/artifact_eval$ bash ../script/extract_strip.sh ./table_7/testsuite
```

#### Radare2

The steps of extracting results of radare2:

```console
# x86/x64 dataset
/opt/artifact_eval$ bash ../script/run_disassembler.sh -d ./x86_dataset/linux/ -s ../disassemblers/radare/radareBB.py -p "BlockRadare"

# arm/mips dataset
/opt/artifact_eval$ bash ../script/run_disassembler.sh -d ./table_7/testsuite/ -s ../disassemblers/radare/radareBB.py -p "BlockRadare"
```

#### Angr

The steps of extracting results of angr:

```console
/opt/artifact_eval$ conda activate angr

# x86/x64 dataset
/opt/artifact_eval$ bash ../script/run_disassembler.sh -d ./x86_dataset/linux/ -s ../disassemblers/angr/angrBlocks.py -p "BlockAngr"

# x86/x64 dataset
/opt/artifact_eval$ bash ../script/run_disassembler.sh -d ./table_7/testsuite/ -s ../disassemblers/angr/angrBlocks.py -p "BlockAngr"

conda deactivate
```

#### Bap

The steps of extracting results of bap:

```console
/opt/artifact_eval$ opam switch 4.12.1
/opt/artifact_eval$ eval $(opam env)

# x86/x64 dataset
/opt/artifact_eval$ bash ../script/run_disassembler.sh -d ./x86_dataset/linux/ -s ../disassemblers/bap/bapBB.py -p "BlockBap"

# arm/mips dataset
/opt/artifact_eval$ bash ../script/run_disassembler.sh -d ./table_7/testsuite/ -s ../disassemblers/bap/bapBB.py -p "BlockBap"
```

#### Ghidra

The steps of extracting results of ghidra:

```console
# x86/x64 dataset
/opt/artifact_eval$ bash ../script/run_disassembler_ghidra.sh -d ./x86_dataset/linux/ -p "BlockGhidra"

# arm/mips dataset
/opt/artifact_eval$ bash ../script/run_disassembler_ghidra.sh -d ./table_7/testsuite/ -p "BlockGhidra"
```

#### Dyninst

The steps of extracting results of dyninst:

```console
/opt/artifact_eval$ pushd $PWD && cd ../disassemblers/dyninst && make && popd

# x86/x64 dataset
/opt/artifact_eval$ bash ../script/run_disassembler_dyninst.sh -d ./x86_dataset/linux/ -s ../disassemblers/dyninst/dyninstBlocks -p "BlockDyninst932"

# arm/mips dataset
/opt/artifact_eval$ bash ../script/run_disassembler_dyninst.sh -d ./table_7/testsuite/ -s ../disassemblers/dyninst/dyninstBlocks -p "BlockDyninst932"
```

#### Objdump

The steps of extracting results of objdump:

```console
# x86/x64
/opt/artifact_eval$ bash ../script/run_disassembler.sh -d ./x86_dataset/linux/ -s ../disassemblers/objdump/objdumpBB.py -p "BlockObjdump"

# arm/mips
/opt/artifact_eval$ bash ../script/run_disassembler.sh -d ./table_7/testsuite/ -s ../disassemblers/objdump/objdumpBB.py -p "BlockObjdump"
```

#### IDA Pro

Ida pro is a commecial software, so the binary is not available. The steps of extracting results of ida:

```console
# x86/x64
/opt/artifact_eval$ bash ../script/run_disassembler.sh -d ./x86_dataset/linux/ -s ../disassemblers/ida/runIDAScript.py -p "BlockIda"

# arm/mips
/opt/artifact_eval$ bash ../script/run_disassembler.sh -d ./table_7/testsuite/ -s ../disassemblers/ida/runIDAScript.py -p "BlockIda"
```

#### BinaryNinja

BinaryNinja is a commecial software, so the binary is not available. The steps of extracting results of binaryninja:

```console
# x86/x64
/opt/artifact_eval$ bash ../script/run_disassembler.sh -d ./x86_dataset/linux/ -s ../disassemblers/ninja/ninjaBB.py -p "BlockIda"

# arm/mips
/opt/artifact_eval$ bash ../script/run_disassembler.sh -d ./table_7/testsuite/ -s ../disassemblers/ninja/ninjaBB.py -p "BlockIda"
```

### Extract Ground Truth

```console
# x86/x64
/opt/artifact_eval$ bash ../script/run_extract_linux.sh -d ./x86_dataset/linux/ -s ../extract_gt/extractBB.py -p "gtBlock"

# arm/mips
/opt/artifact_eval$ bash ../script/run_extract_linux.sh -d ./table_7/testsuite -s ../extract_gt/extractBB.py -p "gtBlock"
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
# it is fine for the following warning message
WARNING: The requested image's platform (linux/arm/v7) does not match the detected host platform (linux/amd64) and no specific platform was requested

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

Start a `py_gt` docker container, suppose we are in the `artifact_eval` folder.

```console
docker run -it --rm -v $PWD/../:/opt/shared bin2415/py_gt /bin/bash
```

```console
## insider py_gt docker. suppose we are currently in `/opt/shared/artifact_eval` directory, and the built binaries is in `./coreutils-8.30/build_gcc_O2/bin`
## we want to extract ground truth of `./coreutils-8.30/build_gcc_O2/bin`
/opt/shared/artifact_eval: bash ../script/run_extract_linux.sh -d ./coreutils-8.30/build_gcc_O2/bin/ls -s ../extract_gt/extractBB.py

## the extracted ground truth is `./coreutils-8.30/build_gcc_O2/bin/gtBlock_ls.pb`
```

### Compare with disassembler

Here, we compare radare with our ground truth. The steps of extracting disassembly result of radare2 are shown as following:

```console
# inside py_gt docker:

# strip targeted binary: ls
cp ./coreutils-8.30/build_gcc_O2/bin/ls ./coreutils-8.30/build_gcc_O2/bin/ls.strip && strip ./coreutils-8.30/build_gcc_O2/bin/ls.strip
# extract disassembly result of radare2
python3 ../disassemblers/radare/radareBB.py -b ./coreutils-8.30/build_gcc_O2/bin/ls.strip -o ./coreutils-8.30/build_gcc_O2/bin/BlockRadare_ls.pb
```

#### Compare instruction

```console
python3 ../compare/compareInstsArmMips.py -b ./coreutils-8.30/build_gcc_O2/bin/ls -c ./coreutils-8.30/build_gcc_O2/bin/BlockRadare_ls.pb -g ./coreutils-8.30/build_gcc_O2/bin/gtBlock_ls.pb

# the result is shown:
...
[Result]:The total instruction number is 17558
[Result]:Instruction false positive number is 278, rate is 0.015833
[Result]:Instruction false negative number is 3630, rate is 0.206743
[Result]:Padding byte instructions number is 0, rate is 0.000000
[Result]:Precision 0.980431
[Result]:Recall 0.793257
```

#### Compare Function

```console
python3 ../compare/compareFuncsArmMips.py -b ./coreutils-8.30/build_gcc_O2/bin/ls -c ./coreutils-8.30/build_gcc_O2/bin/BlockRadare_ls.pb -g ./coreutils-8.30/build_gcc_O2/bin/gtBlock_ls.pb

# the result is shown:
...
[Result]:The total Functions in ground truth is 288
[Result]:The total Functions in compared is 195
[Result]:False positive number is 23
[Result]:False negative number is 116
[Result]:Precision 0.882051
[Result]:Recall 0.597222
```

#### Compare Jump Table

```console
python3 ../compare/compareJmpTableArmMips.py -b ./coreutils-8.30/build_gcc_O2/bin/ls -c ./coreutils-8.30/build_gcc_O2/bin/BlockRadare_ls.pb -g ./coreutils-8.30/build_gcc_O2/bin/gtBlock_ls.pb

# the result is shown:
...
[Result]:The total jump table in ground truth is 18
[Result]:The total jump table in compared is 24
[Result]:False negative number is 0
[Result]:False positive number is 6
[Result]:Wrong successors number is 17
[Result]: Recall: 0.055556
[Result]: Precision: 0.041667
```
