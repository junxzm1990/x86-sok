We provide large-scale dataset built by our toolchains for x86/x64, arm32/mthumb/aarch64 and mips32/mips64. To reproduce the result in our Usenix paper easily, we also provide corresponding scripts.

## Download datasets
 - [x86 dataset](https://zenodo.org/record/6566082/files/x86_dataset.tar.xz?download=1). Decompressed size is ~56GB.
 - [mips arm dataset](https://zenodo.org/record/6566082/files/arm_mips_dataset.tar.gz?download=1). Move the `testsuite.tar` to table\_7 directory. Decompressed size is ~35GB.

## Set up environment

```
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

## Byteweight(~40mins)

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

## XDA(~1h)

**Steps to reproduce results in Usenix paper Table 3:**

### set up environment of XDA

```
git clone https://github.com/CUMLSec/XDA XDA_repo
conda create -n xda python=3.7 numpy scipy scikit-learn colorama
conda activate xda
conda install pytorch torchvision torchaudio cudatoolkit=11.0 -c pytorch
pip install --editable .
```

We prepared our finturned models [here](https://drive.google.com/file/d/1Y4cSe-ggywbYHcpAS9y_Dot-K7q49bdK/view?usp=sharing). Decompress and put them into `XDA_repo/checkpoints/`. Download `data-bin` [here](https://drive.google.com/file/d/1F1k5z2dPcyCMP6bUuB7vrxsDZDH6ueC2/view?usp=sharing) and put them into `XDA_repo/data-bin`.

```
cp xda/eval_pair_inst_bound.py XDA_repo/scripts/play
cp xda/*.sh XDA_repo
cp -r xda/XDAInstTest/ XDA_repo
cd XDA_repo
```

### run

```
bash run_oracle.sh
bash run_elfmap.sh
```

### check the result

```
bash calculate_oracle.sh
bash calculate_elfmap.sh
```

## Performance of Dyninst on Complex Constructs(~40mins)

**Steps to reproduce results in Usenix paper Table 4:**

The result of `Manual` in Table 4 is direct from paper [Binary Code is Not Easy](http://www.paradyn.org/papers/Meng15Parsing.pdf) Table 3.

The result of `Oracle` in `Tail Call` column is direct paper [sok](https://arxiv.org/pdf/2007.14266.pdf) Table XIII.

To reproduce the result of `Oracle` in `Embeded`:

```
# compare dyninst with oracle
bash ../script/run_comp_inst_openssl.sh -d x86_dataset/openssl-1.1.0l_execs -s ../compare/compareInstsX86.py -p "BlockDyninst932" -o result/insts_openssl/dyninst
pushd $PWD && cd result/insts_openssl/dyninst
# collect results
grep "Recall" -r . | awk '{sum += $2; cnt += 1} END {print sum/cnt}'
grep "Precision" -r . | awk '{sum += $2; cnt += 1} END {print sum/cnt}'
popd
```
As we have `Precision` and `Recall`, F1-Score is calculated by `2*Precision*Recall/(Precision + Recall)`

To reproduce the result of `Oracle` in `JMPTBL`:

```
# compare dyninst with oracle
bash ../script/run_comp_inst_no_O1.sh -d x86_dataset/linux -s ../compare/compareJmpTableX86.py -p "BlockDyninst932" -o result/jmptbl/dyninst
pushd $PWD && cd result/jmptbl/dyninst
grep "Recall" -r . | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
grep "Precision" -r . | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
popd
```
As we have `Precision` and `Recall`, F1-Score is calcualted by `2*Precision*Recall/(Precision + Recall)`

## Performance of ZAFL on Instruction Recovery(~1h)

**Steps to reproduce results in Usenix paper Table 5:**

```
# compare zafl with oracleGT
bash ../script/run_comp_inst_zafl.sh -d x86_dataset/linux -s ../compare/compareInstX86.py -p "ridaInst" -g "gtBlock" -o result/insns/oracle/zafl
# compare zafl with objdump with sym; This could run parallelly
bash ../script/run_comp_inst_zafl.sh -d x86_dataset/linux -s ../compare/compareInstX86.py -p "ridaInst" -g "objdumpBB" -o result/insns/objdump_syms/zafl
# compare zafl with objdump without sym; This could run parallelly
bash ../script/run_comp_inst_zafl_strip.sh -d x86_dataset/linux -s ../compare/compareInstX86.py -p "ridaInst" -o result/insns/objdump_no_syms/zafl

# check the results. For example,
# the number of false positives of O0:
grep "False Pos"  -r result/insns/objdump_no_syms/zafl | grep O0 | wc -l
# the number of false negatives of O0:
grep "False Neg"  -r result/insns/objdump_no_syms/zafl | grep O0 | wc -l
```

## Distribution of precision of IDA(~20mins)

**Steps to reproduce results in Usenix paper Figure 2:**

```
bash ../script/run_comp_inst_ida.sh -d x86_dataset/linux -s ../compare/compareJmpTableX86.py -p "BlockIda" -o result/jmptbl/ida
grep "Precision" -r result/jmptbl/ida > /tmp/ida_precision.log
python3 write_csv.py /tmp/ida_precision.log ./ida_pre.log  "Precision"
# need to install pandas,matplotlib and seaborn: pip3 install pandas matplotlib seaborn
# the result is stored into ./ida_pre_distribution.pdf
python3 plot_violin_seaborn_jmptbl_ida.py ./ida_pre.log ./ida_pre_distribution.pdf
```

## Accuracy of popular disassemblers on recovering instructions(~20mins)

**Steps to reproduce results in Usenix paper Figure 3:**

```
# scripts to compare populer disassemblers with oracle
bash run_figure_3.sh
bash collect_figure_3.sh
```

## Accuracy of popular disassemblers on recovering jump tables from glibc(~10mins)

**Steps to reproduce results in Usenix paper Figure 5:**

```
# scripts to compare popular disassemblers with oracle
bash run_figure_5.sh
bash collect_figure_5.sh
```

## Compare result of arm and mips disassemblers result (~3h)

**Steps to reproduce results in Usenix paper Table 7:**

### run

```bash
cd table_7
tar -xvf testsuites.tar.gz
bash run_table_7.sh
```

And the compare result will be saved in table_7/res.log

## ORACLEGT v.s. Compilation Metadata (~20mins)

**Steps to reproduce results in Usenix paper Table 6:**

```
# compare compilation metadata with oracle
bash ../script/run_comp_elfmap_gt.sh -d ./x86_dataset/linux/ -s ../compare/compareInstsX86.py -p "elfMapInst" -o result/insns/elfmap
bash collect_table_6.sh
```