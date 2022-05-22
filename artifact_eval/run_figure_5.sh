dataset_path="./x86_dataset"
bash ../script/run_comp_jmptbl_libc_ida.sh -d ${dataset_path}/linux/libs -s ../compare/compareJmpTableGt.py -p "Block-idaBlocks" -g "gtBlock" -o result/jmptbl_gt/improved_oracle/ida &
bash ../script/run_comp_jmptbl_libc.sh -d ${dataset_path}/linux/libs -s ../compare/compareJmpTableGt.py -p "BlockAngr" -g "gtBlock" -o result/jmptbl_gt/improved_oracle/angr
bash ../script/run_comp_jmptbl_libc_ninja.sh -d ${dataset_path}/linux/libs -s ../compare/compareJmpTableGt.py -p "BlockNinja" -g "gtBlock" -o result/jmptbl_gt/improved_oracle/ninja &
bash ../script/run_comp_jmptbl_libc.sh -d ${dataset_path}/linux/libs -s ../compare/compareJmpTableGt.py -p "BlockGhidra" -g "gtBlock" -o result/jmptbl_gt/improved_oracle/ghidra
bash ../script/run_comp_jmptbl_libc.sh -d ${dataset_path}/linux/libs -s ../compare/compareJmpTableGt.py -p "BlockDyninst932" -g "gtBlock" -o result/jmptbl_gt/improved_oracle/dyninst &
bash ../script/run_comp_jmptbl_libc.sh -d ${dataset_path}/linux/libs -s ../compare/compareJmpTableGt.py -p "BlockRadare" -g "gtBlock" -o result/jmptbl_gt/improved_oracle/radare
wait

bash ../script/run_comp_jmptbl_libc_ida.sh -d ${dataset_path}/linux/libs -s ../compare/compareJmpTableGt.py -p "Block-idaBlocks" -g "gtBlockNoPostAA" -o result/jmptbl_gt/original_oracle/ida &
bash ../script/run_comp_jmptbl_libc.sh -d ${dataset_path}/linux/libs -s ../compare/compareJmpTableGt.py -p "BlockAngr" -g "gtBlockNoPostAA" -o result/jmptbl_gt/original_oracle/angr
bash ../script/run_comp_jmptbl_libc_ninja.sh -d ${dataset_path}/linux/libs -s ../compare/compareJmpTableGt.py -p "BlockNinja" -g "gtBlockNoPostAA" -o result/jmptbl_gt/original_oracle/ninja &
bash ../script/run_comp_jmptbl_libc.sh -d ${dataset_path}/linux/libs -s ../compare/compareJmpTableGt.py -p "BlockGhidra" -g "gtBlockNoPostAA" -o result/jmptbl_gt/original_oracle/ghidra
bash ../script/run_comp_jmptbl_libc.sh -d ${dataset_path}/linux/libs -s ../compare/compareJmpTableGt.py -p "BlockDyninst932" -g "gtBlockNoPostAA" -o result/jmptbl_gt/original_oracle/dyninst &
bash ../script/run_comp_jmptbl_libc.sh -d ${dataset_path}/linux/libs -s ../compare/compareJmpTableGt.py -p "BlockRadare" -g "gtBlockNoPostAA" -o result/jmptbl_gt/original_oracle/radare
wait
