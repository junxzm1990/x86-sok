dataset_path="./x86_dataset"
if [[ ! -d $dataset_path ]]; then
	echo "Please give the path of x86_dataset: dataset_path=<path of x86_dataset>"
	exit -1
fi
bash ../script/run_comp_inst_openssl.sh -d $dataset_path/openssl-1.1.0l_execs -s ../compare/compareInstsX86.py -p "BlockObjdump" -g "gtBlock" -o result/insns/openssl/oracle/objdump &
bash ../script/run_comp_inst_openssl.sh -d $dataset_path/openssl-1.1.0l_execs -s ../compare/compareInstsX86.py -p "BlockDyninst932" -g "gtBlock" -o result/insns/openssl/oracle/dyninst 
bash ../script/run_comp_inst_openssl.sh -d $dataset_path/openssl-1.1.0l_execs -s ../compare/compareInstsX86.py -p "BlockGhidra" -g "gtBlock" -o result/insns/openssl/oracle/ghidra &
bash ../script/run_comp_inst_openssl.sh -d $dataset_path/openssl-1.1.0l_execs -s ../compare/compareInstsX86.py -p "BlockAngr" -g "gtBlock" -o result/insns/openssl/oracle/angr
bash ../script/run_comp_inst_openssl.sh -d $dataset_path/openssl-1.1.0l_execs -s ../compare/compareInstsX86.py -p "BlockNinja" -g "gtBlock" -o result/insns/openssl/oracle/ninja &
bash ../script/run_comp_inst_openssl.sh -d $dataset_path/openssl-1.1.0l_execs -s ../compare/compareInstsX86.py -p "BlockBap" -g "gtBlock" -o result/insns/openssl/oracle/bap
bash ../script/run_comp_inst_openssl.sh -d $dataset_path/openssl-1.1.0l_execs -s ../compare/compareInstsX86.py -p "BlockRadare" -g "gtBlock" -o result/insns/openssl/oracle/radare &
bash ../script/run_comp_inst_openssl.sh -d $dataset_path/openssl-1.1.0l_execs -s ../compare/compareInstsX86.py -p "InstIda" -g "gtBlock" -o result/insns/openssl/oracle/ida
wait

bash ../script/run_comp_inst_openssl.sh -d $dataset_path/openssl-1.1.0l_execs -s ../compare/compareInstsX86.py -p "BlockObjdump" -g "BlockObjdump" -o result/insns/openssl/objdump/objdump &
bash ../script/run_comp_inst_openssl.sh -d $dataset_path/openssl-1.1.0l_execs -s ../compare/compareInstsX86.py -p "BlockDyninst932" -g "BlockObjdump" -o result/insns/openssl/objdump/dyninst
bash ../script/run_comp_inst_openssl.sh -d $dataset_path/openssl-1.1.0l_execs -s ../compare/compareInstsX86.py -p "BlockGhidra" -g "BlockObjdump" -o result/insns/openssl/objdump/ghidra &
bash ../script/run_comp_inst_openssl.sh -d $dataset_path/openssl-1.1.0l_execs -s ../compare/compareInstsX86.py -p "BlockAngr" -g "BlockObjdump" -o result/insns/openssl/objdump/angr 
bash ../script/run_comp_inst_openssl.sh -d $dataset_path/openssl-1.1.0l_execs -s ../compare/compareInstsX86.py -p "BlockNinja" -g "BlockObjdump" -o result/insns/openssl/objdump/ninja &
bash ../script/run_comp_inst_openssl.sh -d $dataset_path/openssl-1.1.0l_execs -s ../compare/compareInstsX86.py -p "BlockBap" -g "BlockObjdump" -o result/insns/openssl/objdump/bap 
bash ../script/run_comp_inst_openssl.sh -d $dataset_path/openssl-1.1.0l_execs -s ../compare/compareInstsX86.py -p "BlockRadare" -g "BlockObjdump" -o result/insns/openssl/objdump/radare &
bash ../script/run_comp_inst_openssl.sh -d $dataset_path/openssl-1.1.0l_execs -s ../compare/compareInstsX86.py -p "InstIda" -g "BlockObjdump" -o result/insns/openssl/objdump/ida
wait

bash ../script/run_comp_inst_openssl.sh -d $dataset_path/openssl-1.1.0l_execs -s ../compare/compareInstsX86.py -p "BlockObjdump" -g "InstElfmap" -o result/insns/openssl/debuginfo/objdump &
bash ../script/run_comp_inst_openssl.sh -d $dataset_path/openssl-1.1.0l_execs -s ../compare/compareInstsX86.py -p "BlockDyninst932" -g "InstElfmap" -o result/insns/openssl/debuginfo/dyninst
bash ../script/run_comp_inst_openssl.sh -d $dataset_path/openssl-1.1.0l_execs -s ../compare/compareInstsX86.py -p "BlockGhidra" -g "InstElfmap" -o result/insns/openssl/debuginfo/ghidra &
bash ../script/run_comp_inst_openssl.sh -d $dataset_path/openssl-1.1.0l_execs -s ../compare/compareInstsX86.py -p "BlockAngr" -g "InstElfmap" -o result/insns/openssl/debuginfo/angr
bash ../script/run_comp_inst_openssl.sh -d $dataset_path/openssl-1.1.0l_execs -s ../compare/compareInstsX86.py -p "BlockNinja" -g "InstElfmap" -o result/insns/openssl/debuginfo/ninja &
bash ../script/run_comp_inst_openssl.sh -d $dataset_path/openssl-1.1.0l_execs -s ../compare/compareInstsX86.py -p "BlockBap" -g "InstElfmap" -o result/insns/openssl/debuginfo/bap
bash ../script/run_comp_inst_openssl.sh -d $dataset_path/openssl-1.1.0l_execs -s ../compare/compareInstsX86.py -p "BlockRadare" -g "InstElfmap" -o result/insns/openssl/debuginfo/radare &
bash ../script/run_comp_inst_openssl.sh -d $dataset_path/openssl-1.1.0l_execs -s ../compare/compareInstsX86.py -p "InstIda" -g "InstElfmap" -o result/insns/openssl/debuginfo/ida
wait
