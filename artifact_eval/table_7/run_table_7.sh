g++ -o collect_res ./collect_res.cpp
script_path=$0
base=`dirname $script_path`
base=`realpath $base`
script_path=${base}/../../script/run_comp_inst_arm_mips.sh
ghidra_mips_script_path=${base}/../../script/run_comp_inst_mips_ghidra.sh
binary_path=${base}/testsuite/mips_executables
compare_path=${base}/../../compare
output_path=${base}/compare

#MIPS

bash ${script_path} -d ${binary_path} -p NopObjdump -s ${compare_path}/compareInstsArmMips.py -o ${output_path}/insns/mips/objdump &
bash ${script_path} -d ${binary_path} -p BlockGhidra -s ${compare_path}/compareInstsArmMips.py -o ${output_path}/insns/mips/ghidra &
bash ${script_path} -d ${binary_path} -p BlockAngr -s ${compare_path}/compareInstsArmMips.py -o ${output_path}/insns/mips/angr &
bash ${script_path} -d ${binary_path} -p BlockRadareNew -s ${compare_path}/compareInstsArmMips.py -o ${output_path}/insns/mips/radare &
bash ${script_path} -d ${binary_path} -p InstIda -s ${compare_path}/compareInstsArmMips.py -o ${output_path}/insns/mips/ida &
bash ${script_path} -d ${binary_path} -p BlockNinja -s ${compare_path}/compareInstsArmMips.py -o ${output_path}/insns/mips/ninja

bash ${script_path} -d ${binary_path} -p BlockGhidra -s ${compare_path}/compareFuncsArmMips.py -o ${output_path}/funcs/mips/ghidra &
bash ${script_path} -d ${binary_path} -p BlockAngr -s ${compare_path}/compareFuncsArmMips.py -o ${output_path}/funcs/mips/angr &
bash ${script_path} -d ${binary_path} -p BlockRadareNew -s ${compare_path}/compareFuncsArmMips.py -o ${output_path}/funcs/mips/radare &
bash ${script_path} -d ${binary_path} -p BlockIda -s ${compare_path}/compareFuncsArmMips.py -o ${output_path}/funcs/mips/ida &
bash ${script_path} -d ${binary_path} -p BlockNinja -s ${compare_path}/compareFuncsArmMips.py -o ${output_path}/funcs/mips/ninja

bash ${ghidra_mips_script_path} -d ${binary_path} -p BlockGhidraJT -i BlockGhidra  -s ${compare_path}/compareJmpTableMipsGhidra.py -o ${output_path}/jmptbl/mips/ghidra &
bash ${script_path} -d ${binary_path} -p BlockAngr -s ${compare_path}/compareJmpTableArmMips.py -o ${output_path}/jmptbl/mips/angr &
bash ${script_path} -d ${binary_path} -p BlockRadareNew -s ${compare_path}/compareJmpTableArmMips.py -o ${output_path}/jmptbl/mips/radare &
bash ${script_path} -d ${binary_path} -p BlockIda -s ${compare_path}/compareJmpTableArmMips.py -o ${output_path}/jmptbl/mips/ida &
bash ${script_path} -d ${binary_path} -p BlockNinja -s ${compare_path}/compareJmpTableArmMips.py -o ${output_path}/jmptbl/mips/ninja

# ARM32

binary_path=${base}/testsuite/arm32_executables

bash ${script_path} -d ${binary_path} -p BlockObjdump -s ${compare_path}/compareInstsArmMips.py -o ${output_path}/insns/arm32/objdump &
bash ${script_path} -d ${binary_path} -p BlockGhidra -s ${compare_path}/compareInstsArmMips.py -o ${output_path}/insns/arm32/ghidra &
bash ${script_path} -d ${binary_path} -p BlockAngr -s ${compare_path}/compareInstsArmMips.py -o ${output_path}/insns/arm32/angr &
bash ${script_path} -d ${binary_path} -p BlockRadare -s ${compare_path}/compareInstsArmMips.py -o ${output_path}/insns/arm32/radare &
bash ${script_path} -d ${binary_path} -p InstIda -s ${compare_path}/compareInstsArmMips.py -o ${output_path}/insns/arm32/ida &
bash ${script_path} -d ${binary_path} -p BlockNinja -s ${compare_path}/compareInstsArmMips.py -o ${output_path}/insns/arm32/ninja

bash ${script_path} -d ${binary_path} -p BlockGhidra -s ${compare_path}/compareFuncsArmMips.py -o ${output_path}/funcs/arm32/ghidra &
bash ${script_path} -d ${binary_path} -p BlockAngr -s ${compare_path}/compareArm32AngrFuncs.py -o ${output_path}/funcs/arm32/angr &
bash ${script_path} -d ${binary_path} -p BlockRadare -s ${compare_path}/compareFuncsArmMips.py -o ${output_path}/funcs/arm32/radare &
bash ${script_path} -d ${binary_path} -p BlockIda -s ${compare_path}/compareFuncsArmMips.py -o ${output_path}/funcs/arm32/ida &
bash ${script_path} -d ${binary_path} -p BlockNinja -s ${compare_path}/compareFuncsArmMips.py -o ${output_path}/funcs/arm32/ninja

bash ${script_path} -d ${binary_path} -p BlockGhidra -s ${compare_path}/compareJmpTableArmMips.py -o ${output_path}/jmptbl/arm32/ghidra &
bash ${script_path} -d ${binary_path} -p BlockAngr -s ${compare_path}/compareJmpTableArmMips.py -o ${output_path}/jmptbl/arm32/angr &
bash ${script_path} -d ${binary_path} -p BlockRadare -s ${compare_path}/compareJmpTableArmMips.py -o ${output_path}/jmptbl/arm32/radare &
bash ${script_path} -d ${binary_path} -p BlockIda -s ${compare_path}/compareJmpTableArmMips.py -o ${output_path}/jmptbl/arm32/ida &
bash ${script_path} -d ${binary_path} -p BlockNinja -s ${compare_path}/compareJmpTableArmMips.py -o ${output_path}/jmptbl/arm32/ninja

# THUMB

binary_path=${base}/testsuite/mthumb_executables

bash ${script_path} -d ${binary_path} -p BlockObjdump -s ${compare_path}/compareInstsArmMips.py -o ${output_path}/insns/mthumb/objdump &
bash ${script_path} -d ${binary_path} -p BlockGhidra -s ${compare_path}/compareInstsArmMips.py -o ${output_path}/insns/mthumb/ghidra &
bash ${script_path} -d ${binary_path} -p BlockAngr -s ${compare_path}/compareInstsArmMips.py -o ${output_path}/insns/mthumb/angr &
bash ${script_path} -d ${binary_path} -p BlockRadare -s ${compare_path}/compareInstsArmMips.py -o ${output_path}/insns/mthumb/radare &
bash ${script_path} -d ${binary_path} -p InstIda -s ${compare_path}/compareInstsArmMips.py -o ${output_path}/insns/mthumb/ida &
bash ${script_path} -d ${binary_path} -p BlockNinja -s ${compare_path}/compareInstsArmMips.py -o ${output_path}/insns/mthumb/ninja

bash ${script_path} -d ${binary_path} -p BlockGhidra -s ${compare_path}/compareFuncsArmMips.py -o ${output_path}/funcs/mthumb/ghidra &
bash ${script_path} -d ${binary_path} -p BlockAngr -s ${compare_path}/compareFuncsArmMips.py -o ${output_path}/funcs/mthumb/angr &
bash ${script_path} -d ${binary_path} -p BlockRadare -s ${compare_path}/compareFuncsArmMips.py -o ${output_path}/funcs/mthumb/radare &
bash ${script_path} -d ${binary_path} -p BlockIda -s ${compare_path}/compareFuncsArmMips.py -o ${output_path}/funcs/mthumb/ida &
bash ${script_path} -d ${binary_path} -p BlockNinja -s ${compare_path}/compareFuncsArmMips.py -o ${output_path}/funcs/mthumb/ninja &

bash ${script_path} -d ${binary_path} -p BlockGhidra -s ${compare_path}/compareJmpTableArmMips.py -o ${output_path}/jmptbl/mthumb/ghidra &
bash ${script_path} -d ${binary_path} -p BlockAngr -s ${compare_path}/compareJmpTableArmMips.py -o ${output_path}/jmptbl/mthumb/angr &
bash ${script_path} -d ${binary_path} -p BlockRadare -s ${compare_path}/compareJmpTableArmMips.py -o ${output_path}/jmptbl/mthumb/radare &
bash ${script_path} -d ${binary_path} -p BlockIda -s ${compare_path}/compareJmpTableArmMips.py -o ${output_path}/jmptbl/mthumb/ida &
bash ${script_path} -d ${binary_path} -p BlockNinja -s ${compare_path}/compareJmpTableArmMips.py -o ${output_path}/jmptbl/mthumb/ninja &

# AARCH64

binary_path=${base}/testsuite/aarch64_executables

bash ${script_path} -d ${binary_path} -p BlockObjdump -s ${compare_path}/compareInstsArmMips.py -o ${output_path}/insns/aarch64/objdump &
bash ${script_path} -d ${binary_path} -p BlockGhidra -s ${compare_path}/compareInstsArmMips.py -o ${output_path}/insns/aarch64/ghidra &
bash ${script_path} -d ${binary_path} -p BlockAngr -s ${compare_path}/compareInstsArmMips.py -o ${output_path}/insns/aarch64/angr &
bash ${script_path} -d ${binary_path} -p BlockRadare -s ${compare_path}/compareInstsArmMips.py -o ${output_path}/insns/aarch64/radare &
bash ${script_path} -d ${binary_path} -p InstIda -s ${compare_path}/compareInstsArmMips.py -o ${output_path}/insns/aarch64/ida &
bash ${script_path} -d ${binary_path} -p BlockNinja -s ${compare_path}/compareInstsArmMips.py -o ${output_path}/insns/aarch64/ninja

bash ${script_path} -d ${binary_path} -p BlockGhidra -s ${compare_path}/compareFuncsArmMips.py -o ${output_path}/funcs/aarch64/ghidra &
bash ${script_path} -d ${binary_path} -p BlockAngr -s ${compare_path}/compareFuncsArmMips.py -o ${output_path}/funcs/aarch64/angr &
bash ${script_path} -d ${binary_path} -p BlockRadare -s ${compare_path}/compareFuncsArmMips.py -o ${output_path}/funcs/aarch64/radare &
bash ${script_path} -d ${binary_path} -p BlockIda -s ${compare_path}/compareFuncsArmMips.py -o ${output_path}/funcs/aarch64/ida &
bash ${script_path} -d ${binary_path} -p BlockNinja -s ${compare_path}/compareFuncsArmMips.py -o ${output_path}/funcs/aarch64/ninja

bash ${script_path} -d ${binary_path} -p BlockGhidra -s ${compare_path}/compareJmpTableArmMips.py -o ${output_path}/jmptbl/aarch64/ghidra &
bash ${script_path} -d ${binary_path} -p BlockAngr -s ${compare_path}/compareJmpTableArmMips.py -o ${output_path}/jmptbl/aarch64/angr &
bash ${script_path} -d ${binary_path} -p BlockRadare -s ${compare_path}/compareJmpTableArmMips.py -o ${output_path}/jmptbl/aarch64/radare &
bash ${script_path} -d ${binary_path} -p BlockIda -s ${compare_path}/compareJmpTableArmMips.py -o ${output_path}/jmptbl/aarch64/ida &
bash ${script_path} -d ${binary_path} -p BlockNinja -s ${compare_path}/compareJmpTableArmMips.py -o ${output_path}/jmptbl/aarch64/ninja

find ${output_path} -iname "*.log" | sort | xargs ${base}/collect_res > ${base}/res.log
cat ${base}/res.log
