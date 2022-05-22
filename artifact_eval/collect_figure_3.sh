result_path_oracle="result/insns/openssl/oracle"
result_path_objdump="result/insns/openssl/objdump"
result_path_debuginfo="result//insns/openssl/debuginfo"
echo "=========================="
echo "Oracle IDA"
grep "F1" -r $result_path_oracle/ida | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "Objdump IDA"
grep "F1" -r $result_path_objdump/ida | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "DebugInfo IDA"
grep "F1" -r $result_path_debuginfo/ida | awk '{sum += $3; cnt += 1} END {print sum/cnt}'

echo "=========================="
echo "Oracle Binary Ninja"
grep "F1" -r $result_path_oracle/ninja | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "Objdump Binary Ninja"
grep "F1" -r $result_path_objdump/ninja | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "DebugInfo Binary Ninja"
grep "F1" -r $result_path_debuginfo/ninja | awk '{sum += $3; cnt += 1} END {print sum/cnt}'

echo "=========================="
echo "Oracle Ghidra"
grep "F1" -r $result_path_oracle/ghidra | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "Objdump Ghidra"
grep "F1" -r $result_path_objdump/ghidra | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "DebugInfo Ghidra"
grep "F1" -r $result_path_debuginfo/ghidra | awk '{sum += $3; cnt += 1} END {print sum/cnt}'

echo "=========================="
echo "Oracle Angr"
grep "F1" -r $result_path_oracle/angr | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "Objdump Angr"
grep "F1" -r $result_path_objdump/angr | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "DebugInfo Angr"
grep "F1" -r $result_path_debuginfo/angr | awk '{sum += $3; cnt += 1} END {print sum/cnt}'

echo "=========================="
echo "Oracle Dyninst"
grep "F1" -r $result_path_oracle/dyninst | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "Objdump Dyninst"
grep "F1" -r $result_path_objdump/dyninst | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "DebugInfo Dyninst"
grep "F1" -r $result_path_debuginfo/dyninst | awk '{sum += $3; cnt += 1} END {print sum/cnt}'

echo "=========================="
echo "Oracle Objdump"
grep "F1" -r $result_path_oracle/objdump | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "Objdump Objdump"
grep "F1" -r $result_path_objdump/objdump | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "DebugInfo Objdump"
grep "F1" -r $result_path_debuginfo/objdump | awk '{sum += $3; cnt += 1} END {print sum/cnt}'

echo "=========================="
echo "Oracle Bap"
grep "F1" -r $result_path_oracle/bap | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "Bap Bap"
grep "F1" -r $result_path_objdump/bap | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "DebugInfo Bap"
grep "F1" -r $result_path_debuginfo/bap | awk '{sum += $3; cnt += 1} END {print sum/cnt}'

echo "=========================="
echo "Oracle Radare2"
grep "F1" -r $result_path_oracle/radare | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "Radare2 Radare2"
grep "F1" -r $result_path_objdump/radare | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "DebugInfo Radare2"
grep "F1" -r $result_path_debuginfo/radare | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
