result_path_orig_oracle="result/jmptbl_gt/original_oracle"
result_path_impro_oracle="result/jmptbl_gt/improved_oracle"
echo "======================="
echo "Original OracleGT Angr"
grep "F1" -r $result_path_orig_oracle/angr | awk '{sum += $4; cnt += 1} END {print sum/cnt}'
echo "Improved OracleGT Angr"
grep "F1" -r $result_path_impro_oracle/angr | awk '{sum += $4; cnt += 1} END {print sum/cnt}'

echo "======================="
echo "Original OracleGT IDA"
grep "F1" -r $result_path_orig_oracle/ida | awk '{sum += $4; cnt += 1} END {print sum/cnt}'
echo "Improved OracleGT IDA"
grep "F1" -r $result_path_impro_oracle/ida | awk '{sum += $4; cnt += 1} END {print sum/cnt}'

echo "======================="
echo "Original OracleGT Binary Ninja"
grep "F1" -r $result_path_orig_oracle/ninja | awk '{sum += $4; cnt += 1} END {print sum/cnt}'
echo "Improved OracleGT Binary Ninja"
grep "F1" -r $result_path_impro_oracle/ninja | awk '{sum += $4; cnt += 1} END {print sum/cnt}'

echo "======================="
echo "Original OracleGT Ghidra"
grep "F1" -r $result_path_orig_oracle/ghidra | awk '{sum += $4; cnt += 1} END {print sum/cnt}'
echo "Improved OracleGT Ghidra"
grep "F1" -r $result_path_impro_oracle/ghidra | awk '{sum += $4; cnt += 1} END {print sum/cnt}'

echo "======================="
echo "Original OracleGT Dyninat"
grep "F1" -r $result_path_orig_oracle/dyninst | awk '{sum += $4; cnt += 1} END {print sum/cnt}'
echo "Improved OracleGT Dyninst"
grep "F1" -r $result_path_impro_oracle/dyninst | awk '{sum += $4; cnt += 1} END {print sum/cnt}'

echo "======================="
echo "Original OracleGT Radare2"
grep "F1" -r $result_path_orig_oracle/radare | awk '{sum += $4; cnt += 1} END {print sum/cnt}'
echo "Improved OracleGT Radare2"
grep "F1" -r $result_path_impro_oracle/radare | awk '{sum += $4; cnt += 1} END {print sum/cnt}'
