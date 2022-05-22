echo "==============oracle O0======================"
echo "\tRecall"
grep -i "Recall" ./XDAInstTest/O0_oracle.log | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "\tPrecision"
grep -i "Precision" ./XDAInstTest/O0_oracle.log | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "\tF1 Score"
grep -i "F1" ./XDAInstTest/O0_oracle.log | awk '{sum += $4; cnt += 1} END {print sum/cnt}'

echo "==============oracle O1======================"
echo "\tRecall"
grep -i "Recall" ./XDAInstTest/O1_oracle.log | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "\tPrecision"
grep -i "Precision" ./XDAInstTest/O1_oracle.log | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "\tF1 Score"
grep -i "F1" ./XDAInstTest/O1_oracle.log | awk '{sum += $4; cnt += 1} END {print sum/cnt}'

echo "==============oracle O2======================"
echo "\tRecall"
grep -i "Recall" ./XDAInstTest/O2_oracle.log | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "\tPrecision"
grep -i "Precision" ./XDAInstTest/O2_oracle.log | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "\tF1 Score"
grep -i "F1" ./XDAInstTest/O2_oracle.log | awk '{sum += $4; cnt += 1} END {print sum/cnt}'

echo "==============oracle O3======================"
echo "\tRecall"
grep -i "Recall" ./XDAInstTest/O3_oracle.log | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "\tPrecision"
grep -i "Precision" ./XDAInstTest/O3_oracle.log | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "\tF1 Score"
grep -i "F1" ./XDAInstTest/O3_oracle.log | awk '{sum += $4; cnt += 1} END {print sum/cnt}'

echo "==============oracle Os======================"
echo "\tRecall"
grep -i "Recall" ./XDAInstTest/Os_oracle.log | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "\tPrecision"
grep -i "Precision" ./XDAInstTest/Os_oracle.log | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "\tF1 Score"
grep -i "F1" ./XDAInstTest/Os_oracle.log | awk '{sum += $4; cnt += 1} END {print sum/cnt}'

echo "==============oracle Of======================"
echo "\tRecall"
grep -i "Recall" ./XDAInstTest/Of_oracle.log | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "\tPrecision"
grep -i "Precision" ./XDAInstTest/Of_oracle.log | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "\tF1 Score"
grep -i "F1" ./XDAInstTest/Of_oracle.log | awk '{sum += $4; cnt += 1} END {print sum/cnt}'
