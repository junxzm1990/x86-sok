echo "==============elfmap O0======================"
echo "\tRecall"
grep -i "Recall" ./XDAInstTest/O0_elfmap.log | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "\tPrecision"
grep -i "Precision" ./XDAInstTest/O0_elfmap.log | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "\tF1 Score"
grep -i "F1" ./XDAInstTest/O0_elfmap.log | awk '{sum += $4; cnt += 1} END {print sum/cnt}'

echo "==============elfmap O1======================"
echo "\tRecall"
grep -i "Recall" ./XDAInstTest/O1_elfmap.log | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "\tPrecision"
grep -i "Precision" ./XDAInstTest/O1_elfmap.log | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "\tF1 Score"
grep -i "F1" ./XDAInstTest/O1_elfmap.log | awk '{sum += $4; cnt += 1} END {print sum/cnt}'

echo "==============elfmap O2======================"
echo "\tRecall"
grep -i "Recall" ./XDAInstTest/O2_elfmap.log | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "\tPrecision"
grep -i "Precision" ./XDAInstTest/O2_elfmap.log | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "\tF1 Score"
grep -i "F1" ./XDAInstTest/O2_elfmap.log | awk '{sum += $4; cnt += 1} END {print sum/cnt}'

echo "==============elfmap O3======================"
echo "\tRecall"
grep -i "Recall" ./XDAInstTest/O3_elfmap.log | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "\tPrecision"
grep -i "Precision" ./XDAInstTest/O3_elfmap.log | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "\tF1 Score"
grep -i "F1" ./XDAInstTest/O3_elfmap.log | awk '{sum += $4; cnt += 1} END {print sum/cnt}'

echo "==============elfmap Os======================"
echo "\tRecall"
grep -i "Recall" ./XDAInstTest/Os_elfmap.log | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "\tPrecision"
grep -i "Precision" ./XDAInstTest/Os_elfmap.log | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "\tF1 Score"
grep -i "F1" ./XDAInstTest/Os_elfmap.log | awk '{sum += $4; cnt += 1} END {print sum/cnt}'

echo "==============elfmap Of======================"
echo "\tRecall"
grep -i "Recall" ./XDAInstTest/Of_elfmap.log | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "\tPrecision"
grep -i "Precision" ./XDAInstTest/Of_elfmap.log | awk '{sum += $3; cnt += 1} END {print sum/cnt}'
echo "\tF1 Score"
grep -i "F1" ./XDAInstTest/Of_elfmap.log | awk '{sum += $4; cnt += 1} END {print sum/cnt}'
