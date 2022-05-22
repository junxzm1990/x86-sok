output=./result/insns/elfmap
output=/work2/compare_data/x86/elfmap_new_new
echo "The number of False Positives of O0:"
grep "False Pos" -r $output | grep O0 | wc -l
echo "The number of False Positives of O1:"
grep "False Pos" -r $output | grep O1 | wc -l
echo "The number of False Positives of O2:"
grep "False Pos" -r $output | grep O2 | wc -l
echo "The number of False Positives of O3:"
grep "False Pos" -r $output | grep O3 | wc -l
echo "The number of False Positives of Os:"
grep "False Pos" -r $output | grep Os | wc -l
echo "The number of False Positives of Of:"
grep "False Pos" -r $output | grep Of | wc -l

echo "The number of False Negatives of O0:"
grep "False Neg" -r $output | grep O0 | wc -l
echo "The number of False Negatives of O1:"
grep "False Neg" -r $output | grep O1 | wc -l
echo "The number of False Negatives of O2:"
grep "False Neg" -r $output | grep O2 | wc -l
echo "The number of False Negatives of O3:"
grep "False Neg" -r $output | grep O3 | wc -l
echo "The number of False Negatives of Os:"
grep "False Neg" -r $output | grep Os | wc -l
echo "The number of False Negatives of Of:"
grep "False Neg" -r $output | grep Of | wc -l
