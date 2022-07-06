# do not output the O0 info
echo $1
dir_name=$1
#echo "O0 precision"
#v1=`grep "Precision" -r $dir_name |  grep -v truePositive  | grep -v "Binary file" | grep O0 | rev | cut -d " " -f1 | rev | awk '{s+=$1} END {print s}'`
#v2=`grep "Precision" -r $dir_name | grep -v truePositive | grep -v "Binary file" | grep O0 | wc -l`
#echo "$v1 / $v2"
#echo "scale=4; $v1/$v2" | bc
#echo "O0 Recall"
#v1=`grep "Recall" -r $dir_name | grep -v "Binary file" | grep O0 | rev | cut -d " " -f1 | rev | awk '{s+=$1} END {print s}'`
#v2=`grep "Recall" -r $dir_name | grep -v "Binary file" | grep O0 | wc -l`
#echo "scale=4; $v1/$v2" | bc

#echo ""

#echo "O2 precision"
v1=`grep "Precision" -r $dir_name | grep -v "Binary file" | grep -v truePositive | grep O2 | rev | cut -d " " -f1 | rev | awk '{s+=$1} END {print s}'`
v2=`grep "Precision" -r $dir_name | grep -v "Binary file" | grep -v truePositive | grep O2 | wc -l`
# echo $v1
# echo $v2
echo "scale=10; $v1/$v2" | bc
#echo "O2 Recall"
v1=`grep "Recall" -r $dir_name | grep -v "Binary file" | grep O2 | rev | cut -d " " -f1 | rev | awk '{s+=$1} END {print s}'`
v2=`grep "Recall" -r $dir_name | grep -v "Binary file" | grep O2 | wc -l`
echo "scale=10; $v1/$v2" | bc
#echo ""

#echo "O3 precision"
v1=`grep "Precision" -r $dir_name | grep -v "Binary file" |  grep -v truePositive | grep O3 | rev | cut -d " " -f1 | rev | awk '{s+=$1} END {print s}'`
v2=`grep "Precision" -r $dir_name | grep -v "Binary file" | grep -v truePositive | grep O3 | wc -l`
echo "scale=10; $v1/$v2" | bc
#echo "O3 Recall"
v1=`grep "Recall" -r $dir_name | grep -v "Binary file" | grep O3 | rev | cut -d " " -f1 | rev | awk '{s+=$1} END {print s}'`
v2=`grep "Recall" -r $dir_name | grep -v "Binary file" | grep O3 | wc -l`
echo "scale=10; $v1/$v2" | bc
#echo ""

#echo "Os precision"
v1=`grep "Precision" -r $dir_name | grep -v "Binary file" | grep -v truePositive | grep Os | rev | cut -d " " -f1 | rev | grep -v matches | awk '{s+=$1} END {print s}'`
v2=`grep "Precision" -r $dir_name | grep -v "Binary file" | grep -v truePositive | grep Os | wc -l`
echo "scale=10; $v1/$v2" | bc
#echo "Os Recall"
v1=`grep "Recall" -r $dir_name | grep -v "Binary file" | grep Os | rev | cut -d " " -f1 | rev | awk '{s+=$1} END {print s}'`
v2=`grep "Recall" -r $dir_name | grep -v "Binary file" | grep Os | wc -l`
echo "scale=10; $v1/$v2" | bc
#echo ""

#echo "Of precision"
v1=`grep "Precision" -r $dir_name | grep -v "Binary file" | grep -v truePositive | grep Of | rev | cut -d " " -f1 | grep -v matches | rev | awk '{s+=$1} END {print s}'`
v2=`grep "Precision" -r $dir_name | grep -v "Binary file" | grep -v truePositive | grep Of | wc -l`
echo "scale=10; $v1/$v2" | bc
#echo "Of Recall"
v1=`grep "Recall" -r $dir_name | grep -v "Binary file" | grep Of | rev | cut -d " " -f1 | rev | awk '{s+=$1} END {print s}'`
v2=`grep "Recall" -r $dir_name | grep -v "Binary file" | grep Of | wc -l`
echo "scale=10; $v1/$v2" | bc
#echo ""

