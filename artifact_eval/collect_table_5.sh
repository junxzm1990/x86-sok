echo "==============Result of False positives:=============="
echo "============Objdump-Sym=============="
echo "#FP of O0"
grep "False Pos"  -r result/insns/objdump_syms/zafl | grep O0 | wc -l
echo "#FP of O2"
grep "False Pos"  -r result/insns/objdump_syms/zafl | grep O2 | wc -l
echo "#FP of O3"
grep "False Pos"  -r result/insns/objdump_syms/zafl | grep O3 | wc -l
echo "#FP of Os"
grep "False Pos"  -r result/insns/objdump_syms/zafl | grep Os | wc -l
echo "#FP of Of"
grep "False Pos"  -r result/insns/objdump_syms/zafl | grep Of | wc -l

echo "============Objdump=============="
echo "#FP of O0"
grep "False Pos"  -r result/insns/objdump_no_syms/zafl | grep O0 | wc -l
echo "#FP of O2"
grep "False Pos"  -r result/insns/objdump_no_syms/zafl | grep O2 | wc -l
echo "#FP of O3"
grep "False Pos"  -r result/insns/objdump_no_syms/zafl | grep O3 | wc -l
echo "#FP of Os"
grep "False Pos"  -r result/insns/objdump_no_syms/zafl | grep Os | wc -l
echo "#FP of Of"
grep "False Pos"  -r result/insns/objdump_no_syms/zafl | grep Of | wc -l

echo "============Oracle=============="
echo "#FP of O0"
grep "False Pos"  -r result/insns/oracle/zafl | grep O0 | wc -l
echo "#FP of O2"
grep "False Pos"  -r result/insns/oracle/zafl | grep O2 | wc -l
echo "#FP of O3"
grep "False Pos"  -r result/insns/oracle/zafl | grep O3 | wc -l
echo "#FP of Os"
grep "False Pos"  -r result/insns/oracle/zafl | grep Os | wc -l
echo "#FP of Of"
grep "False Pos"  -r result/insns/oracle/zafl | grep Of | wc -l

echo "==============Result of False negatives:=============="
echo "============Objdump-Sym=============="
echo "#FN of O0"
grep "False Neg"  -r result/insns/objdump_syms/zafl | grep O0 | wc -l
echo "#FN of O2"
grep "False Neg"  -r result/insns/objdump_syms/zafl | grep O2 | wc -l
echo "#FN of O3"
grep "False Neg"  -r result/insns/objdump_syms/zafl | grep O3 | wc -l
echo "#FN of Os"
grep "False Neg"  -r result/insns/objdump_syms/zafl | grep Os | wc -l
echo "#FN of Of"
grep "False Neg"  -r result/insns/objdump_syms/zafl | grep Of | wc -l

echo "============Objdump=============="
echo "#FN of O0"
grep "False Neg"  -r result/insns/objdump_no_syms/zafl | grep O0 | wc -l
echo "#FN of O2"
grep "False Neg"  -r result/insns/objdump_no_syms/zafl | grep O2 | wc -l
echo "#FN of O3"
grep "False Neg"  -r result/insns/objdump_no_syms/zafl | grep O3 | wc -l
echo "#FN of Os"
grep "False Neg"  -r result/insns/objdump_no_syms/zafl | grep Os | wc -l
echo "#FN of Of"
grep "False Neg"  -r result/insns/objdump_no_syms/zafl | grep Of | wc -l

echo "============Oracle=============="
echo "#FN of O0"
grep "False Neg"  -r result/insns/oracle/zafl | grep O0 | wc -l
echo "#FN of O2"
grep "False Neg"  -r result/insns/oracle/zafl | grep O2 | wc -l
echo "#FN of O3"
grep "False Neg"  -r result/insns/oracle/zafl | grep O3 | wc -l
echo "#FN of Os"
grep "False Neg"  -r result/insns/oracle/zafl | grep Os | wc -l
echo "#FN of Of"
grep "False Neg"  -r result/insns/oracle/zafl | grep Of | wc -l
