echo $0
base_name=`dirname $0`
echo $base_name
run_script="$base_name/run_extract_linux.sh"

extract_bb="$base_name/../extract_gt/extractBB.py"

binutils="/work/arm32_sync/testsuite/aarch64_executables/cpu2006"
bash $run_script -d $binutils/gcc_O0_64 -s $extract_bb &
bash $run_script -d $binutils/gcc_O2_64 -s $extract_bb &
bash $run_script -d $binutils/gcc_O3_64 -s $extract_bb 

bash $run_script -d $binutils/gcc_Os_64 -s $extract_bb &
bash $run_script -d $binutils/gcc_Of_64 -s $extract_bb &


bash $run_script -d $binutils/clang_O0_64 -s $extract_bb 
bash $run_script -d $binutils/clang_O2_64 -s $extract_bb &
bash $run_script -d $binutils/clang_O3_64 -s $extract_bb &

bash $run_script -d $binutils/clang_Os_64 -s $extract_bb &
bash $run_script -d $binutils/clang_Of_64 -s $extract_bb
wait
