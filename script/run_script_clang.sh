echo $0
base_name=`dirname $0`
echo $base_name
run_script="$base_name/../run_extract_linux.sh"

extract_bb="$base_name/../extractBB.py"

cpu2006="/work/arm32_sync/testsuite/exeutables/utils/cpu2006/"
bash $run_script -d $cpu2006/clang_O0 -s $extract_bb &
bash $run_script -d $cpu2006/clang_O2 -s $extract_bb &
bash $run_script -d $cpu2006/clang_O3 -s $extract_bb 

bash $run_script -d $cpu2006/clang_Os -s $extract_bb &
bash $run_script -d $cpu2006/clang_Of -s $extract_bb 

binutils="/work/arm32_sync/testsuite/exeutables/utils/binutils/"
bash $run_script -d $binutils/clang_O0 -s $extract_bb &
bash $run_script -d $binutils/clang_O2 -s $extract_bb &
bash $run_script -d $binutils/clang_O3 -s $extract_bb 

bash $run_script -d $binutils/clang_Os -s $extract_bb &
bash $run_script -d $binutils/clang_Of -s $extract_bb 

wait
