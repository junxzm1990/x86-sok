bash run_elfmap_predicate.sh ./XDAInstTest/O0_test 2>&1 | tee ./XDAInstTest/O0_elfmap.log &
bash run_elfmap_predicate.sh ./XDAInstTest/O1_test 2>&1 | tee ./XDAInstTest/O1_elfmap.log
bash run_elfmap_predicate.sh ./XDAInstTest/O2_test 2>&1 | tee ./XDAInstTest/O2_elfmap.log &
bash run_elfmap_predicate.sh ./XDAInstTest/O3_test 2>&1 | tee ./XDAInstTest/O3_elfmap.log
bash run_elfmap_predicate.sh ./XDAInstTest/Os_test 2>&1 | tee ./XDAInstTest/Os_elfmap.log &
bash run_elfmap_predicate.sh ./XDAInstTest/Of_test 2>&1 | tee ./XDAInstTest/Of_elfmap.log
