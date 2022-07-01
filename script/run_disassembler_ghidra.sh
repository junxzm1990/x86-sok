#!/bin/bash

print_help() {
    echo -e "\t\t -d: required. The directory that contains binary"
    echo -e "\t\t -s: required. The script that extract gt"
    echo -e "\t\t -p: optional. The output name with prefix"
}

PREFIX=""
CUR_PATH=`realpath $0`
CUR_PATH=`dirname $CUR_PATH`

ghidra_path="/usr/ghidra_9.2.3_PUBLIC/support/analyzeHeadless"

while getopts "hd:s:p:" arg
do
    case $arg in
        h)
            print_help
            ;;
        d)
            DIRECTORY=$OPTARG
            ;;
        p)
            PREFIX=$OPTARG
            ;;
    esac
done

if [[ ! -d $DIRECTORY ]]; then
    echo "Please input directory with (-d)!"
    exit -1
fi

if [[ -z $PREFIX ]]; then
    echo "Please input the prefix with (-p)!"
    exit -1
fi

for f in `find $DIRECTORY -executable -type f | grep _strip`; do
    echo "==================current file is $f================="
    dir_name=`dirname $f`
    base_name=`basename $f`
    output=${dir_name}/${PREFIX}_${base_name}.pb
    log=${dir_name}/${PREFIX}_${base_name}.log

    #if [ -f $output ]; then
    #    echo "exists, skip!"
    #    continue
    #fi

    export GHIDRA_OUT_PATH="$output"
    export GHIDRA_STAT_OUT_PATH="$log"
    project=`cat /proc/sys/kernel/random/uuid | sed 's/[-]//g' | head -c 20; echo;`
    cmd="$ghidra_path ~/ghidra/project $project -deleteProject -scriptPath $CUR_PATH/../disassemblers/ghidra -postScript ghidraBB.py -import $f"
    echo "$cmd"
    $ghidra_path ~/ghidra/project $project -deleteProject -scriptPath $CUR_PATH/../disassemblers/ghidra -postScript ghidraBB.py -import $f
done
