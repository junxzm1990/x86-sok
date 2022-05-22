#!/bin/bash

print_help() {
    echo -e "\t\t -d: required. The directory that contains binary"
    echo -e "\t\t -s: required. The script that extract gt"
    echo -e "\t\t -p: optional. The output name with prefix"
}

PREFIX=""

while getopts "hd:s:p:" arg
do
    case $arg in
        h)
            print_help
            ;;
        d)
            DIRECTORY=$OPTARG
            ;;
        s)
            SCRIPT=$OPTARG
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

if [[ ! -f $SCRIPT ]]; then
    echo "Please input disassembler path with (-s)!"
    exit -1
fi

if [[ -z $PREFIX ]]; then
    echo "Please input the prefix with (-p)!"
    exit -1
fi

for f in `find $DIRECTORY -executable -type f | grep -v O1 | grep -v striped_exes | grep _strip | grep -v Ida`; do
    echo "==================current file is $f================="
    dir_name=`dirname $f`
    base_name=`basename $f`
    output=${dir_name}/${PREFIX}_${base_name}.pb

    if [ -f $output ]; then
        echo "exists, skip!"
        continue
    fi

    cmd="python3 $SCRIPT -b $f -o $output"
    echo "$cmd"
    python3 $SCRIPT -b $f -o $output > /dev/null
    
done
