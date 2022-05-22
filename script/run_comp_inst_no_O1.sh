#! /bin/bash

print_help() {
    echo -e "\t\t -d: required. The directory that contains binary."
    echo -e "\t\t -s: required. the script that compare."
    echo -e "\t\t -p: required. the compared tools."
}

PREFIX=""

while getopts "d:s:p:ho:" arg
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
        o)
            OUTPUT=$OPTARG
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

if [ -z $OUTPUT ]; then
    OUTPUT="/tmp/"
fi

output_dir=`dirname $OUTPUT`

if [ ! -d $OUTPUT ]; then
    echo "mkdir -p $OUTPUT"
    mkdir -p $OUTPUT
fi

for f in `find ${DIRECTORY} -executable -type f | grep -v _O1 | grep -v _strip`; do
    base_name=`basename $f`
    dir_name=`dirname $f`
    strip_dir_name=${dir_name}_strip

    gt_file=${dir_name}/gtBlock_${base_name}.pb
    cmp_file=${strip_dir_name}/${PREFIX}_${base_name}.strip.pb

    if [ ! -f $cmp_file ]; then
	    continue
    fi
    echo $gt_file
    echo $cmp_file
    output_name=`realpath $f`
    output_name="${output_name//\//@}"

    output_name=${OUTPUT}/$output_name

    if [ -f $output_name ]; then
        echo "skip"
        continue
    fi
    python3 $SCRIPT -g $gt_file -c $cmp_file -b $f 2>&1 | tee $output_name
done
