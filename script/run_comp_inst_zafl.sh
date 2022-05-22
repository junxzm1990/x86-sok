#! /bin/bash

print_help() {
    echo -e "\t\t -d: required. The directory that contains binary."
    echo -e "\t\t -s: required. the script that compare."
    echo -e "\t\t -p: required. the compared tools."
    echo -e "\t\t -g: required. the prefix of ground truth"
}

PREFIX=""

while getopts "d:s:p:ho:g:" arg
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
	g)
	    GT_PREFIX=$OPTARG
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

if [[ -z $GT_PREFIX ]]; then
    echo "Please input the gt prefix with (-g)!"
    exit -1
fi

output_dir=`dirname $OUTPUT`

if [ ! -d $OUTPUT ]; then
    echo "mkdir -p $OUTPUT"
    mkdir -p $OUTPUT
fi

for f in `find ${DIRECTORY} -executable -type f | grep -v _strip | grep -v clang_m32 | grep -v _O1 | grep -v dealII_base`; do
    base_name=`basename $f`
    dir_name=`dirname $f`
    strip_dir_name=${dir_name}_strip

    gt_file=${dir_name}/${GT_PREFIX}_${base_name}.pb
    cmp_file=${strip_dir_name}/${PREFIX}_${base_name}.strip.pb
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
