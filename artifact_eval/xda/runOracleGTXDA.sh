#!/bin/bash

print_help(){
        echo -e "\t\t -d: required. The directory that contains binary"
        echo -e "\t\t -s: required. The script that extract gt"
        echo -e "\t\t -p: optioal. The output name with prefix(default is gtBlock)"
        exit 0
}

PREFIX="elfMapInst"
while getopts "hd:s:p:o:" arg
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
                        OUTPUT_DIR=$OPTARG
                        ;;
        esac
done

if [[ ! -d $DIRECTORY ]]; then
        echo $DIRECTORY
        echo "Please input directory with (-d)!"
        exit -1
fi

if [[ ! -s $SCRIPT ]]; then
        echo "Please input extract script with (-s)!"
        exit -1
fi

if [[ ! -d $OUTPUT_DIR ]]; then
        echo "mkdir -p $OUTPUT_DIR"
        mkdir -p $OUTPUT_DIR
fi

for f in `find $DIRECTORY -executable -type f | grep -v _strip | grep gcc | grep -v m32`; do
        echo "===========current file is $f==================="
        dir_name=`dirname $f`
        base_name=`basename $f`
        gt=${dir_name}/${PREFIX}_${base_name}.pb
        echo $output_f
        output_f="${f//pure_executables\/}"
        output_f="${output_f//\//@}"

        output=${OUTPUT_DIR}/${output_f}
        echo $output

        if [ -f $output ]; then
                echo "skip"
                continue
        fi
        if [ `file $f | grep -c debug_info` -eq 0 ]; then
                echo "do not have debug information"
                continue
        fi
        echo "output file is $output"
        echo "gt is $gt"
        python3 $SCRIPT -g $gt -b $f > $output
done
