#!/bin/bash

print_help(){
	echo -e "\t\t -d: required. The directory that contains binary"
	echo -e "\t\t -s: required. The script that extract gt"
	echo -e "\t\t -p: optioal. The output name with prefix(default is gtBlock)"
	exit 0
}

PREFIX="gtBlock"
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
	echo "Please input extract script with (-s)!"
	exit -1
fi


for f in `find $DIRECTORY -executable -type f`; do
	echo "===========current file is $f==================="
	
	gt_gz=${f}.gt.gz
	gt=${f}.gt
	dir_name=`dirname $f`
	base_name=`basename $f`
	output=${dir_name}/${PREFIX}_${base_name}.pb

	objcopy --dump-section .rand=$gt_gz $f && yes | gzip -d $gt_gz

	python3 $SCRIPT -b $f -m $gt -o $output
done

