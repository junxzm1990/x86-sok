input=$1
cur_dir=`dirname $0`
cur_dir=`realpath $cur_dir`
cmd="python scripts/play/eval_pair_inst_bound.py ./checkpoints/instbound_oracle"
for f in $input/*; do
	echo "=========current file is $f=============="
	exec="$cmd $f $cur_dir/data-bin/instbound_oracle"
	echo $exec
	eval $exec
done
