dst_path=$1

for f in `find $dst_path -executable -type f | grep -v _strip`; do
	dir_name=`dirname $f`
	f_name=`basename $f`
	dst="${dir_name}_strip/${f_name}.strip"
	echo $dst
	cp $f $dst
	strip $dst
done
