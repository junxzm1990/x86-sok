src_dir=$1
dst_dir=$2

dst_oracle=$dst_dir/oracle
dst_symbol=$dst_dir/symbol
mkdir -p $dst_oracle/binary
mkdir -p $dst_oracle/binary_strip
mkdir -p $dst_symbol/binary
mkdir -p $dst_symbol/binary_strip

echo "==========preprocessing dataset============"
for f in `find $src_dir -executable -type f | grep -v _strip | grep -v m32 | grep -v clang`; do
	opt=`echo "$f" | rev | cut -d "/" -f2 | rev | cut -d '_' -f2`
	basename=`basename $f`
	basename="gcc_coreutils_64_${opt}_${basename}"
	dst_ora1=$dst_oracle/binary/$basename
	dst_ora2=$dst_oracle/binary_strip/$basename
	dst_sym1=$dst_symbol/binary/$basename
	dst_sym2=$dst_symbol/binary_strip/$basename

	cp $f $dst_ora1
	cp $f $dst_sym1

	cp $f $dst_ora2
	cp $f $dst_sym2

	strip $dst_ora2
	strip $dst_sym2
	readelf -Ws $dst_ora1 | grep "\.cold" | awk '{print $8}' | xargs -I{} objcopy $dst_ora1 -N {}
done
