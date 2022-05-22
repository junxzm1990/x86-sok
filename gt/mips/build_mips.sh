#!/bin/bash

# testing environment: ubuntu 18.04
# build script

set -e


BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

SRC_PATH=`dirname $0`
SRC_PATH=`realpath $SRC_PATH`

PWD_PATH="${SRC_PATH}/build_mips"

SRC_PATH=`realpath $SRC_PATH/../`

if [ ! -d $PWD_PATH ];then
    echo -e "${GREEN}[*] mkdir directory $PWD_PATH${NC}"
    mkdir $PWD_PATH
    mkdir -p $PWD_PATH/succeed
fi

cd $PWD_PATH

BUILD_ESSENTIAL="apt-get -y update && \
	apt-get -y install git wget flex texinfo gcc-multilib g++-multilib python3 build-essential bison zlib1g-dev libtool cmake gcc g++ libc6 gawk"
echo $BUILD_ESSENTIAL
eval $BUILD_ESSENTIAL

# build protobuf
echo
echo -e "${BLUE}===================== build protobuf ======================${NC}"
echo

if [ ! -f ${PWD_PATH}/succeed/protobuf ]; then
    cd $PWD_PATH
    eval "apt-get -y install autoconf automake libtool curl make g++ unzip pkg-config"
    eval "git clone https://github.com/protocolbuffers/protobuf.git"
    eval "cd protobuf && git submodule update --init --recursive && ./autogen.sh"
    eval "./configure && make -j$(nproc) &&  make install && ldconfig"
    echo "done" > ${PWD_PATH}/succeed/protobuf
fi

echo
echo -e "${GREEN}[*] build protobuf succeed!${NC}"

# build protobuf-c
echo
echo -e  "${BLUE}===================== build protobuf-c =======================${NC}"
echo
cd $PWD_PATH

if [ ! -f ${PWD_PATH}/succeed/protobuf-c ]; then
    echo "git clone https://github.com/protobuf-c/protobuf-c.git"
    eval "git clone https://github.com/protobuf-c/protobuf-c.git"
    eval 'cd protobuf-c && ./autogen.sh && ./configure && make -j$(nproc) && make install'
    eval 'ln -sf /usr/local/lib/libprotobuf-c.so.1.0.0 /usr/lib/libprotobuf-c.so.1'
    echo "done" > ${PWD_PATH}/succeed/protobuf-c
fi

echo
echo -e "${GREEN}[*] build protobuf-c succeed!${NC}"


# get disassemble_compare
cd $PWD_PATH
echo
echo -e "${BLUE}===================== build shuffleInfo.so ======================${NC}"
echo
PROTODEF_DIR="$PWD_PATH/../proto"
PROTO="shuffleInfo.proto"
SHUFFLEINFO="shuffleInfo.so"
CC_HDR="shuffleInfo.pb.h"
PROTO_C="shuffleInfo.pb.cc"
C_HDR="shuffleInfo.pb-c.*"

# compile shuffle.so
cd $PROTODEF_DIR
set +e
eval "protoc --proto_path=$PROTODEF_DIR --cpp_out=. $PROTODEF_DIR/$PROTO"
eval "protoc --proto_path=$PROTODEF_DIR --c_out=. $PROTODEF_DIR/$PROTO"
eval "c++ -fPIC -shared $PROTODEF_DIR/$PROTO_C -o $PROTODEF_DIR/$SHUFFLEINFO `pkg-config --cflags --libs protobuf`"
set -e

# cp the .so to /usr/lib
LIB1="/usr/lib"
LIB2="/usr/local/lib"
  cp $PROTODEF_DIR/$SHUFFLEINFO $LIB1/$SHUFFLEINFO
  cp $PROTODEF_DIR/$SHUFFLEINFO $LIB2/$SHUFFLEINFO
  cp $PROTODEF_DIR/$SHUFFLEINFO $LIB2/lib$SHUFFLEINFO
  cp $PROTODEF_DIR/$SHUFFLEINFO $LIB1/lib$SHUFFLEINFO

# get and build gas
cd $PWD_PATH
GAS_DIR=${PWD_PATH}/binutils-2.30/gas
GOLD_DIR=${PWD_PATH}/binutils-2.30/gold

echo
echo -e "${BLUE}===================== build gas && gold ===========================${NC}"
echo

if [ ! -f ${PWD_PATH}/succeed/binutils ]; then
    wget -c 'https://ftp.gnu.org/gnu/binutils/binutils-2.30.tar.xz'
    tar xvJf binutils-2.30.tar.xz
    echo "rm -r binutils-2.30/gas"
    rm -r binutils-2.30/gas
    rm -r binutils-2.30/gold
    echo "cp -r ${SRC_PATH}/binutils/gas-2.30 ${GAS_DIR}"
    cp -r ${SRC_PATH}/binutils/gas-2.30 ${GAS_DIR}

    cp -r ${SRC_PATH}/binutils/gold-2.30 ${GOLD_DIR}
    
    cp $PROTODEF_DIR/$C_HDR $GAS_DIR

    cp $PROTODEF_DIR/$CC_HDR ${GOLD_DIR}/
    cp $PROTODEF_DIR/$PROTO_C ${GOLD_DIR}/

    echo "cd $PWD_PATH/binutils-2.30 && mkdir -p build && cd build"
    eval "cd $PWD_PATH/binutils-2.30 && mkdir -p build && cd build"

    CFLAGS="`pkg-config --cflags 'libprotobuf-c >= 1.0.0'`" LDFLAGS=`pkg-config --libs 'libprotobuf-c >= 1.0.0'` \
            ../configure --enable-gold --prefix=${PWD_PATH}/executable_binutils \
            --disable-werror --enable-shared \
             --enable-ld=default \
	     --enable-plugins    \
             --enable-64-bit-bfd \
             --with-system-zlib \
            && make -j$(nproc)
            && make install
    echo "done" > ${PWD_PATH}/succeed/binutils
fi

echo
echo -e "${GREEN}[*] build gas&&gold succeed!${NC}"

GAS_PATH=$PWD_PATH/binutils-2.30/build/gas/as-new
GOLD_PATH=$PWD_PATH/binutils-2.30/build/gold/ld-new

# get gcc-8.1.0
GCC_PATH="$PWD_PATH/gcc-8.1.0"
# GCC_EXE_PATH="$PWD_PATH/gcc_executable"
#GCC_EXE_PATH=""
GCC_BUILD_PATH_32="$PWD_PATH/build_gcc_32"
GCC_BUILD_PATH_64="$PWD_PATH/build_gcc_64"
GCC_EXE_PATH="$PWD_PATH/executable_gcc"

# soft link gas
eval " cp /usr/bin/as /usr/bin/as.old"
eval " ln -sf $GAS_PATH /usr/bin/as"

echo
echo -e "${BLUE}======================= build gcc ===============================${NC}"
echo
cd $PWD_PATH

if [ ! -f ${PWD_PATH}/succeed/gcc ]; then

    eval "wget -c https://bigsearcher.com/mirrors/gcc/releases/gcc-8.1.0/gcc-8.1.0.tar.xz"
    eval "tar xvJf gcc-8.1.0.tar.xz"
    eval "mkdir -p $GCC_EXE_PATH"
    eval "mkdir -p $GCC_BUILD_PATH_32"
    eval "mkdir -p $GCC_BUILD_PATH_64"

    # download gcc dependencies
    cd $GCC_PATH
    eval "./contrib/download_prerequisites"

    echo
    echo -e "${BLUE}======================= build gcc(32) ===============================${NC}"
    echo   
    
    export CFLAGS="-mabi=32 -B/usr/libo32"
    export CXXFLAGS="-mabi=32 -B/usr/libo32"
    export CCASFLAGS="-mabi=32 -B/usr/libo32"
    export FCFLAGS="-mabi=32 -B/usr/libo32"
    export FFLAGS="-mabi=32 -B/usr/libo32"
    export ADAFLAGS="-mabi=32 -B/usr/libo32"
    export GOCFLAGS="-mabi=32 -B/usr/libo32"
    export LIBCFLAGS="-mabi=32 -B/usr/libo32" 
    export LIBCXXFLAGS="-mabi=32 -B/usr/libo32"
    export LDFLAGS="-mabi=32 -L/usr/libo32"
  
    cp -r /usr/lib32 /usr/libn32
    ln -sf /usr/libo32/crt1.o /usr/lib32/crt1.o
    ln -sf /usr/libo32/crti.o /usr/lib32/crti.o
    ln -sf /usr/libo32/crtn.o /usr/lib32/crtn.o
    ln -sf /usr/libo32/libc.so /usr/lib32/libc.so
    ln -sf /usr/libo32/libpthread.so /usr/lib32/libpthread.so
    
    BUILD_GCC="../gcc-8.1.0/configure -v --with-pkgversion=Debian 8.1.0 --with-bugurl=file:///usr/share/doc/gcc-8/README.Bugs --enable-languages=c,c++ --prefix=$GCC_EXE_PATH --with-gcc-major-version-only --program-suffix=-8.1 --enable-shared --enable-linker-build-id --enable-nls --enable-clocale=gnu --enable-libstdcxx-debug --enable-libstdcxx-time=yes --with-default-libstdcxx-abi=new --enable-gnu-unique-object --disable-libitm --disable-libsanitizer --disable-libquadmath --disable-libquadmath-support --disable-plugin --enable-default-pie --with-system-zlib --disable-libphobos --enable-objc-gc=auto --enable-multiarch --disable-werror --disable-multilib --with-mips-plt --with-arch-64=mips64r2 --with-madd4=no --enable-targets=all --disable-checking --build=mips64el-linux-gnuabi64 --host=mips64el-linux-gnuabi64 --target=mips64el-linux-gnuabi64 --enable-targets=all --disable-lto --disable-bootstrap --with-as=${PWD_PATH}/executable_binutils/bin/as" 


    eval $BUILD_GCC

    rm -r "${GCC_PATH}/gcc"
    cp -r "${SRC_PATH}/gcc/gcc-8.1.0/gcc" ${GCC_PATH}/gcc

    # gcc
    eval "cd $GCC_BUILD_PATH_32 && make -j8 &&   make install"

    echo
    echo -e "${BLUE}======================= build gcc(64) ===============================${NC}"
    echo
         
    export CFLAGS="-mabi=64 -B/usr/lib"
    export CXXFLAGS="-mabi=64 -B/usr/lib"
    export CCASFLAGS="-mabi=64 -B/usr/lib"
    export FCFLAGS="-mabi=64 -B/usr/lib"
    export FFLAGS="-mabi=64 -B/usr/lib"
    export ADAFLAGS="-mabi=64 -B/usr/lib"
    export GOCFLAGS="-mabi=64 -B/usr/lib"
    export LIBCFLAGS="-mabi=64 -B/usr/lib" 
    export LIBCXXFLAGS="-mabi=64 -B/usr/lib"
    export LDFLAGS="-mabi=64 -L/usr/lib"
   
    ln -sf /usr/lib/mips64el-linux-gnuabi64/crt1.o /usr/lib32/crt1.o
    ln -sf /usr/lib/mips64el-linux-gnuabi64/crti.o /usr/lib32/crti.o
    ln -sf /usr/lib/mips64el-linux-gnuabi64/crtn.o /usr/lib32/crtn.o
    ln -sf /usr/lib/mips64el-linux-gnuabi64/libc.so /usr/lib32/libc.so
    ln -sf /usr/lib/mips64el-linux-gnuabi64/libpthread.so /usr/lib32/libpthread.so 
    
    BUILD_GCC="../gcc-8.1.0/configure -v --with-pkgversion=Debian 8.1.0 --with-bugurl=file:///usr/share/doc/gcc-8/README.Bugs --enable-languages=c,c++ --prefix=$GCC_EXE_PATH --with-gcc-major-version-only --program-suffix=-8.1 --enable-shared --enable-linker-build-id --enable-nls --enable-clocale=gnu --enable-libstdcxx-debug --enable-libstdcxx-time=yes --with-default-libstdcxx-abi=new --enable-gnu-unique-object --disable-libitm --disable-libsanitizer --disable-libquadmath --disable-libquadmath-support --disable-plugin --enable-default-pie --with-system-zlib --disable-libphobos --enable-objc-gc=auto --enable-multiarch --disable-werror --disable-multilib --with-mips-plt --with-arch-64=mips64r2 --with-madd4=no --enable-targets=all --disable-checking --build=mips64el-linux-gnuabi64 --host=mips64el-linux-gnuabi64 --target=mips64el-linux-gnuabi64 --enable-targets=all --disable-lto --disable-bootstrap --with-as=${PWD_PATH}/executable_binutils/bin/as" 


    eval "cd $GCC_BUILD_PATH_64 && make -j8 &&   make install"

    cp -r /usr/libn32/* /usr/lib32/

    echo "done" > ${PWD_PATH}/succeed/gcc

fi

echo
echo -e "${GREEN}[*] build gcc succeed!"


rm /usr/bin/as
apt-get install --reinstall binutils

echo
echo -e "${BLUE}======================= build clang ===============================${NC}"
echo

LLVM_PATH=${SRC_PATH}/llvm/llvm-6.0.0
BINUTILS_PATH=${PWD_PATH}/binutils-2.30

cd $PWD_PATH

if [ ! -f ${PWD_PATH}/succeed/clang ]; then
    mkdir -p build_clang
    LLVM_BUILD_DIR=${PWD_PATH}/build_clang
    cd build_clang
    cmake ${LLVM_PATH} -DCMAKE_EXE_LINKER_FLAGS_DEBUG="-I/usr/local/include -L/usr/local/lib -lprotobuf -lpthread" -DLLVM_ENABLE_RTTI=ON -DLLVM_BINUTILS_INCDIR=$BINUTILS_PATH/include -DCMAKE_BUILD_TYPE=Release

    MODIFIED_LINK1="$LLVM_BUILD_DIR/lib/MC/CMakeFiles/LLVMMC.dir/link.txt"
    MODIFIED_LINK2="$LLVM_BUILD_DIR/tools/lto/CMakeFiles/LTO.dir/link.txt"
    MODIFIED_LINK3="$LLVM_BUILD_DIR/tools/clang/tools/libclang/CMakeFiles/libclang.dir/link.txt"
    MODIFIED_LINK4="$LLVM_BUILD_DIR/tools/clang/tools/c-index-test/CMakeFiles/c-index-test.dir/link.txt"

    # Adding /usr/lib/shuffleInfo.so
    sed -i '/LLVMMC.dir/s/$/\ \/usr\/lib\/shuffleInfo\.so/' $MODIFIED_LINK1

    # Adding -I/usr/local/include -L/usr/local/lib -lprotobuf
    sed -i 's/$/\-I\/usr\/local\/include\ \-L\/usr\/local\/lib\ \-lprotobuf/' $MODIFIED_LINK2
    sed -i 's/$/\-I\/usr\/local\/include\ \-L\/usr\/local\/lib\ \-lprotobuf/' $MODIFIED_LINK3
    sed -i 's/$/\-I\/usr\/local\/include\ \-L\/usr\/local\/lib\ \-lprotobuf/' $MODIFIED_LINK4

    cp $PROTODEF_DIR/$CC_HDR $LLVM_PATH/include/llvm/Support/$CC_HDR

    make -j8
    echo "done" > ${PWD_PATH}/succeed/clang
fi

echo
echo -e "${GREEN}[*] build clang succeed!"
echo

cd $PWD_PATH

if [ ! -d ${PWD_PATH}/executable_binutils ]; then
    mkdir -p executable_binutils
    ln -sf $GAS_PATH ${PWD_PATH}/executable_binutils/as
    ln -sf $GOLD_PATH ${PWD_PATH}/executable_binutils/ld
fi

echo
echo -e "${BLUE}======================= build glibc_2.27 ===============================${NC}"
echo

if [ ! -f ${PWD_PATH}/succeed/glibc ]; then
    cd $PWD_PATH

    ENV64=${SRC_PATH}/gcc64.rc
    ENV32=${SRC_PATH}/gcc32.rc

    wget -c https://ftp.gnu.org/gnu/libc/glibc-2.27.tar.xz
    tar -xvf glibc-2.27.tar.xz

    echo
    echo -e "${BLUE}======================= build glibc_2.27(64) ===============================${NC}"
    echo

    mkdir -p glibc_build_32 && cd glibc_build_32

    source $ENV64

    export CFLAGS="-O2 ${CFLAGS}"
    export CXXFLAGS="-O2 ${CXXFLAGS}"

    ../glibc-2.27/configure --prefix=$PWD --enable-kernel=4.15.0 --enable-static --enable-static-nss \
        && make -j8 && make install

    echo "done" > ${PWD_PATH}/succeed/glibc

fi

echo
echo -e "${GREEN}[*] build glibc succeed!"

cd $PWD_PATH

# build python dependency
apt-get -y install python3-pip
cd ${SRC_PATH}
pip3 install -r requirements.txt

echo
echo -e "${GREEN}[*] build succeed${NC}"
