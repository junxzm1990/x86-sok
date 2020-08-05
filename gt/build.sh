#!/bin/bash

# testing environment: ubuntu 18.04
# build script

set -e


BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

SRC_PATH=`dirname $0`
SRC_PATH=`realpath $SRC_PATH`

PWD_PATH="${SRC_PATH}/build"


if [ ! -d $PWD_PATH ];then
    echo -e "${GREEN}[*] mkdir directory $PWD_PATH${NC}"
    mkdir $PWD_PATH
    mkdir -p $PWD_PATH/succeed
fi

cd $PWD_PATH

BUILD_ESSENTIAL="sudo apt-get -y update && sudo apt-get -y upgrade && \
	sudo apt-get -y install build-essential bison zlib1g-dev libtool cmake linux-libc-dev-i386-cross gcc-multilib g++-multilib libc6-dev-i386"
echo $BUILD_ESSENTIAL
eval $BUILD_ESSENTIAL

# build protobuf
echo
echo -e "${BLUE}===================== build protobuf ======================${NC}"
echo

if [ ! -f ${PWD_PATH}/succeed/protobuf ]; then
    cd $PWD_PATH
    eval "sudo apt-get -y install autoconf automake libtool curl make g++ unzip pkg-config"
    eval "git clone https://github.com/protocolbuffers/protobuf.git"
    eval "cd protobuf && git submodule update --init --recursive && ./autogen.sh"
    eval "./configure && make -j$(nproc) &&  sudo make install && sudo ldconfig"
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
    eval 'cd protobuf-c && ./autogen.sh && ./configure && make -j$(nproc) && sudo  make install'
    eval 'sudo ln -sf /usr/local/lib/libprotobuf-c.so.1.0.0 /usr/lib/libprotobuf-c.so.1'
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
  sudo cp $PROTODEF_DIR/$SHUFFLEINFO $LIB1/$SHUFFLEINFO
  sudo cp $PROTODEF_DIR/$SHUFFLEINFO $LIB2/$SHUFFLEINFO
  sudo cp $PROTODEF_DIR/$SHUFFLEINFO $LIB2/lib$SHUFFLEINFO
  sudo cp $PROTODEF_DIR/$SHUFFLEINFO $LIB1/lib$SHUFFLEINFO


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
    rm -r binutils-2.30/gas
    rm -r binutils-2.30/gold

    cp -r ${SRC_PATH}/binutils/gas-2.30 ${GAS_DIR}

    cp -r ${SRC_PATH}/binutils/gold-2.30 ${GOLD_DIR}

    cp $PROTODEF_DIR/$C_HDR $GAS_DIR

    cp $PROTODEF_DIR/$CC_HDR ${GOLD_DIR}/
    cp $PROTODEF_DIR/$PROTO_C ${GOLD_DIR}/

    eval "cd $PWD_PATH/binutils-2.30 && mkdir -p build && cd build"

    CFLAGS="`pkg-config --cflags 'libprotobuf-c >= 1.0.0'`" LDFLAGS=`pkg-config --libs 'libprotobuf-c >= 1.0.0'` \
            ../configure --enable-gold --prefix=${PWD_PATH}/executable_binutils \
            --disable-werror --enable-shared \
             --enable-ld=default \
	     --enable-plugins    \
             --enable-64-bit-bfd \
             --with-system-zlib \
            && make -j$(nproc)
            # && make install
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
GCC_BUILD_PATH="$PWD_PATH/build_gcc"
GCC_EXE_PATH="$PWD_PATH/executable_gcc"

# soft link gas
eval " sudo cp /usr/bin/as /usr/bin/as.old"
eval " sudo ln -sf $GAS_PATH /usr/bin/as"

echo
echo -e "${BLUE}======================= build gcc ===============================${NC}"
echo
cd $PWD_PATH

if [ ! -f ${PWD_PATH}/succeed/gcc ]; then

    eval "wget -c https://bigsearcher.com/mirrors/gcc/releases/gcc-8.1.0/gcc-8.1.0.tar.xz"
    eval "tar xvJf gcc-8.1.0.tar.xz"
    # eval "mkdir $GCC_EXE_PATH"
    eval "mkdir -p build_gcc && cd build_gcc"

    # download gcc dependencies
    cd $GCC_PATH
    eval "./contrib/download_prerequisites"
    cd $GCC_BUILD_PATH


    # build gcc must use modified binutils-2.30
    BUILD_GCC="../gcc-8.1.0/configure                                           \
           --prefix=$GCC_EXE_PATH                                      \
           --enable-multilib                                 \
        --disable-libmpx \
        --with-system-zlib                                 \
        --program-suffix=-8.1 \
        --enable-languages=c,c++,fortran,go && make -j$(nproc)"

    eval $BUILD_GCC

    rm -r "${GCC_PATH}/gcc"
    cp -r "${SRC_PATH}/gcc/gcc-8.1.0/gcc" ${GCC_PATH}/gcc

      # gcc
    eval "cd $GCC_BUILD_PATH && make -j$(nproc) &&   make install"

    echo "done" > ${PWD_PATH}/succeed/gcc

fi

echo
echo -e "${GREEN}[*] build gcc succeed!"

sudo rm /usr/bin/as
sudo apt-get install --reinstall binutils

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

    make -j$(nproc)
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

    mkdir -p glibc_build_64 && cd glibc_build_64

    source $ENV64

    export CFLAGS="-O2 ${CFLAGS}"
    export CXXFLAGS="-O2 ${CXXFLAGS}"

    ../glibc-2.27/configure --prefix=$PWD --enable-kernel=4.15.0 --enable-static --enable-static-nss \
        && make -j$(nproc) && make install

    echo
    echo -e "${BLUE}======================= build glibc_2.27(32) ===============================${NC}"
    echo

    cd $PWD_PATH

    source $ENV32

    export CFLAGS="-O2 ${CFLAGS}"
    export CXXFLAGS="-O2 ${CXXFLAGS}"

    mkdir -p glibc_build_32 && cd glibc_build_32
    ../glibc-2.27/configure --prefix=$PWD --enable-kernel=4.15.0 --enable-static --enable-static-nss --host=i686-pc-linux-gnu \
       && make -j$(npcorc) && make install

    echo "done" > ${PWD_PATH}/succeed/glibc

fi

echo
echo -e "${GREEN}[*] build glibc succeed!"

cd $PWD_PATH

# build python dependency
sudo apt-get -y install python-pip
cd ${SRC_PATH}
sudo pip install -r requirements.txt

echo
echo -e "${GREEN}[*] build succeed!"
