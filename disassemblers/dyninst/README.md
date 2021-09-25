## install dyninst

```
git clone https://github.com/dyninst/dyninst.git
cd dyninst && git checkout v9.3.2
mkdir build && cd build && cmake .. && sudo make && sudo make install
sudo apt install libgoogle-glog-dev
```

## install protobuf

```
sudo apt-get install autoconf automake libtool curl make g++ unzip -y
git clone https://github.com/google/protobuf.git
cd protobuf
git submodule update --init --recursive
./autogen.sh
make
make check
sudo make install
sudo ldconfig
```

## build

```
make
```
