## Install Protobuf

```
git clone https://github.com/protocolbuffers/protobuf.git
cd protobuf
git submodule update --init --recursive
./autogen.sh

./configure
make
make check
sudo make install
sudo ldconfig
```

## Install other dependencies

```
sudo apt-get install -y libcapstone-dev
sudo apt-get install -y libiberty-dev
```

## Build

```
make
```
