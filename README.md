
## We are releasing our code and data step by step. Stay tuned!


# x86-sok

## The Framework of compilers

We modified compilers(gcc/clang) to collect the information of basic blocks and reconstruct the information of binary code.
And we want to extract executable file's basic block, jump table, fixup/reference and function information in compilation tool and can help to evaluate disassemblers.

For clang, we re-use the implemenation of [CCR](https://github.com/kevinkoo001/CCR).

```
                                                              |
 ===============       ===============       ===============  |     =============
||             ||     ||             ||     ||             || |    ||           ||
|| preprocess  ||  +  ||   compile   ||  +  ||  assemble   || | +  ||   link    ||  => executable
||             ||     ||             ||     ||             || |    ||           ||
 ===============       ===============       ===============  |     =============
               llvm/clang              MC Componment          |      linker(gold)

```

For gcc, we modifed gcc and gas(GNU assembler).
Modifications can be found at [gcc modification](https://github.com/junxzm1990/x86-sok/blob/master/gt/gcc/gcc-8.1.0/patch_f4eef700) and [gas modification](https://github.com/junxzm1990/x86-sok/blob/master/gt/binutils/patch_as_2_30).


```
                                        |                      |
 ===============       ===============  |     ===============  |     =============
||             ||     ||             || |    ||             || |    ||           ||
|| preprocess  ||  +  ||   compile   || | +  ||  assemble   || | +  ||   link    ||  => executable
||             ||     ||             || |    ||             || |    ||           ||
 ===============       ===============  |     ===============  |     =============
                  gcc                   |      assembler(gas)  |      linker(gold)

```

There exist some differences between llvm toolchains(based on ccr) and gcc toolchains. In llvm, it has [MC componment](http://blog.llvm.org/2010/04/intro-to-llvm-mc-project.html) that combines `compilation` and `assembling` together internally. While gcc outputs the .s file after compilation, and invoke `assembler(gas)` to assemble the .s file into object. So it is easier to extract the basic block and jump table information in compilation and store this information in object file after assembling in llvm toolchains when comparing to gcc toolchains.

As basic block, function, and jump table information can only be collected in compilation stage, so firstly, we output the related information into .s file, and then we reconstruct these information in assembler(gas).


## Build the compilers

We provide two ways to build the toolchains of compilers: ubuntu18.04 and docker.

### Ubuntu 18.04

If you are using Ubuntu 18.04, we recommend you to build the toolchain in your computer:

```console
$ git clone git@github.com:junxzm1990/x86-sok.git
$ cd x86-sok/gt
$ bash build.sh
```

The gcc/g++ are installed in `gt/build/executable_gcc/bin`, clang/clang++ are installed in `gt/build/build_clang/bin`. We also build glibc by using our toolchain so that the compiled glibc contains the information emitted by compiler. Glibc is installed in `gt/build/glibc_build_32` or `gt/build/glibc_build_64`. 

For convenience, we provide config scripts to set `CC`, `CXX`, `CFLAGS`, `CXXFLAGS`, `LDFLAGS`. These configs are `gt/gcc64.rc`, `gt/gcc32.rc`, `gt/clang64.rc` and `gt/clang32.rc`.

Before compiling, we can  set proper configures by:

```console
# for example, we want to compile the source code by gcc
$ source gcc64.rc

# set the proper optimization level
$ export CFLAGS="-O2 $CFLAGS" && export CXXFLAGS="-O2 $CXXFLAGS"
```


### Docker

If you prefer to use Docker, we also provides script to build docker image.

```console
# install docker firstly
$ curl -fsSL https://get.docker.com/ | sudo sh
$ sudo usermod -aG docker [user_id]

# build our toolchain
$ git clone git@github.com:junxzm1990/x86-sok.git
$ cd x86-sok/gt
$ docker build -t x86_gt ./

# check the image
$ docker image ls
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
x86_gt              latest              85f6fb2d4257        2 minutes ago       20.5GB

# launch the image
$ docker run --rm -it x86_gt:latest /bin/bash

# configure CC, CXX, CFLAGS, CXXFLAGS, LDFLAGS
$ source ./gcc64.rc
$ export CFLAGS="-O2 $CLFAGS" && export CXXFLAGS="-O2 $CXXFLAGS"
```

Or pull the image from Docker Hub:

```console
$ docker pull bin2415/x86_gt:0.1

# check the image
$ docker image ls
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
bin2415/x86_gt      0.1                 85f6fb2d4257        3 minutes ago       20.5GB

# launch the image
$ docker run --rm -it bin2415/x86_gt:0.1 /bin/bash

# configure CC, CXX, CFLAGS, CXXFLAGS, LDFLAGS
$ source ./gcc64.rc
$ export CFLAGS="-O2 $CLFAGS" && export CXXFLAGS="-O2 $CXXFLAGS"
```


### Compile binary with our toolchain

TODO.

## Testsuite

TODO.
