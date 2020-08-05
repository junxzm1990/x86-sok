# x86-sok

We modified compilers(gcc/clang) to collect the information of basic blocks and reconstruct the information of binary code.

For clang, we re-use the implemenation of [CCR](https://github.com/kevinkoo001/CCR).

For gcc, we modifed gcc and gas(GNU assembler).
Modifications can be found at [gcc modification](https://github.com/junxzm1990/x86-sok/blob/master/gt/gcc/gcc-8.1.0/patch_f4eef700) and [gas modification](https://github.com/junxzm1990/x86-sok/blob/master/gt/binutils/patch_as_2_30).

## Build the toolchain

We provide two ways to build the toolchains of compilers: ubuntu18.04 and docker.

### Ubuntu 18.04

If you are using Ubuntu 18.04, we recommend you to build the toolchain in your computer:

```
git clone git@github.com:junxzm1990/x86-sok.git
cd x86-sok/gt
bash build.sh
```


### Docker

TODO.


### Compile binary with our toolchain

TODO.

## Testsuite

TODO.
