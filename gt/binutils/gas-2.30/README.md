binutils-2.30

- handle basic block dummy directives [06/08/2019]
- fix basic block size and fixups [18/08/2019]

## TODO

- [x] Handle assemble file and inline assemble statement
- [x] Handle the new section for fragment
- [x] fix basic block size
- [x] basic block's fixup number equal to total fixup number in .text.xxx section
- [x] figure out what are .text.startup, .text.hot, .text.exit and .text.unlikely section
- [x] Support LTO optimization
- [ ] Handle other sections' fixups(.eh\_frame .etc)
- [x] add padding size of basic block
- [ ] There is problem that compile with static link: `-static-libstdc++ -static-libgcc`
- [ ] .fini\_array section's fixups
- [ ] handle .init and .fini section

## Problems

- Can't handle fixups in section .plt and .got.plt
- Can't handle the linker added functions. (We may handle it by compiling the glibc with our tool, but it seems that gold linker can't work correctly of compiling glibc)

## Build

- Install protobuf-c [link](https://github.com/protobuf-c/protobuf-c)

- set CFLAGS and LDFLAGS
```
CFLAGS=`pkg-config --cflags 'libprotobuf-c >= 1.0.0'`
LDFLAGS=`pkg-config --libs 'libprotobuf-c >= 1.0.0'`
```


