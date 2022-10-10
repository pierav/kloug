#!/bin/bash

if [ ! -d $RISCV ]; then
    mkdir -p $RISCV && chmod 777 $RISCV
    cd $RISCV
    RISCV64_UNKNOWN_ELF_GCC=riscv64-unknown-elf-gcc-8.3.0-2020.04.0-x86_64-linux-ubuntu14.tar.gz
    wget https://static.dev.sifive.com/dev-tools/$RISCV64_UNKNOWN_ELF_GCC 
    tar -x -f $RISCV64_UNKNOWN_ELF_GCC --strip-components=1 -C $RISCV
else
    echo "Using RISCV=$RISCV."
fi