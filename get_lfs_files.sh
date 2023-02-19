#!/bin/bash

wget https://www.cs.purdue.edu/homes/antoniob/shared/precompiled_llvm_binaries.tgz
tar -xf precompiled_llvm_binaries.tgz -C patcherex/binary_dependencies/clang/
rm precompiled_llvm_binaries.tgz

wget https://www.cs.purdue.edu/homes/antoniob/shared/powerpc-eabivle.tgz
tar -xf powerpc-eabivle.tgz -C patcherex/binary_dependencies/powerpc-eabivle/
rm powerpc-eabivle.tgz
