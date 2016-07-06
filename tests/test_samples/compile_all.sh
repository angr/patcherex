#!/bin/bash

SCRIPT=./compile.sh

if [ "$1" == "vm" ]; then
    OUT="../../../vm/shared/"
else
    OUT="../../../binaries-private/tests/i386/patchrex/"
fi

rm $OUT/indirect_call_test_O0; $SCRIPT indirect_call_test.c -O0 -o $OUT/indirect_call_test_O0
rm $OUT/indirect_call_test_Ofast; $SCRIPT indirect_call_test.c -Ofast -o $OUT/indirect_call_test_Ofast
rm $OUT/indirect_call_test_Oz; $SCRIPT indirect_call_test.c -Oz -o $OUT/indirect_call_test_Oz

rm $OUT/indirect_jump_test_O0; $SCRIPT indirect_jump_test.c -O0 -o $OUT/indirect_jump_test_O0
rm $OUT/indirect_jump_test_Ofast; $SCRIPT indirect_jump_test.c -Ofast -o $OUT/indirect_jump_test_Ofast
rm $OUT/indirect_jump_test_Oz; $SCRIPT indirect_jump_test.c -Ofast -o $OUT/indirect_jump_test_Oz

rm $OUT/arbitrary_transmit_O0; $SCRIPT arbitrary_transmit.c -O0 -o $OUT/arbitrary_transmit_O0
rm $OUT/arbitrary_transmit_Ofast; $SCRIPT arbitrary_transmit.c -Ofast -o $OUT/arbitrary_transmit_Ofast
rm $OUT/arbitrary_transmit_Oz; $SCRIPT arbitrary_transmit.c -Ofast -o $OUT/arbitrary_transmit_Oz

rm $OUT/indirect_call_test_fullmem_O0; $SCRIPT indirect_call_test_fullmem.c -O0 -o $OUT/indirect_call_test_fullmem_O0
printf '\x00\x00\x00\x3a' | dd of=$OUT/indirect_call_test_fullmem_O0 bs=1 seek=136 count=4 conv=notrunc 2> /dev/null

rm $OUT/backdoorme1; $SCRIPT backdoorme1.c -Ofast -o $OUT/backdoorme1
rm $OUT/backdoorme2; $SCRIPT backdoorme2.c -Ofast -o $OUT/backdoorme2
rm $OUT/backdoorme3; $SCRIPT backdoorme3.c -Ofast -o $OUT/backdoorme3
rm $OUT/backdoorme4; $SCRIPT backdoorme4.c -Ofast -o $OUT/backdoorme4
rm $OUT/backdoorme5; $SCRIPT backdoorme5.c -Ofast -o $OUT/backdoorme5
