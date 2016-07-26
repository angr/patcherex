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

rm $OUT/indirect_call_test_O0_exec_allocate; $SCRIPT indirect_call_test_exec_allocate.c -O0 -o $OUT/indirect_call_test_O0_exec_allocate

rm $OUT/indirect_jump_test_O0; $SCRIPT indirect_jump_test.c -O0 -o $OUT/indirect_jump_test_O0
rm $OUT/indirect_jump_test_Ofast; $SCRIPT indirect_jump_test.c -Ofast -o $OUT/indirect_jump_test_Ofast
rm $OUT/indirect_jump_test_Oz; $SCRIPT indirect_jump_test.c -Ofast -o $OUT/indirect_jump_test_Oz

rm $OUT/arbitrary_transmit_O0; $SCRIPT arbitrary_transmit.c -O0 -o $OUT/arbitrary_transmit_O0
rm $OUT/arbitrary_transmit_Ofast; $SCRIPT arbitrary_transmit.c -Ofast -o $OUT/arbitrary_transmit_Ofast
rm $OUT/arbitrary_transmit_Oz; $SCRIPT arbitrary_transmit.c -Ofast -o $OUT/arbitrary_transmit_Oz
rm $OUT/arbitrary_transmit_stdin_O0; $SCRIPT arbitrary_transmit_stdin.c -O0 -o $OUT/arbitrary_transmit_stdin_O0
rm $OUT/arbitrary_transmit_stdin_Ofast; $SCRIPT arbitrary_transmit_stdin.c -Ofast -o $OUT/arbitrary_transmit_stdin_Ofast
rm $OUT/arbitrary_transmit_stdin_Oz; $SCRIPT arbitrary_transmit_stdin.c -Ofast -o $OUT/arbitrary_transmit_stdin_Oz

rm $OUT/indirect_call_test_fullmem_O0; $SCRIPT indirect_call_test_fullmem.c -O0 -o $OUT/indirect_call_test_fullmem_O0
printf '\x00\x00\x00\x3a' | dd of=$OUT/indirect_call_test_fullmem_O0 bs=1 seek=136 count=4 conv=notrunc 2> /dev/null

rm $OUT/backdoorme1; $SCRIPT backdoorme1.c -Ofast -o $OUT/backdoorme1
rm $OUT/backdoorme2; $SCRIPT backdoorme2.c -Ofast -o $OUT/backdoorme2
rm $OUT/backdoorme3; $SCRIPT backdoorme3.c -Ofast -o $OUT/backdoorme3
rm $OUT/backdoorme4; $SCRIPT backdoorme4.c -Ofast -o $OUT/backdoorme4
rm $OUT/backdoorme5; $SCRIPT backdoorme5.c -Ofast -o $OUT/backdoorme5
rm $OUT/backdoorme6; $SCRIPT backdoorme6.c -Ofast -o $OUT/backdoorme6
rm $OUT/backdoorme7; $SCRIPT backdoorme7.c -Ofast -o $OUT/backdoorme7
rm $OUT/backdoorme8; $SCRIPT backdoorme8.c -Ofast -o $OUT/backdoorme8
rm $OUT/backdoorme9; $SCRIPT backdoorme9.c -Ofast -o $OUT/backdoorme9

rm $OUT/echo1; $SCRIPT echo1.c -o $OUT/echo1
rm $OUT/echo2; $SCRIPT echo2.c -o $OUT/echo2

# rm $OUT/call_stack_main; $SCRIPT call_stack_main.c -o $OUT/call_stack_main
