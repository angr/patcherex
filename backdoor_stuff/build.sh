#!/bin/bash

rm backdoor_pov.pov
rm backdoor_pov.o
/usr/i386-linux-cgc/bin/clang -c -nostdlib -fno-builtin -nostdinc -Iinclude -Ilib -I/usr/include -O0 -g -Werror -Wno-overlength-strings -Wno-packed -Wall -o backdoor_pov.o backdoor_pov.c
/usr/i386-linux-cgc/bin/ld -nostdlib -static -o backdoor_pov.pov backdoor_pov.o -L/usr/lib -lcgc -lpov

