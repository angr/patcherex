#include <stdio.h>

// Compiled on Ubuntu 20.04 with flag `-no-pie`

int main(void)
{
    char *str2 = "Goodbye!\n", *str1 = "Hello world!\n";
    printf(str1);
    return 0;
}

