#include <stdio.h>

int max(int, int);
int add(int, int);
int subtract(int, int);
int multiply(int, int);
int divide(int, int);
int print_n_times(int, int);

int max(int a, int b){ return a >= b ? a : b; }
int add(int a, int b){ for(;; b--, a++) if(b <= 0) return a; }
int subtract(int a, int b){ for(;; b--, a--) if(b <= 0) return a; }
int multiply(int a, int b){ for(int c = 0;; b = subtract(b, 1), c = add(c, a)) if(b <= 0) return c; }
int divide(int a, int b){ for(int c = 0;; a = subtract(a, b), c = add(c, 1)) if (a < b) return c; }
int print_n_times(int a, int n){ for(; n > 0; n--) printf("%d", a); }

void main(){ print_n_times(multiply(add(1, 2), subtract(9, 2)), divide(10, max(2, 5))); }
