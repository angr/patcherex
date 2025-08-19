#ifndef STDLIB_H_
#define STDLIB_H_

#include <libcgc.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#define isinf(x) __builtin_isinf(x)
#define isnan(x) __builtin_isnan(x)
int isspace( int c );
int isdigit( int c );
int isnan( double val );
int isinf( double val );
double atof(const char *str);
int atoi(const char *str);
int islower( int c );
int isupper( int c );
int isalpha( int c );
int isalnum( int c );

char *strncpy( char *, const char *, size_t );
int putc( int );
//int printf( const char *fmt, ... );
void bzero( void *, size_t );
void *memset(void *, int, size_t);
char *strncat( char *, const char *, size_t );
int receive_bytes (unsigned char *buffer, size_t size);
size_t receive_until( char *, char, size_t );
size_t receive_until_flush( char *, char , size_t);
size_t itoa( char *, size_t, size_t );
void puts( char *t );
char *strchr(const char *, int);
char *strtok(char *, const char *);
ssize_t write( const void *, size_t );

int putc( int c );

void int_to_str( int val, char *buf );
void int_to_hex( unsigned int val, char *buf );
void float_to_str( double val, char *buf, int precision );
int vprintf( const char *fmt, va_list arg );
int vsprintf( char *str, const char *fmt, va_list arg );
int printf( const char *fmt, ... );
int sprintf( char *str, const char *fmt, ... );

long strtol(const char *str, char **endptr, int base);
unsigned long strtoul(const char *str, char **endptr, int base);

extern void *malloc(size_t size);
extern void *calloc(size_t nmemb, size_t size);
extern void *realloc(void *ptr, size_t size);
extern void free(void *ptr);
extern size_t malloc_size(void *ptr);

int abs(int j);

static void exit(int ret)
{
    _terminate(ret);
}

#endif /* !STDLIB_H_ */
