#ifndef STDIO_H_
#define STDIO_H_

typedef int FILE;

#define stdin  0
#define stdout 1
#define stderr 2

extern char **environ;

// file operations are nops
#define vfprintf(stream, format, ap) {; }
#define fputs(string, stream) do {printf("%s", string); } while (0)
#define fputc(c, stream) {; }
//#define fprintf(stream, format, ...) do {; } while(0)
#define fprintf(stream, format, ARGS...) do {printf(format, ##ARGS); } while(0)
#define fflush(x) do {; } while(0)
#define fclose(x) do {; } while(0)
#define fopen(x, y) 1

// hope we never hit these
#define sleep(x) do {; } while (0)
#define popen(x, y) 1
#define pclose(x) do {; } while (0)
#define abort() do {_terminate(1);} while (0)
#define getenv(x) NULL
#define getc(f) EOF
#define getpid() 1

#define EOF -1

#endif /* !STDIO_H_ */
