#include <libcgc.h>


typedef char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;


uint8_t* working_code_on_stack;
uint8_t* working_code_on_heap;
uint32_t gdummy;

uint8_t shellcode[100] = {0x60, 0xB9, 0x01, 0x80, 0x04, 0x08, 0xBA, 0x03, 0x00, 0x00, 0x00, 0xB8, 0x02, 0x00, 0x00, 0x00, 0xBB, 0x01, 0x00, 0x00, 0x00, 0xBE, 0x00, 0x00, 0x00, 0x00, 0xCD, 0x80, 0x61, 0xC3};
char* cstr = (char*)"CGC";

void *memcpy(void *dst, const void *src, size_t n) {
   char *d = (char*)dst;
   const char *s = (const char *)src;
   while (n--) {*d++ = *s++;}
   return dst;
}

size_t receive_until(int fd, char *dst, char delim, size_t max )
{
    size_t len = 0;
    size_t rx = 0;
    char c = 0;

    while( len < max ) {
        dst[len] = 0x00;

        if ( receive( fd, &c, 1, &rx ) != 0 ) {
            len = 0;
            goto end;
        }

        if ( c == delim ) {
            goto end;
        }
   
        dst[len] = c;
        len++;
    }
end:
    return len;
}

size_t receive_n( int fd, unsigned char *dst, size_t n_bytes )
{
  size_t len = 0;
  size_t rx = 0;
  while(len < n_bytes) {
    if (receive(fd, dst + len, n_bytes - len, &rx) != 0) {
      len = 0;
      break;
    }
    len += rx;
  }

  return len;
}

int send_all(int fd, const void *msg, size_t n_bytes)
{
  size_t len = 0;
  size_t tx = 0;
  while(len < n_bytes) {
    if (transmit(fd, (char *)msg + len, n_bytes - len, &tx) != 0) {
      return 1;
    }
    len += tx;
  }
  return 0;
}

int strlen(unsigned char* str){
  int i=0;
  while(str[i]!='\x00'){
    i++;
  }
  return i;
}

void send_str(unsigned char* str){
  send_all(1,(unsigned char*)str,strlen(str));
  return;
}
void send_str_nl(unsigned char* str){
  send_str(str);
  send_all(1,"\n",1);
  return;
}

unsigned int receive_int_nl(){
  unsigned char tmp[9];
  receive_n(0,tmp,9);
  unsigned int result=0;
  int c;

  for(c=0;c<8;c++){
    if (tmp[c] > 47 && tmp[c] < 58)
      result += (tmp[c] - 48);
    else if (tmp[c] > 64 && tmp[c] < 71)
      result += (tmp[c] - 55);
    else if (tmp[c] > 96 && tmp[c] < 103)
      result += (tmp[c] - 87);
    if(c!=8-1){
      result <<= 4;
    }
  }
  return result;
}


int type2_submit(const unsigned char *val, size_t len) {
   return send_all(3, val, len);
}

void int_to_str(int i,unsigned char* tmp){
  uint32_t c;
  uint8_t b;
  for(c=0;c<8;c++){
    b = (i>>(c*4) & 0xf);
    if(b>=10){
      b+=7;
    }
    tmp[8-1-c]='0'+b;
  }
  tmp[8]='\x00';
}

void sprint(){
  void (*fpointer)(unsigned char*);
  fpointer = send_str;
  fpointer((unsigned char*)cstr);
}

void print(){
  send_str((unsigned char*)"AAAA\n");
}

void call_main(){
  void (*fpointer)();
  fpointer = (void (*)()) print;
  fpointer();
}

void call_stack(){
  void (*fpointer)();
  fpointer = (void (*)()) 0xbaaaa000;
  fpointer();
}

void test_stack(){
  uint32_t* a =  (uint32_t*) 0xbaaab000;
  a[0] = 0x41;
  send_str((unsigned char*)a);
}


int main() {
  send_str((unsigned char*)"hello\n");
  unsigned int option;
  
  option = receive_int_nl();
  switch(option){
    case 1:
      call_stack();
    break;
    case 2:
      call_main();
    break;
    case 3:
      test_stack();
    break;
  }

  return 0;
}

