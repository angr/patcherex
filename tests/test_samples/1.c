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

char* cstr = (char*)"cccccccc\n";

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

void vul_fpointer_main(){
  void (*fpointer)();
  fpointer = sprint;
  fpointer();
  fpointer = (void (*)()) receive_int_nl();
  fpointer();
}
void vul_fpointer_stack(){
  void (*fpointer)();
  fpointer = sprint;
  fpointer = (void (*)()) working_code_on_stack;
  fpointer();

  fpointer = (void (*)()) receive_int_nl();
  fpointer();
}
void vul_fpointer_heap(){
  void (*fpointer)();
  fpointer = sprint;
  fpointer = (void (*)()) working_code_on_heap;
  fpointer();

  fpointer = (void (*)()) receive_int_nl();
  fpointer();
}
void vul_fpointer_unknown(){
  void (*fpointer)();
  fpointer = (void (*)()) receive_int_nl();
  fpointer();
}

void sane_fpointer(){
  ;
}
void stable(){
  ;
}

void setup(){
  void (*fpointer)();
  fpointer = sprint;
  int i;
  allocate(0x1000, 1,(void**) &working_code_on_heap);
  working_code_on_stack = (uint8_t*) 0xbaaaa000;

  for(i=0;i<100;i++){
    uint8_t b = *(((uint8_t*) fpointer)+i);
    working_code_on_heap[i] = b;
    working_code_on_stack[i] = b;
  }

}


int main() {
  send_str((unsigned char*)"hello\n");
  uint32_t option;
  unsigned char tmp[9];

  setup();

  option = receive_int_nl();
  switch(option){
    case 1:
      vul_fpointer_main();
    break;
    case 2:
      vul_fpointer_stack();
    break;
    case 3:
      vul_fpointer_heap();
    break;
    case 4:
      vul_fpointer_unknown();
    break;
  }

  return 0;
}

/*
~/git/cgc/compilerex $ PP=../vm/shared/; rm $PP/1; ./compile.sh ../patcherex/tests/test_samples/1.c -o $PP/1
*/
