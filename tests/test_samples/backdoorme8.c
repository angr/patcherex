#include <libcgc.h>

typedef char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;


void *memcpy(void *dst, const void *src, size_t n) {
   char *d = (char*)dst;
   const char *s = (const char *)src;
   while (n--) {*d++ = *s++;}
   return dst;
}

int strlen(char *s) {
  int len = 0;
  while (s[len]) {
    len++;
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

void send_str(unsigned char* str){
  send_all(1,(unsigned char*)str,strlen((char*)str));
  return;
}

void send_str_nl(unsigned char* str){
  send_str(str);
  send_all(1,"\n",1);
  return;
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

size_t receive_until_str(int fd, char *dst, const char* delim, int delim_length, size_t max )
{
    size_t len = 0;
    size_t rx = 0;
    char c = 0;
    int delim_idx = 0;
    while( len < max ) {
        dst[len] = 0x00;

        if ( receive( fd, &c, 1, &rx ) != 0 ) {
            len = 0;
            goto end;
        }
        if ( c == delim[delim_idx] ) {
            delim_idx += 1;
        }else{
            delim_idx = 0;
        }
        if ( delim_idx == delim_length ){
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
void send_int_nl(uint32_t input){
  unsigned char tmp[9];
  unsigned int nibble;
  tmp[8] = '\x00';
  int c;

  for(c=7;c>=0;c--){
    nibble = input & 0x0000000f;
    if (nibble < 10)
      tmp[c] = nibble+48;
    else
      tmp[c] = nibble+55;;
    input >>= 4;
  }
  send_str_nl(tmp);
}
void send_int_space(uint32_t input){
  unsigned char tmp[9];
  unsigned int nibble;
  tmp[8] = '\x00';
  int c;

  for(c=7;c>=0;c--){
    nibble = input & 0x0000000f;
    if (nibble < 10)
      tmp[c] = nibble+48;
    else
      tmp[c] = nibble+55;;
    input >>= 4;
  }
  send_str(tmp);
  send_str((unsigned char*)" ");
}

void sleep(int secs, int usecs) {
    struct timeval tv;
    tv.tv_sec = secs;
    tv.tv_usec = usecs;
    fdwait(0, NULL, NULL, &tv, NULL);
}

int main() {
  uint8_t bigbuffer[100000];
  int c;
  receive(0,&bigbuffer,1,NULL);
  // send the backdoor delimiter --> the backdoor will fail
  send_all(1,"\x04\xd0\xcc\xba",4);
  sleep(5,0);
  receive(0,&bigbuffer,100,NULL);

  return 0;}


