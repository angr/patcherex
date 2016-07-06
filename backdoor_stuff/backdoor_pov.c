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

/*
int K( int i ) { return
 i < 20 ? K1 : 
 i < 40 ? K2 :
 i < 60 ? K3 : K4;
}

int F( int i, int B, int C, int D ) { return
 i < 20 ?  (D ^ ( B & (C ^ D))) : 
 i < 40 ? (D ^ B ^ C) : 
 i < 60 ? (B & C) | (D & (B ^ C)) : 
 (D ^ B ^ C) ;
}
*/


//---------------------------------------
// right now, this is compiled to 268 bytes with -Oz

#define K1 0x5A827999
#define K2 0x6ED9EBA1
#define K3 0x8F1BBCDC
#define K4 0xCA62C1D6


//TODO it seems this is not used by final compiled code (but it is still present in the compiled code)
// find a way to tell clang to remove it
int ROTATE_LEFT(const int value, int shift) {
    unsigned int uvalue = (unsigned int)value;
    return (uvalue << shift) | (uvalue >> (32- shift));
}



// Update HASH[] by processing a one 64-byte block in MESSAGE[]
__attribute__((__fastcall)) int SHA1(int MESSAGE[] )
{
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
    //send_int_nl(A[i]);
    // W[i] calculation, also known as 'Message Scheduling'
    if ( i < 16 ){
      // reverse the order of bytes on little-endian
      W[i] = MESSAGE[i];
      //send_int_nl(i);
      //send_int_nl(W[i]);
    }else{
      W[i] = ROTATE_LEFT( W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1 );
      //send_int_space(i);
      //send_int_space(W[i-3]);
      //send_int_space(W[i-8]);
      //send_int_space(W[i-14]);
      //send_int_nl(W[i-16]);
      //send_int_nl(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16]);
      //send_int_nl(ROTATE_LEFT( W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1 ));
      //send_int_nl(W[i]);
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

    //FN = F( i, B, C, D );


    //send_int_nl(FN);
    //send_int_nl(E[i]);
    //send_int_nl(W[i]);
    //send_int_nl(K(i));

    An = FN + E + ROTATE_LEFT( A, 5 ) + W[i] + K;
    //send_int_space(A[i+1]);
    //send_int_space(FN);
    //send_int_space(E[i]);
    //send_int_space(K(i));//
    //send_int_nl(W[i]);//

    E = D;
    D = C;
    C = ROTATE_LEFT( B, 30 );
    A = An;
    B = A;
    //send_int_nl(A[i+1]);
  }


  return (0x67452301 + A);
}
//-----------------------


uint32_t sha1block(uint8_t input[5]){
  // this will be written in asm
  uint32_t* addr;
  uint32_t res;

  allocate(0x1000, 0, (void*) &addr);
  addr[0] = input[0]<<24|input[1]<<16|input[2]<<8|input[3];
  addr[1] = input[4]<<24;

  res = SHA1((int*)addr);
  deallocate(addr,0x1000); //not necessary in final code
  //check if i == res (i terminates with zeros, so it must res)
  return res;
}


int main() {
  uint32_t res;
  unsigned int i;

  for(i=0;i<0x80000;i++){
    res = sha1block(&(backdoor_solutions[i*5]));
    //send_str("------");
    //send_int_nl(res);
    if((res!=i) || ((res&0x7ffff)!=res)){
      send_int_space(i);
      send_int_nl(res);
    }
  }

  send_str((unsigned char*)"------\n");  
  return 0;
}


