/*
Implementation of Skinny128/128 with AVX2.

This code verifies the test vectors for Skinny and can
also be used to run benchmarks.
*/

/*
Skinny implementation

Code based on https://github.com/kste/skinny_avx
*/

#include "stdio.h"
#include "stdlib.h"
#include <string.h>
#include "Skinny128128AVX2.h"
#include "timing.h"

#define NUM_TIMINGS 25000
#define TESTRUN 0

//Skinny encryption using 64 blocks
#include "skinny128.c"
#include "skinny_1s.c"

extern void unpack_and_store_message(unsigned char *out, u256 x[32]);
extern void pack_message(u256 x[32], const unsigned char *in);
extern void pack_mes_tweak( const unsigned char *in, unsigned long long offset);
extern void pack_ad_tweak( const unsigned char *in, unsigned long long offset);

// Debug print function
#if DEBUG
void print256_asint(const u256 in)
{
	unsigned char arr[32];
	_mm256_storeu_si256((u256 *)&arr[0], in);
	int i;
	for(i=0;i<32;++i)
	{
		printf("%d ",arr[i]);
	}
	printf("\n");
}
#endif

#if IDX_PROP
unsigned char the_tweak[1024];
#elif PRECOMPUTE
void precompute_tweaks(unsigned long long len_mes, unsigned long long len_ad, u256 *tw_ad, u256 *tw_mes){
		
		
		
		unsigned char tw[1024];
		memset(tw,0,1024);
		unsigned long long *high, *low;
		unsigned char ch = 0;
		unsigned long long j;
		unsigned char i;
		for(j=0;j<len_ad;j+=1024){
			for(i=0;i<64;++i){
				low = &tw[16*i+15];
				tw[16*i] = 32;
				(*low) = ch;
				++ch;
			}
			#if DEBUG
			for(i=16;i<32;++i){
					printf("%d ",tw[i]);
			}
			printf("\n\n");
			#endif
			pack_tweak(tw_ad, tw,(j/32));
			
		}
		ch = 0;
		for(j=0;j<len_mes;j+=1024){
			for(i=0;i<64;++i){
				low = &tw[15+16*i];
				(*low) += ch;
				tw[16*i] = 0;
				++ch;
			}
			pack_tweak(tw_mes, tw,(j/32));
		}
}
#endif

int crypto_stream_skinny128128ecb_avx2(
  unsigned char *out,
  unsigned char *in,
  unsigned long long inlen,
  const unsigned char *k
) 
{
  int i, j;
  #if TWEAK
  u256 rk[48][16];
  #else
  u256 rk[40][16];
  #endif
  u256 x[32];
  u256 key;

  if (!inlen) {
	  return 0;
	}
	
	int z;
  key_schedule(k, rk); 

  while(inlen >= 1024){
      pack_message(x, in);
	  #if DEBUG
	  for(z=0;z<32;++z)
	  {
		  printf("x[%d]: ",z);
		  print256_asint(x[z]);
	  }
	  #endif
      encrypt_64blocks(x, rk);
      unpack_and_store_message(out, x);
    
    inlen -= 1024;
    in += 1024;
    out += 1024;
  }

  return 0;
}
 
  #if IDX_PROP
void reset_tweak()
{
	unsigned long long *ptr;
	int i;
	unsigned char ch = 0;
	for(i=0;i<1024;i+=8)
	{
		ptr = &the_tweak[i];
		(*ptr) = 0;
	}
	for(i=8;i<1024;i+=16)
	{
		ptr = &the_tweak[i];
		(*ptr) += ch;
		++ch;
	}
}	  
#elif PRECOMPUTE
void reset_tweak(const unsigned char at[16], const unsigned long long mlen, u256 *tw_mes){
	int i;
	unsigned char tmp[32];
	tmp[0] = at[0] | 0x80;
	tmp[16] = tmp[0];
	
	unsigned char tmp_32[32];
	  memcpy(tmp+1,at+1,15);
	  memcpy(tmp+17,at+1,15);
	
	u256 tk[32];
	pack_key(tk,tmp);
	/*#if DEBUG
	printf("Packed tag\n");
	print_tweak(1024,tk);
	#endif*/
	for(i=0;i<(mlen/32);++i){
		tw_mes[i] ^= tk[i%32];
	}
}	

#endif
  
  
  #if (DEBUG && IDX_PROP)
 void print_tweak()
 {
	int j,i;
	for(j=0;j<64;++j)
	{
		for(i=0;i<16;++i){
			printf("%d ",the_tweak[16*j+i]);
		}
		printf("\n");
	}
	printf("\n\n\n");
 } 
    
 #elif (DEBUG && !IDX_PROP)
 void print_something(const unsigned char in[1024]){
	 int i,j;
	 for(i=0;i<64;++i){
		 for(j=0;j<16;++j){
			 printf("%d ",in[16*i+j]);
		 }
		 printf("\n");
	 } 
 }
 
 void print_tweak(int len, const u256 *tw)
 {
	int j;
		for(j=0;j<(len/32);++j)
		{
			print256_asint(tw[j]);
		}
	printf("\n\n\n");
 } 
 
 #endif
 
  void encrypt_deoxys(unsigned char *out,
  unsigned char *in,
  unsigned long long inlen,
  const unsigned char *k, const unsigned char *ad, unsigned long long adlen, const unsigned char nonce[15],unsigned char at[16], u256 *tweak_pre, u256 *tweak_pre_ad) /* This may literally be the dumbest way, excluding offensively stupid ways, I could do this, but it has two advantages: 1) I don't fuck with the Skinny internals. 2) It's simple.*/
  {
		#if DEBUG
	  printf("Entering encrypt:\n");
	  #endif
	  u256 rk[48][16];
	  int i,j;
	  key_schedule(k,rk);
	
	  
	  unsigned char buffer[1024];
	  unsigned char auth[16] = {0x00,0x00,0x00,0x00,  0x00,0x00,0x00,0x00  ,0x00,0x00,0x00,0x00,  0x00,0x00,0x00,0x00};
	  
	  u256 x[32];
	  unsigned long long *ptr,*ptr2,*ptr3;
	  unsigned char tk_1s[32];
	  unsigned char n[16];
	  memcpy(n+ 1, nonce , 15);
	  // Additional data processing
	  #if IDX_PROP
	  for(i=0;i<64;++i){
		ptr = &the_tweak[16*i];
		(*ptr)+=32; /* Thank you Stefan */
	  }
	  #endif
	  
	  for(i=0;i<adlen;i+=1024){ // Or maybe just 64
			memcpy(buffer, ad + i, 1024);
			pack_message(x, buffer);
			expand_tweak(i/32,tweak_pre_ad);
			encrypt_64blocks(x,rk);
			
			unpack_and_store_message(buffer,x);
			
			ptr = &auth[0];
			for(j=0;j<64;++j)
			{
				ptr2 = &buffer[16*j];
				(*ptr) ^= (*ptr2);
			}
			ptr = &auth[8];
			for(j=0;j<64;++j)
			{
				ptr2 = &buffer[16*j+8];
				(*ptr) ^= (*ptr2);
			}
			
	  }
	  #if DEBUG
	  printf("AD, encr\n");
	  for(i=0;i<16;++i){
		printf("%d ",auth[i]);
		}
		printf("\n");
	#endif
	
	#if IDX_PROP
	  reset_tweak();
	  #endif
	  
	  for(i=0;i<inlen;i+=1024){ 
			memcpy(buffer, in + i, 1024);
			pack_message(x, buffer);
			expand_tweak(i/32,tweak_pre);
			encrypt_64blocks(x,rk);
			unpack_and_store_message(buffer,x);
			ptr = &auth[0];
			for(j=0;j<64;++j)
			{
				ptr2 = &buffer[16*j];
				(*ptr) ^= (*ptr2);
			}
			ptr = &auth[8];
			for(j=0;j<64;++j)
			{
				ptr2 = &buffer[16*j+8];
				(*ptr) ^= (*ptr2);
			}
			
	  }
	  
	  n[0] = 0x10;
	  
	  memcpy(tk_1s,k,16);
	  memcpy(tk_1s+16,n,16);
	  
	  
	  sk1_enc(auth,tk_1s);
	  
	  memcpy(at,auth,16);
	  
	  #if IDX_PROP
	  reset_tweak();
	  #endif

	  auth[0] = auth[0] | 0x80;
	   
	   #if IDX_PROP
	   ptr = &auth[0];
	  	   
	   for(j=0;j<1024;j+=16)
	   {
		   ptr2 = &the_tweak[j];
		   (*ptr2) ^= (*ptr);
		   
	   }
	   
	   ptr = &auth[8];
	   
	   for(j=8;j<1024;j+=16)
	   {
		   ptr2 = &the_tweak[j];
		   (*ptr2) ^= (*ptr); 
	   }
	   #elif PRECOMPUTE
	   unsigned char tmp_32[32];
	   memcpy(tmp_32,auth,16);
	   memcpy(tmp_32+16,auth,16);
	   u256 tw_tag[32];
	   pack_key(tw_tag,tmp_32);
	   #if DEBUG
	  printf("Tag, encr:\n");
	  for(i=0;i<16;++i){
		printf("%d ",auth[i]);
		}
		printf("\n");
		#endif
	   for(i=0;i<(inlen/32);++i){
			tweak_pre[i] ^= tw_tag[i%32];
	   }
	   // print_tweak(inlen,tweak_pre);
	   // printf("That's three prints\n");
	   #endif 
	
		
		
// Encryption	
	n[0] = 0x00;
	   // printf("Tweak at encr:\n");print_tweak();
	for(i=0;i<inlen;i+=1024){ // Or maybe just 64
			for(j=0;j<64;++j){
				memcpy(buffer + 16*j, &n, 16);
			}
			pack_message(x, buffer);
			expand_tweak(i/32,tweak_pre);
			encrypt_64blocks(x,rk);
			
			unpack_and_store_message(buffer,x);
			/*printf("Encr output buffer\n");
			print_something(buffer);*/
			for(j=0;j<64;++j){
				ptr = &out[16*j+i];
				ptr2 = &in[16*j+i];
				ptr3 = &buffer[16*j];
				(*ptr) ^= (*ptr2)^(*ptr3);
				
			}
			
			for(j=0;j<64;++j){
				ptr = &out[16*j+8+i];
				ptr2 = &in[16*j+8+i];
				ptr3 = &buffer[16*j+8];
				(*ptr) ^= (*ptr2)^(*ptr3);
				
			}
			
	  }
  }
	
	  
  
  int decrypt_deoxys(unsigned char *pt,
  unsigned char *ct,
  unsigned long long inlen,
  const unsigned char *k, const unsigned char *ad, unsigned long long adlen, const unsigned char nonce[15],unsigned char at[16], u256 *tweak_pre, u256 *tweak_pre_ad) /* This may literally be the dumbest way, excluding offensively stupid ways, I could do this, but it has two advantages: 1) I don't fuck with the Skinny internals. 2) It's simple.*/
  {
	  #if DEBUG
	  printf("Entering decrypt:\n");
	  #endif
	   u256 rk[48][16];
	   int i,j;
	  key_schedule(k,rk);
	    
	  unsigned char buffer[1024];
	  unsigned char tag1[16];
	  memcpy(tag1,at,16);
	  unsigned char auth[16] = {0x00,0x00,0x00,0x00,  0x00,0x00,0x00,0x00  ,0x00,0x00,0x00,0x00,  0x00,0x00,0x00,0x00};
	  u256 x[32];
	  unsigned long long *ptr,*ptr2,*ptr3;
	  unsigned char tk_1s[32];
	  unsigned char n[16];
	  n[0] = 0x00;
	  memcpy(n+ 1, nonce , 15);
	  
	   
	  
	  // Set up tweak for decrypt
	  tag1[0] = tag1[0] | 0x80;
	  #if IDX_PROP
	   ptr = &auth[0];
	  	   
	   for(j=0;j<1024;j+=16)
	   {
		   ptr2 = &the_tweak[j];
		   (*ptr2) ^= (*ptr);
		   
	   }
	   
	   ptr = &auth[8];
	   
	   for(j=8;j<1024;j+=16)
	   {
		   ptr2 = &the_tweak[j];
		   (*ptr2) ^= (*ptr); 
	   }
	   #elif PRECOMPUTE
	   #if DEBUG
	  printf("at, decr:\n");
	  for(i=0;i<16;++i){
		printf("%d ",tag1[i]);
		}
		printf("\n");
		#endif
		unsigned char tmp_32[32];
		memcpy(tmp_32,tag1,16);
		memcpy(tmp_32+16,tag1,16);
	   u256 tw_tag[32];
	   pack_key(tw_tag,tmp_32);
	   #if DEBUG
	   // print_tweak(inlen,tweak_pre);
	   #endif
	   for(i=0;i<(inlen/32);++i){
			tweak_pre[i] ^= tw_tag[i%32];
	   }
	   
	   #endif 
	  
	  // printf("Tweak at decr:\n");print_tweak();
	  // Decryption
	  
	  for(i=0;i<inlen;i+=1024){
		  #if DEBUG
		  printf("Iteration number %d\n",i); // 
		  #endif 
		  for(j=0;j<64;++j){
				memcpy(buffer + 16*j, &n, 16);
			}
			
			
			pack_message(x, buffer);
			expand_tweak(i/32,tweak_pre);
			encrypt_64blocks(x,rk);
			
			unpack_and_store_message(buffer,x);
			 
			/*printf("Decr output buffer\n");
			print_something(buffer);*/
			 
			for(j=0;j<64;++j){
				ptr = &pt[16*j+i];
				ptr2 = &ct[16*j+i];
				ptr3 = &buffer[16*j];
				(*ptr) = (*ptr2)^(*ptr3);
				
			}
			
			for(j=0;j<64;++j){
				ptr = &pt[16*j+8+i];
				ptr2 = &ct[16*j+8+i];
				ptr3 = &buffer[16*j+8];
				(*ptr) = (*ptr2)^(*ptr3);
				
			}
			
	  }
	  
	  // Remove tag from tweak
	  #if IDX_PROP
	  reset_tweak();
	  #elif PRECOMPUTE
	  for(i=0;i<(inlen/32);++i){
			tweak_pre[i] ^= tw_tag[i%32];
	   }
	   
	   #endif
	  
	  
	  // Additional data processing
	  #if IDX_PROP
	  for(i=0;i<64;++i){
		ptr = &the_tweak[16*i];
		(*ptr)+=32; /* Thank you Stefan */
	  }
	  #endif
	  
	  
	  for(i=0;i<adlen;i+=1024){ 
			memcpy(buffer, ad + i, 1024);
			pack_message(x, buffer);
			
			expand_tweak(i/32,tweak_pre_ad);
			encrypt_64blocks(x,rk);
			#if (DEBUG && 0)
			printf("The values of x, decr, AD, pre\n");
			for(j=0;j<32;++j){
				print256_asint(x[j]);
			}
			#endif // */
			unpack_and_store_message(buffer,x);
			// print_something(buffer);
			// printf("Buffer, AD, decr\n");
			// print_something(buffer);*/
			ptr = &auth[0];
			for(j=0;j<64;++j)
			{
				ptr2 = &buffer[16*j];
				(*ptr) ^= (*ptr2);
			}
			ptr = &auth[8];
			for(j=0;j<64;++j)
			{
				ptr2 = &buffer[16*j+8];
				(*ptr) ^= (*ptr2);
			}
			
	  }
	  
	  #if DEBUG
	  printf("AD processed, decr:\n");
	  for(i=0;i<16;++i){
		printf("%d ",auth[i]);
		}
		printf("\n");
		#endif
	 
	  // Tag generation
	   
	   #if IDX_PROP
	   reset_tweak();
	   #endif
	  
	  // From the Deoxys paper "tag <- Auth"  =>  Just use auth...
	  
	  for(i=0;i<inlen;i+=1024){ // Or maybe just 64
			memcpy(buffer, pt + i, 1024);
			pack_message(x, buffer);
			expand_tweak(i/32,tweak_pre);
			encrypt_64blocks(x,rk);
			unpack_and_store_message(buffer,x);
			
			ptr = &auth[0];
			for(j=0;j<64;++j)
			{
				ptr2 = &buffer[16*j];
				(*ptr) ^= (*ptr2);
			}
			ptr = &auth[8];
			for(j=0;j<64;++j)
			{
				ptr2 = &buffer[16*j+8];
				(*ptr) ^= (*ptr2);
			}
			
	  }
	  
	  memcpy(tk_1s,k,16);
	  n[0] = 0x10;
	  memcpy(tk_1s+16,n,16);
	  #if DEBUG
	  printf("The tag, decr:\n");
	  for(i=0;i<16;++i){
		printf("%d ",auth[i]);
	}
	printf("\n");
	#endif
	  sk1_enc(auth,tk_1s);
	  
	  
		for(i=0;i<16;++i)
		{
			
			if(at[i]!=auth[i]){
				printf("Oh shit!\n"); /* Should have memory wipe here, but I want to see what comes out. It appears that I am a masochist (or a good coder, but who actually believes that?)*/ 
				return -1;
			}
		}
				
	return 0;
	  
  }
  

void check_testvector() {
  unsigned char *in,*out;
  unsigned long long inlen;

  int i;
  //Encrypt the test vector
  
  #if TWEAK
   unsigned char plaintext[16] = {0x3a,0x0c,0x47,0x76,0x7a,0x26,0xa6,0x8d,
								0xd3,0x82,0xa6,0x95,0xe7,0x02,0x2e,0x25};

  unsigned char k[32] = {0x00,0x9c,0xec,0x81,0x60,0x5d,0x4a,0xc1,						 
						0xd2,0xae,0x9e,0x30,0x85,0xd7,0xa1,0xf3,
						0x1a,0xc1,0x23,0xeb,0xfc,0x00,0xfd,0xdc,
						0xf0,0x10,0x46,0xce,0xed,0xdf,0xca,0xb3};

 unsigned ciphertext[16] = {0xb7,0x31,0xd9,0x8a,0x4b,0xde,0x14,0x7a,
							0x7e,0xd4,0xa6,0xf1,0x6b,0x9b,0x58,0x7f};
	#else
  
  unsigned char plaintext[16] = {0xf2,0x0a,0xdb,0x0e,0xb0,0x8b,0x64,0x8a,
                                 0x3b,0x2e,0xee,0xd1,0xf0,0xad,0xda,0x14};
  unsigned char k[16] = {0x4f,0x55,0xcf,0xb0,0x52,0x0c,0xac,0x52,
                         0xfd,0x92,0xc1,0x5f,0x37,0x07,0x3e,0x93}; // 128 bits = keys....
						 
  unsigned char ciphertext[16] = {0x22,0xff,0x30,0xd4,0x98,0xea,0x62,0xd7,
                             0xe4,0x5b,0x47,0x6e,0x33,0x67,0x5b,0x74};
	#endif

  //Generate 64 blocks of plaintext
  inlen = 1024;
  in = malloc(1024);
  out = malloc(1024);
  for(i = 0; i < 64; i++){ 
    memcpy(in + 16*i, &plaintext, 16);
  }
  
  
  #if DEBUG
  int j;
  printf("I do not want to see this\n");
  for(j=0;j<64;++j)
  {
	  for(i=0;i<16;++i)
	  {
		  printf("%d ",in[j*16+i]);
	  }
	  printf("\n");
  }
  printf("\n\n\n"); 
  //Generate the output stream
  crypto_stream_skinny128128ecb_avx2(out,in,inlen,k);

  //Validate outputstream
  for(i = 0; i < 1024; i++) {
    if(out[i] != ciphertext[i % 16]) {
      printf("ERROR: Outputstream does not match test vector at position %i!\n", i);
    }
  } 
  
  #endif

}



int cmp_dbl(const void *x, const void *y)
{
  double xx = *(double*)x, yy = *(double*)y;
  if (xx < yy) return -1;
  if (xx > yy) return  1;
  return 0;
}

int main() {
	int i,j;
	#if (TEST_FUNCTIONALITY && !TEST_DEOXYS)
  check_testvector();
   #elif TEST_DEOXYS 
   const unsigned int mlen = 1024*2;
   unsigned char plaintext[16] = "0123456789abcdef";
   unsigned char add[16] = "fedcba9876543210";
   unsigned char *in = malloc(mlen);
   unsigned char *ad = malloc(1024);
   unsigned char *real_pt = malloc(mlen);
   unsigned char *out = malloc(mlen);
   unsigned char nonce[15] = "noncenoncenonce";
   unsigned char key[16] = "keykeykeykeykey!";
   unsigned char *pt = malloc(mlen);
   unsigned char *add_tag = malloc(16);
   for(i = 0; i < (mlen/16); i++){ 
    memcpy(in + 16*i, &plaintext, 16);
	memcpy(real_pt + 16*i, &plaintext, 16);
	if(i<64){
	memcpy(ad + 16*i, &add, 16);}
   }
   
   u256 *tweak_pre = _mm_malloc(mlen,32); 
	u256 *tweak_pre_ad = _mm_malloc(1024,32); 
   memset(out,0,mlen);
   // #if !TEST_PRECOMPUTE
   #if PRECOMPUTE
   printf("Precomputing tweaks\n"); // 
   precompute_tweaks(mlen,1024,tweak_pre_ad,tweak_pre);
   printf("Tweaks precomputed\n");
   #if DEBUG
	   // print_tweak(mlen,tweak_pre);
	   // printf("Printing AD tweaks\n");
	   // print_tweak(1024,tweak_pre_ad);
	   #endif
   #endif
   
   encrypt_deoxys(out, in, mlen,key,ad,1024,nonce,add_tag,tweak_pre,tweak_pre_ad);
   
   memset(in,0,mlen);
   #if IDX_PROP
   
   memset(the_tweak,0,1024);
   
   
   #elif PRECOMPUTE
   #if DEBUG
		printf("Tags to reset\n");
	   // print_tweak(mlen,tweak_pre);
	   // print_tweak(1024,add_tag);
	   printf("Right before reset\n");
	#endif
   reset_tweak(add_tag,mlen,tweak_pre);
   #if DEBUG
	   // print_tweak(mlen,tweak_pre);
	   #endif
   
   #endif
   
   if(decrypt_deoxys(in, out, mlen,key,ad,1024,nonce,add_tag,tweak_pre,tweak_pre_ad))
   {
		
	   printf("Damn\n");
	   #if VERIFY_OUTPUT
	   for(i=0;i<mlen;++i){
			printf("%d ",in[i]);
			if(i> 0 && i%16==0)
			{
				printf("\n");
			} // */
		}
		#endif
   }
   else
   {
		
		printf("Awesome\nLet's have a look:\n");
		#if VERIFY_OUTPUT
		for(i=0;i<mlen;++i){
			printf("%c",in[i]);
			if(i> 0 && i%16==0)
			{
				printf("\n");
			}
		}
		#endif
   }
   
   printf("\n");
   #else
	  //  printf("Precomputing tweaks\n");
    // precompute_tweaks(1);
	// printf("Tweaks precomputed\n");
   encrypt_deoxys(out, in, 1024,key,ad,1024,nonce,add_tag);
   
   memset(in,0,1024);
   memset(the_tweak,0,1024);
   
   if(decrypt_deoxys(in, out, 1024,key,ad,1024,nonce,add_tag))
   {
	   printf("Damn\n");
	   for(i=0;i<1024;++i){
			printf("%d ",in[i]);
			if(i> 0 && i%16==0)
			{
				printf("\n");
			} // */
		}
   }
   else
   {
		printf("Awesome\nLet's have a look:\n");
		for(i=0;i<1024;++i){
			printf("%c",in[i]);
			if(i> 0 && i%16==0)
			{
				printf("\n");
			}
		}
   }
   printf("\n");
   
   #endif

  //  #endif
  //Benchmark Skinny
  #if TIMED_RUN && !DEBUG
  free(tweak_pre);
  free(tweak_pre_ad);
  unsigned char *inn, *outt, *k;
  unsigned long long inlen;
  u64 timer = 0;
  double timings[NUM_TIMINGS];

  

  srand(0);
  inlen = 1024*128; // 1,2,4,8,16,32,64,128
  inn = malloc(inlen);
  outt = malloc(inlen);
  k = malloc(16);

  u256 *tweak_pre_2 = _mm_malloc(inlen,32);
  u256 *tweak_pre_ad_2 = _mm_malloc(1024,32);
   precompute_tweaks(inlen,1024,tweak_pre_ad_2,tweak_pre_2);
   int z;
  for(z=0;z<100;++z){
	  for(i = -1000; i < NUM_TIMINGS; i++){
		//Get random input
		for(j = 0; j < inlen; j++) 
		{
		  inn[j] = rand() & 0xff;
		}
		for(j = 0; j < 16; j++) {
		  k[j] = rand() & 0xff;
		}

		timer = start_rdtsc();
		// crypto_stream_skinny128128ecb_avx2(out,in,inlen,k);
		encrypt_deoxys(outt, inn, inlen,key,ad,1024,nonce,add_tag,tweak_pre_2,tweak_pre_ad_2);
		timer = end_rdtsc() - timer;

		if(i >= 0 && i < NUM_TIMINGS) 
		  timings[i] = ((double)timer) / inlen;
	  }

	  //Get Median
	  
	  qsort(timings, NUM_TIMINGS, sizeof(double), cmp_dbl);
	  printf("%f\n" /*Skinny128128: %f cycles per byte\n"*/, timings[NUM_TIMINGS / 2]);
  }
  #endif
  return 0;
}
