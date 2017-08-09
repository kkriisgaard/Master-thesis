#include <stdio.h>
#include "emmintrin.h"
#include "wmmintrin.h"
#include "api.h"
#include "auxfuncs.h"
#include "crypto_aead.h"

#include <stdio.h>
#include <stdint.h>

// ------------- TIMING CODE

#define cpuid(func,ax,bx,cx,dx)\
		   __asm__ __volatile__ ("cpuid":\
		   "=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx) : "a" (func));

#ifndef REPEAT
	#define REPEAT 1 
#endif
#ifndef WARMUP
	#define WARMUP REPEAT/4
#endif
	
uint64_t start_clk,end_clk;
double total_clk;
int t;

static __inline uint64_t get_Clks(void) 
{
	uint32_t __a,__d;
	__asm__ __volatile__ ("rdtsc" : "=a" (__a), "=d" (__d));
	return ((uint64_t)__a) | (((uint64_t)__d)<<32ULL);
}

#define MEASURE(x)  for (t=0; t< WARMUP; t++)		   \
					{x;}				   \
					start_clk=get_Clks();			   \
					for (t = 0; t < REPEAT; t++)		\
					{								   \
								 {x;}				   \
					}								   \
					end_clk=get_Clks();				 \
					total_clk=(double)(end_clk-start_clk)/REPEAT;


#define TIME_IT(name, func, nbytes, MULTIPLE) \
	/*printf("%s-%d: ", name, nbytes);*/ \
	MEASURE(func); \
	fprintf(resdump,"%g\n" /*cpb\n"*/, total_clk/(nbytes)/(MULTIPLE));


// ----------- END OF TIMING CODE

int main(int argc,char *argv[])
{
	int j = 0;
	int sz = 0;
	unsigned char c;
	unsigned long long clen; 
	unsigned long long mlen;
	int ch;
	FILE *fp;
	fp = fopen("infile4096.txt","r");
	if(fp==NULL){printf("Couldn't open file. Terminating\n");return 0;}
	fseek(fp, 0L, SEEK_END);
	sz = ftell(fp);
	rewind(fp);
	unsigned char *test = malloc(sz);
		
	while ( j<sz) 
	{
		ch = fgetc(fp);
		test[j] = (unsigned char)ch;
		++j;
	}
	fclose(fp);
	printf("\n"); // 
	mlen = sz;
	
	unsigned char key[CRYPTO_KEYBYTES] =  "This is A key?!!";
	unsigned char *pt = malloc(mlen); 
	int os = ((sz/(127*CRYPTO_KEYBYTES))+1)*CRYPTO_KEYBYTES;
	unsigned char *ct = malloc(mlen + 16 + os); // 

	unsigned char ad[144] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
	const unsigned char nonce[CRYPTO_NPUBBYTES] = {0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xE2};

	// printf("Encryption happens here\n");
	FILE *resdump;
	resdump = fopen("COLM127-Skylake-4096-8.txt","w");
	for(int y=0;y<10;++y)
	{
		TIME_IT("COLM0-Pipe",crypto_aead_encrypt(ct,&clen,test,mlen,ad,144,0,nonce,key),mlen,1); 
	} // */
	fclose(resdump);
	
	// crypto_aead_encrypt(ct,&clen,test,mlen,ad,10,0,nonce,key);
	FILE *out = fopen("outfile.txt","w");
	// printf("\nmlen = %d\nclen = %d\n",mlen,clen);
	for(int i=0;i<clen;++i)
	{
		fprintf(out,"%c",ct[i]);
	} 
	
	fclose(out);
	
	FILE *cipher = fopen("outfile.txt","r");
	
	fseek(cipher, 0L, SEEK_END);
	sz = ftell(cipher);
	
	rewind(cipher);
	unsigned char *cip = malloc(mlen + 16 + os); // = malloc(sz);
	j = 0;
	while(j<sz)
	{
		ch = fgetc(cipher);
		cip[j] = (unsigned char)ch;
		++j;
	}
	// printf("\nclen = %d\nsz = %d\nTrying anyway\n",*clen,sz);
	// printf("\nDecryption happens here\n");
	int dec_status = crypto_aead_decrypt(pt,&mlen,0,cip,clen,ad,144,nonce,key); // */
	// printf("\nPlaintext of length %d:\n",*mlen);
	if(!dec_status)
	{
		printf("It works!\n");
		// for(int i=0;i<mlen;++i)
		// {
		// 	printf("%c",pt[i]);
		// }
	}
	else
	{
		printf("Message not verified\n");
		// for(int i=0;i<mlen;++i)
		// {
		// 	printf("%c",pt[i]);
		// }
	}
	printf("\n"); // */
	return 0;
}