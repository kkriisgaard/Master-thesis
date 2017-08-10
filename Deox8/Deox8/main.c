#include <stdio.h>
#include "api.h"
#include "emmintrin.h"
#include "wmmintrin.h"
#include "crypto_aead.h"
// #include "auxfuncs.h"
#include <stdint.h>


// ------------- TIMING CODE

#define cpuid(func,ax,bx,cx,dx)\
		   __asm__ __volatile__ ("cpuid":\
		   "=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx) : "a" (func));

#ifndef REPEAT
	#define REPEAT 100000
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
	fprintf(resdump,"%g\n"/* cpb\n"*/, total_clk/(nbytes)/(MULTIPLE));


// ----------- END OF TIMING CODE

int main(int argc,char *argv[])
{
	int j = 0;
	int sz = 0;
	// unsigned char c;
	unsigned long long clen; 
	unsigned long long mlen;
	int ch;
	FILE *fp;
	fp = fopen("simple-165.txt","r");
	if(fp==NULL){printf("Couldn't open file. Terminating\n");return 0;}
	fseek(fp, 0L, SEEK_END);
	sz = ftell(fp);
	rewind(fp);
	mlen = sz;
	unsigned char key[CRYPTO_KEYBYTES] =  "This is A key?!!";
	unsigned char *pt = malloc(mlen); 
	unsigned char *ct = malloc(mlen + CRYPTO_ABYTES);
	while ( j<sz) 
	{
		ch = fgetc(fp);
		pt[j] = (unsigned char)ch;
		++j;
	}
	
	fclose(fp);
	
	unsigned char *dec = malloc(mlen); // [2048];
	unsigned long long ml;
	unsigned char ad[128] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
	const unsigned char nonce[CRYPTO_NPUBBYTES] = {0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xE2, 0x02, 0x04, 0x08, 0x10,  0x40, 0x80, 0xE2}; // */
	/*FILE *resdump;
   	resdump = fopen("Deoxys-Skylake-1000-128.txt","w");
	for(j=0;j<1000;++j)
	{
		TIME_IT("Deoxys-init",crypto_aead_encrypt( ct,&clen,pt,mlen,ad,128,0x0,nonce,key),mlen, 1 );
	}
    	fclose(resdump);*/
    	crypto_aead_encrypt( ct,&clen,pt,mlen,ad,128,0x0,nonce,key);
	
	FILE *out;
	out = fopen("outfile.txt","w");
	for(j=0;j<clen;++j)
	{
		fprintf(out,"%c",ct[j]);
	}
	// printf("\nDecrypting now, clen = %d\n",clen); // oi
	// printf("Entering decrypt\n");
	int dec_status = crypto_aead_decrypt( dec,&ml,0x0,ct,clen,ad,128,nonce,key);
	// printf("ml = %d\n",ml);
	// printf("I should be printing the ciphertext now\n");
	if(!dec_status || 1){for(j=0;j<ml;++j)
	{
		printf("%c",dec[j]);
	} printf("\n");}
	
	if(dec_status==-1)
	{
		printf("Verification failed\n");
	}// */
	return 0;
}
