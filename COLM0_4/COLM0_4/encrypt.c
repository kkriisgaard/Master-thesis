#include <stdio.h>
#include "api.h"
#include "emmintrin.h"
#include "wmmintrin.h"
#include "crypto_aead.h"
#include "auxfuncs.h"
#include <stdbool.h>
#include "macros.kkr"
// #include "debugfuncs.h"

__m128i enc_keys[11];

void generate_enc_key(__m128i key) 
{
	__m128i kt;
	enc_keys[0] = key;
	kt = _mm_aeskeygenassist_si128(key, 0x01);
	enc_keys[1] = key_exp_assist(enc_keys[0],kt);
	kt = _mm_aeskeygenassist_si128(enc_keys[1], 0x02);
	enc_keys[2] = key_exp_assist(enc_keys[1],kt);
	kt = _mm_aeskeygenassist_si128(enc_keys[2], 0x04);
	enc_keys[3] = key_exp_assist(enc_keys[2],kt);
	kt = _mm_aeskeygenassist_si128(enc_keys[3], 0x08);
	enc_keys[4] = key_exp_assist(enc_keys[3],kt);
	kt = _mm_aeskeygenassist_si128(enc_keys[4], 0x10);
	enc_keys[5] = key_exp_assist(enc_keys[4],kt);
	kt = _mm_aeskeygenassist_si128(enc_keys[5], 0x20);
	enc_keys[6] = key_exp_assist(enc_keys[5],kt);
	kt = _mm_aeskeygenassist_si128(enc_keys[6], 0x40);
	enc_keys[7] = key_exp_assist(enc_keys[6],kt);
	kt = _mm_aeskeygenassist_si128(enc_keys[7], 0x80);
	enc_keys[8] = key_exp_assist(enc_keys[7],kt);
	kt = _mm_aeskeygenassist_si128(enc_keys[8], 0x1B);
	enc_keys[9] = key_exp_assist(enc_keys[8],kt);
	kt = _mm_aeskeygenassist_si128(enc_keys[9], 0x36);
	enc_keys[10] = key_exp_assist(enc_keys[9],kt);
}

/* void encrypt_8block(__m128i* in, __m128i* out) // This function was fucking tedious to write.
{
	// __m128i* tmp = malloc(8*sizeof(__m128i));
	
	out[0] = _mm_xor_si128(in[0],keys[0]);
	out[1] = _mm_xor_si128(in[1],keys[0]);
	out[2] = _mm_xor_si128(in[2],keys[0]);
	out[3] = _mm_xor_si128(in[3],keys[0]);
	out[4] = _mm_xor_si128(in[4],keys[0]);
	out[5] = _mm_xor_si128(in[5],keys[0]);
	out[6] = _mm_xor_si128(in[6],keys[0]);
	out[7] = _mm_xor_si128(in[7],keys[0]);
	// print128_asint(out[1]);

	out[0] = _mm_aesenc_si128(out[0],keys[1]);
	out[1] = _mm_aesenc_si128(out[1],keys[1]);
	out[2] = _mm_aesenc_si128(out[2],keys[1]);
	out[3] = _mm_aesenc_si128(out[3],keys[1]);
	out[4] = _mm_aesenc_si128(out[4],keys[1]);
	out[5] = _mm_aesenc_si128(out[5],keys[1]);
	out[6] = _mm_aesenc_si128(out[6],keys[1]);
	out[7] = _mm_aesenc_si128(out[7],keys[1]);
	// print128_asint(out[1]);
	
	out[0] = _mm_aesenc_si128(out[0],keys[2]);
	out[1] = _mm_aesenc_si128(out[1],keys[2]);
	out[2] = _mm_aesenc_si128(out[2],keys[2]);
	out[3] = _mm_aesenc_si128(out[3],keys[2]);
	out[4] = _mm_aesenc_si128(out[4],keys[2]);
	out[5] = _mm_aesenc_si128(out[5],keys[2]);
	out[6] = _mm_aesenc_si128(out[6],keys[2]);
	out[7] = _mm_aesenc_si128(out[7],keys[2]);
	// print128_asint(out[1]);
	
	out[0] = _mm_aesenc_si128(out[0],keys[3]);
	out[1] = _mm_aesenc_si128(out[1],keys[3]);
	out[2] = _mm_aesenc_si128(out[2],keys[3]);
	out[3] = _mm_aesenc_si128(out[3],keys[3]);
	out[4] = _mm_aesenc_si128(out[4],keys[3]);
	out[5] = _mm_aesenc_si128(out[5],keys[3]);
	out[6] = _mm_aesenc_si128(out[6],keys[3]);
	out[7] = _mm_aesenc_si128(out[7],keys[3]);
	// print128_asint(out[1]);

	out[0] = _mm_aesenc_si128(out[0],keys[4]);
	out[1] = _mm_aesenc_si128(out[1],keys[4]);
	out[2] = _mm_aesenc_si128(out[2],keys[4]);
	out[3] = _mm_aesenc_si128(out[3],keys[4]);
	out[4] = _mm_aesenc_si128(out[4],keys[4]);
	out[5] = _mm_aesenc_si128(out[5],keys[4]);
	out[6] = _mm_aesenc_si128(out[6],keys[4]);
	out[7] = _mm_aesenc_si128(out[7],keys[4]);
	// print128_asint(out[1]);
	
	out[0] = _mm_aesenc_si128(out[0],keys[5]);
	out[1] = _mm_aesenc_si128(out[1],keys[5]);
	out[2] = _mm_aesenc_si128(out[2],keys[5]);
	out[3] = _mm_aesenc_si128(out[3],keys[5]);
	out[4] = _mm_aesenc_si128(out[4],keys[5]);
	out[5] = _mm_aesenc_si128(out[5],keys[5]);
	out[6] = _mm_aesenc_si128(out[6],keys[5]);
	out[7] = _mm_aesenc_si128(out[7],keys[5]);
	// print128_asint(out[1]);
	
	out[0] = _mm_aesenc_si128(out[0],keys[6]);
	out[1] = _mm_aesenc_si128(out[1],keys[6]);
	out[2] = _mm_aesenc_si128(out[2],keys[6]);
	out[3] = _mm_aesenc_si128(out[3],keys[6]);
	out[4] = _mm_aesenc_si128(out[4],keys[6]);
	out[5] = _mm_aesenc_si128(out[5],keys[6]);
	out[6] = _mm_aesenc_si128(out[6],keys[6]);
	out[7] = _mm_aesenc_si128(out[7],keys[6]);
	// print128_asint(out[1]);

	out[0] = _mm_aesenc_si128(out[0],keys[7]);
	out[1] = _mm_aesenc_si128(out[1],keys[7]);
	out[2] = _mm_aesenc_si128(out[2],keys[7]);
	out[3] = _mm_aesenc_si128(out[3],keys[7]);
	out[4] = _mm_aesenc_si128(out[4],keys[7]);
	out[5] = _mm_aesenc_si128(out[5],keys[7]);
	out[6] = _mm_aesenc_si128(out[6],keys[7]);
	out[7] = _mm_aesenc_si128(out[7],keys[7]);
	// print128_asint(out[1]);
	
	out[0] = _mm_aesenc_si128(out[0],keys[8]);
	out[1] = _mm_aesenc_si128(out[1],keys[8]);
	out[2] = _mm_aesenc_si128(out[2],keys[8]);
	out[3] = _mm_aesenc_si128(out[3],keys[8]);
	out[4] = _mm_aesenc_si128(out[4],keys[8]);
	out[5] = _mm_aesenc_si128(out[5],keys[8]);
	out[6] = _mm_aesenc_si128(out[6],keys[8]);
	out[7] = _mm_aesenc_si128(out[7],keys[8]);
	// print128_asint(out[1]);
	
	out[0] = _mm_aesenc_si128(out[0],keys[9]);
	out[1] = _mm_aesenc_si128(out[1],keys[9]);
	out[2] = _mm_aesenc_si128(out[2],keys[9]);
	out[3] = _mm_aesenc_si128(out[3],keys[9]);
	out[4] = _mm_aesenc_si128(out[4],keys[9]);
	out[5] = _mm_aesenc_si128(out[5],keys[9]);
	out[6] = _mm_aesenc_si128(out[6],keys[9]);
	out[7] = _mm_aesenc_si128(out[7],keys[9]);
	// print128_asint(out[1]);

	out[0] = _mm_aesenclast_si128(out[0],keys[10]);
	out[1] = _mm_aesenclast_si128(out[1],keys[10]);
	out[2] = _mm_aesenclast_si128(out[2],keys[10]);
	out[3] = _mm_aesenclast_si128(out[3],keys[10]);
	out[4] = _mm_aesenclast_si128(out[4],keys[10]);
	out[5] = _mm_aesenclast_si128(out[5],keys[10]);
	out[6] = _mm_aesenclast_si128(out[6],keys[10]);
	out[7] = _mm_aesenclast_si128(out[7],keys[10]);
} // */

void encrypt_4block(__m128i* in) // This function was fucking tedious to write.
{	
	in[0] = _mm_xor_si128(in[0],enc_keys[0]);
	in[1] = _mm_xor_si128(in[1],enc_keys[0]);
	in[2] = _mm_xor_si128(in[2],enc_keys[0]);
	in[3] = _mm_xor_si128(in[3],enc_keys[0]);
	
	in[0] = _mm_aesenc_si128(in[0],enc_keys[1]);
	in[1] = _mm_aesenc_si128(in[1],enc_keys[1]);
	in[2] = _mm_aesenc_si128(in[2],enc_keys[1]);
	in[3] = _mm_aesenc_si128(in[3],enc_keys[1]);
	
	in[0] = _mm_aesenc_si128(in[0],enc_keys[2]);
	in[1] = _mm_aesenc_si128(in[1],enc_keys[2]);
	in[2] = _mm_aesenc_si128(in[2],enc_keys[2]);
	in[3] = _mm_aesenc_si128(in[3],enc_keys[2]);
	
	in[0] = _mm_aesenc_si128(in[0],enc_keys[3]);
	in[1] = _mm_aesenc_si128(in[1],enc_keys[3]);
	in[2] = _mm_aesenc_si128(in[2],enc_keys[3]);
	in[3] = _mm_aesenc_si128(in[3],enc_keys[3]);

	in[0] = _mm_aesenc_si128(in[0],enc_keys[4]);
	in[1] = _mm_aesenc_si128(in[1],enc_keys[4]);
	in[2] = _mm_aesenc_si128(in[2],enc_keys[4]);
	in[3] = _mm_aesenc_si128(in[3],enc_keys[4]);
	
	in[0] = _mm_aesenc_si128(in[0],enc_keys[5]);
	in[1] = _mm_aesenc_si128(in[1],enc_keys[5]);
	in[2] = _mm_aesenc_si128(in[2],enc_keys[5]);
	in[3] = _mm_aesenc_si128(in[3],enc_keys[5]);
	
	in[0] = _mm_aesenc_si128(in[0],enc_keys[6]);
	in[1] = _mm_aesenc_si128(in[1],enc_keys[6]);
	in[2] = _mm_aesenc_si128(in[2],enc_keys[6]);
	in[3] = _mm_aesenc_si128(in[3],enc_keys[6]);

	in[0] = _mm_aesenc_si128(in[0],enc_keys[7]);
	in[1] = _mm_aesenc_si128(in[1],enc_keys[7]);
	in[2] = _mm_aesenc_si128(in[2],enc_keys[7]);
	in[3] = _mm_aesenc_si128(in[3],enc_keys[7]);
	
	in[0] = _mm_aesenc_si128(in[0],enc_keys[8]);
	in[1] = _mm_aesenc_si128(in[1],enc_keys[8]);
	in[2] = _mm_aesenc_si128(in[2],enc_keys[8]);
	in[3] = _mm_aesenc_si128(in[3],enc_keys[8]);
	
	in[0] = _mm_aesenc_si128(in[0],enc_keys[9]);
	in[1] = _mm_aesenc_si128(in[1],enc_keys[9]);
	in[2] = _mm_aesenc_si128(in[2],enc_keys[9]);
	in[3] = _mm_aesenc_si128(in[3],enc_keys[9]);

	in[0] = _mm_aesenclast_si128(in[0],enc_keys[10]);
	in[1] = _mm_aesenclast_si128(in[1],enc_keys[10]);
	in[2] = _mm_aesenclast_si128(in[2],enc_keys[10]);
	in[3] = _mm_aesenclast_si128(in[3],enc_keys[10]);
}

void encrypt_8block2(__m128i* in) 
{
	in[0] = _mm_xor_si128(in[0],enc_keys[0]);
	in[1] = _mm_xor_si128(in[1],enc_keys[0]);
	in[2] = _mm_xor_si128(in[2],enc_keys[0]);
	in[3] = _mm_xor_si128(in[3],enc_keys[0]);
	in[4] = _mm_xor_si128(in[4],enc_keys[0]);
	in[5] = _mm_xor_si128(in[5],enc_keys[0]);
	in[6] = _mm_xor_si128(in[6],enc_keys[0]);
	in[7] = _mm_xor_si128(in[7],enc_keys[0]);
	// print128_asint(in[1]);

	in[0] = _mm_aesenc_si128(in[0],enc_keys[1]);
	in[1] = _mm_aesenc_si128(in[1],enc_keys[1]);
	in[2] = _mm_aesenc_si128(in[2],enc_keys[1]);
	in[3] = _mm_aesenc_si128(in[3],enc_keys[1]);
	in[4] = _mm_aesenc_si128(in[4],enc_keys[1]);
	in[5] = _mm_aesenc_si128(in[5],enc_keys[1]);
	in[6] = _mm_aesenc_si128(in[6],enc_keys[1]);
	in[7] = _mm_aesenc_si128(in[7],enc_keys[1]);
	// print128_asint(in[1]);
	
	in[0] = _mm_aesenc_si128(in[0],enc_keys[2]);
	in[1] = _mm_aesenc_si128(in[1],enc_keys[2]);
	in[2] = _mm_aesenc_si128(in[2],enc_keys[2]);
	in[3] = _mm_aesenc_si128(in[3],enc_keys[2]);
	in[4] = _mm_aesenc_si128(in[4],enc_keys[2]);
	in[5] = _mm_aesenc_si128(in[5],enc_keys[2]);
	in[6] = _mm_aesenc_si128(in[6],enc_keys[2]);
	in[7] = _mm_aesenc_si128(in[7],enc_keys[2]);
	// print128_asint(in[1]);
	
	in[0] = _mm_aesenc_si128(in[0],enc_keys[3]);
	in[1] = _mm_aesenc_si128(in[1],enc_keys[3]);
	in[2] = _mm_aesenc_si128(in[2],enc_keys[3]);
	in[3] = _mm_aesenc_si128(in[3],enc_keys[3]);
	in[4] = _mm_aesenc_si128(in[4],enc_keys[3]);
	in[5] = _mm_aesenc_si128(in[5],enc_keys[3]);
	in[6] = _mm_aesenc_si128(in[6],enc_keys[3]);
	in[7] = _mm_aesenc_si128(in[7],enc_keys[3]);
	// print128_asint(in[1]);

	in[0] = _mm_aesenc_si128(in[0],enc_keys[4]);
	in[1] = _mm_aesenc_si128(in[1],enc_keys[4]);
	in[2] = _mm_aesenc_si128(in[2],enc_keys[4]);
	in[3] = _mm_aesenc_si128(in[3],enc_keys[4]);
	in[4] = _mm_aesenc_si128(in[4],enc_keys[4]);
	in[5] = _mm_aesenc_si128(in[5],enc_keys[4]);
	in[6] = _mm_aesenc_si128(in[6],enc_keys[4]);
	in[7] = _mm_aesenc_si128(in[7],enc_keys[4]);
	// print128_asint(in[1]);
	
	in[0] = _mm_aesenc_si128(in[0],enc_keys[5]);
	in[1] = _mm_aesenc_si128(in[1],enc_keys[5]);
	in[2] = _mm_aesenc_si128(in[2],enc_keys[5]);
	in[3] = _mm_aesenc_si128(in[3],enc_keys[5]);
	in[4] = _mm_aesenc_si128(in[4],enc_keys[5]);
	in[5] = _mm_aesenc_si128(in[5],enc_keys[5]);
	in[6] = _mm_aesenc_si128(in[6],enc_keys[5]);
	in[7] = _mm_aesenc_si128(in[7],enc_keys[5]);
	// print128_asint(in[1]);
	
	in[0] = _mm_aesenc_si128(in[0],enc_keys[6]);
	in[1] = _mm_aesenc_si128(in[1],enc_keys[6]);
	in[2] = _mm_aesenc_si128(in[2],enc_keys[6]);
	in[3] = _mm_aesenc_si128(in[3],enc_keys[6]);
	in[4] = _mm_aesenc_si128(in[4],enc_keys[6]);
	in[5] = _mm_aesenc_si128(in[5],enc_keys[6]);
	in[6] = _mm_aesenc_si128(in[6],enc_keys[6]);
	in[7] = _mm_aesenc_si128(in[7],enc_keys[6]);
	// print128_asint(in[1]);

	in[0] = _mm_aesenc_si128(in[0],enc_keys[7]);
	in[1] = _mm_aesenc_si128(in[1],enc_keys[7]);
	in[2] = _mm_aesenc_si128(in[2],enc_keys[7]);
	in[3] = _mm_aesenc_si128(in[3],enc_keys[7]);
	in[4] = _mm_aesenc_si128(in[4],enc_keys[7]);
	in[5] = _mm_aesenc_si128(in[5],enc_keys[7]);
	in[6] = _mm_aesenc_si128(in[6],enc_keys[7]);
	in[7] = _mm_aesenc_si128(in[7],enc_keys[7]);
	// print128_asint(in[1]);
	
	in[0] = _mm_aesenc_si128(in[0],enc_keys[8]);
	in[1] = _mm_aesenc_si128(in[1],enc_keys[8]);
	in[2] = _mm_aesenc_si128(in[2],enc_keys[8]);
	in[3] = _mm_aesenc_si128(in[3],enc_keys[8]);
	in[4] = _mm_aesenc_si128(in[4],enc_keys[8]);
	in[5] = _mm_aesenc_si128(in[5],enc_keys[8]);
	in[6] = _mm_aesenc_si128(in[6],enc_keys[8]);
	in[7] = _mm_aesenc_si128(in[7],enc_keys[8]);
	// print128_asint(in[1]);
	
	in[0] = _mm_aesenc_si128(in[0],enc_keys[9]);
	in[1] = _mm_aesenc_si128(in[1],enc_keys[9]);
	in[2] = _mm_aesenc_si128(in[2],enc_keys[9]);
	in[3] = _mm_aesenc_si128(in[3],enc_keys[9]);
	in[4] = _mm_aesenc_si128(in[4],enc_keys[9]);
	in[5] = _mm_aesenc_si128(in[5],enc_keys[9]);
	in[6] = _mm_aesenc_si128(in[6],enc_keys[9]);
	in[7] = _mm_aesenc_si128(in[7],enc_keys[9]);
	// print128_asint(in[1]);

	in[0] = _mm_aesenclast_si128(in[0],enc_keys[10]);
	in[1] = _mm_aesenclast_si128(in[1],enc_keys[10]);
	in[2] = _mm_aesenclast_si128(in[2],enc_keys[10]);
	in[3] = _mm_aesenclast_si128(in[3],enc_keys[10]);
	in[4] = _mm_aesenclast_si128(in[4],enc_keys[10]);
	in[5] = _mm_aesenclast_si128(in[5],enc_keys[10]);
	in[6] = _mm_aesenclast_si128(in[6],enc_keys[10]);
	in[7] = _mm_aesenclast_si128(in[7],enc_keys[10]);
} // */

__m128i encrypt_block(__m128i pt) 
{
	__m128i tmp;
	tmp = _mm_xor_si128(pt,enc_keys[0]);// print128_asint(tmp);

	tmp = _mm_aesenc_si128(tmp,enc_keys[1]);// print128_asint(tmp);
	tmp = _mm_aesenc_si128(tmp,enc_keys[2]);// print128_asint(tmp);
	tmp = _mm_aesenc_si128(tmp,enc_keys[3]);// print128_asint(tmp);

	tmp = _mm_aesenc_si128(tmp,enc_keys[4]);// print128_asint(tmp);
	tmp = _mm_aesenc_si128(tmp,enc_keys[5]);// print128_asint(tmp);
	tmp = _mm_aesenc_si128(tmp,enc_keys[6]);// print128_asint(tmp);

	tmp = _mm_aesenc_si128(tmp,enc_keys[7]);// print128_asint(tmp);
	tmp = _mm_aesenc_si128(tmp,enc_keys[8]);// print128_asint(tmp);
	tmp = _mm_aesenc_si128(tmp,enc_keys[9]);// print128_asint(tmp);

	tmp = _mm_aesenclast_si128(tmp,enc_keys[10]);
	return tmp;
}

int crypto_aead_encrypt( 
       unsigned char *c,unsigned long long *clen, // c = cipher, clen = cipher length - not const, as they may change in size.
       const unsigned char *m,unsigned long long mlen,
       const unsigned char *ad,unsigned long long adlen, 
       const unsigned char *nsec, 
       const unsigned char *npub, // = nonce
       const unsigned char *k
     )
{
	// Setup
	__m64 param = _mm_set_pi8(0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00);
	__m64 nonce = _mm_set_pi8(npub[7],npub[6],npub[5],npub[4],npub[3],npub[2],npub[1],npub[0]);
	
	__m128i zero_mes = _mm_setzero_si128(); 
	// printf("(start) Address of key is: %llu\n",k);
	__m128i key = _mm_loadu_si128(k); 
	// printf("Address of key is: %llu\n",k);
	generate_enc_key(key);
	// printf("Address of key is: %llu\n",k);
	int fin_mes = mlen%CRYPTO_KEYBYTES; 
	int numblocks_mes =  mlen/CRYPTO_KEYBYTES; // if |M*[l]| < 128, numblocks_ad = l-1. Otherwise, numblocks_ad = l
	int fin_ad =  adlen%CRYPTO_KEYBYTES;  
	int numblocks_ad = adlen/CRYPTO_KEYBYTES; // if |A*[a]| < 128, numblocks_ad = a-1. Otherwise, numblocks_ad = a
	
	// IV (and subkey) generation
	
	__m128i L = encrypt_block(zero_mes);
	__m128i L1 = _mm_xor_si128(L,mul2(L)); /* 3*L */
	__m128i L2 = _mm_xor_si128(L1,mul2(L1)); /* 3^2*L */
	
	__m128i a_Delta[PARA];
	a_Delta[PARA-1]=L1;
	__m128i delta = L1; // = L1; 
	
	__m128i Wp,AA,Z,Ai,IV,_2delta;
	__m128i a_Ai[PARA];
	
	__m128i nonceparam = _mm_set_epi64(nonce,param); 
	Wp = encrypt_block( _mm_xor_si128( nonceparam,L1 )); 
	int upper = numblocks_ad-1; 
	unsigned char Aa[CRYPTO_KEYBYTES]; 
	unsigned long long i,j;
	for(i=0;i<upper;i+=PARA) 
	{
		// delta = mul2(delta);
		
		a_Delta[0] = mul2(a_Delta[PARA-1]);
		a_Delta[1] = mul2(a_Delta[0]);
		a_Delta[2] = mul2(a_Delta[1]);
		a_Delta[3] = mul2(a_Delta[2]);
		
		a_Ai[0] = _mm_loadu_si128(ad+(i  )*CRYPTO_KEYBYTES);
		a_Ai[1] = _mm_loadu_si128(ad+(i+1)*CRYPTO_KEYBYTES);
		a_Ai[2] = _mm_loadu_si128(ad+(i+2)*CRYPTO_KEYBYTES);
		a_Ai[3] = _mm_loadu_si128(ad+(i+3)*CRYPTO_KEYBYTES);
				
		// a_Ai[0] = _mm_xor_si128(a_Ai[0],delta);
		
		a_Ai[0] = _mm_xor_si128(a_Ai[0],a_Delta[0]);
		a_Ai[1] = _mm_xor_si128(a_Ai[1],a_Delta[1]);
		a_Ai[2] = _mm_xor_si128(a_Ai[2],a_Delta[2]);
		a_Ai[3] = _mm_xor_si128(a_Ai[3],a_Delta[3]);
		
		// a_Ai[0] = encrypt_block(a_Ai[0]);
		
		ENCRYPTPARA(a_Ai);
		
		// Wp ^= a_Ai[0];
		
		Wp = Wp^a_Ai[0]^a_Ai[1]^a_Ai[2]^a_Ai[3]; // ^a_Ai[4]^a_Ai[5]^a_Ai[6]^a_Ai[7];// _mm_xor_si128( Z,Wp );		
	}
	if(fin_ad)
	{
		memcpy(Aa, ad+(numblocks_ad*CRYPTO_KEYBYTES), fin_ad); 
		Aa[fin_ad] = 0x80;
		memset(Aa+fin_ad+1,0,CRYPTO_KEYBYTES-(fin_ad+1));
		++numblocks_ad;
		Ai = _mm_loadu_si128(Aa); 
		_2delta = mul2(a_Delta[PARA-1]); // mul2(delta);
		delta =  _mm_xor_si128( _mm_xor_si128(delta /*a_Delta[PARA-1]*/ ,_2delta) , mul2(_2delta) );
	}
	else
	{
		Ai = _mm_loadu_si128(ad+upper*CRYPTO_KEYBYTES); 
		delta = mul2(a_Delta[PARA-1]); //  mul2(delta);
	}
	AA = _mm_xor_si128( Ai,delta );
	Z = encrypt_block(AA);
	IV = _mm_xor_si128( Z,Wp );
	// print128_asint(IV);
	// Encryption
	unsigned char M_star[CRYPTO_KEYBYTES]; 
	int mf = numblocks_mes-1; // l-1
	if(fin_mes)
	{
		memcpy(M_star, m+(numblocks_mes*CRYPTO_KEYBYTES), fin_mes);
		M_star[fin_mes] = 0x80;
		memset(M_star+fin_mes+1,0,CRYPTO_KEYBYTES-(fin_mes+1));
		++numblocks_mes;
	}
	else
	{
		memcpy(M_star,m+CRYPTO_KEYBYTES*mf,CRYPTO_KEYBYTES);
		fin_mes = CRYPTO_KEYBYTES;
	}
	
	__m128i Ml = _mm_loadu_si128(M_star); // Loads straight.
	__m128i Mg[PARA]; 

	__m128i M,X,C,_2W;
	__m128i W = IV;
	__m128i deltaC = L2;	
	delta = L;
	
	a_Delta[PARA-1] = L; /*COLM is one-indexed by nature...*/
	__m128i a_DeltaC[PARA];
	a_DeltaC[PARA-1] = L2; 
	__m128i mes[PARA]/*, a_W[16]*/;
	for(i=0;i<mf;i+=PARA)
	{
			a_Delta[0] = mul2(a_Delta[PARA-1]);
			a_Delta[1] = mul2(a_Delta[0]);
			a_Delta[2] = mul2(a_Delta[1]);
			a_Delta[3] = mul2(a_Delta[2]);
			
			mes[0] = _mm_loadu_si128(m+((i  )*CRYPTO_KEYBYTES));
			mes[1] = _mm_loadu_si128(m+((i+1)*CRYPTO_KEYBYTES));
			mes[2] = _mm_loadu_si128(m+((i+2)*CRYPTO_KEYBYTES));
			mes[3] = _mm_loadu_si128(m+((i+3)*CRYPTO_KEYBYTES));
			
			Ml = mes[3]^Ml^mes[0]^mes[1]^mes[2]; 
			
			Mg[0] = _mm_xor_si128(mes[0],a_Delta[0]);
			Mg[1] = _mm_xor_si128(mes[1],a_Delta[1]);
			Mg[2] = _mm_xor_si128(mes[2],a_Delta[2]);
			Mg[3] = _mm_xor_si128(mes[3],a_Delta[3]);
			
		ENCRYPTPARA(Mg);
		
		for(j=0;j<PARA;++j)		
		{
			// _2W = mul2(W);
			Wp = _mm_xor_si128(Mg[j],mul2(W));
			Mg[j] = _mm_xor_si128(Wp,W);
			W = Wp;
		}
		ENCRYPTPARA(Mg);
		// Mg[0] = encrypt_block(Mg[0]); // 
		
			// deltaC = mul2(deltaC);
			
			a_DeltaC[0] = mul2(a_DeltaC[PARA-1]);
			a_DeltaC[1] = mul2(a_DeltaC[0]);
			a_DeltaC[2] = mul2(a_DeltaC[1]);
			a_DeltaC[3] = mul2(a_DeltaC[2]);
			
			// mes[0] = _mm_xor_si128(Mg[0],deltaC);
			
			mes[0] = _mm_xor_si128(Mg[0],a_DeltaC[0]);
			mes[1] = _mm_xor_si128(Mg[1],a_DeltaC[1]);
			mes[2] = _mm_xor_si128(Mg[2],a_DeltaC[2]);
			mes[3] = _mm_xor_si128(Mg[3],a_DeltaC[3]);
			
			// _mm_storeu_si128( (__m128i *)&c[(i  )*CRYPTO_KEYBYTES], mes[0] ); 
			
			_mm_storeu_si128( (__m128i *)&c[(i  )*CRYPTO_KEYBYTES], mes[0] ); 
			_mm_storeu_si128( (__m128i *)&c[(i+1)*CRYPTO_KEYBYTES], mes[1] ); 
			_mm_storeu_si128( (__m128i *)&c[(i+2)*CRYPTO_KEYBYTES], mes[2] ); 
			_mm_storeu_si128( (__m128i *)&c[(i+3)*CRYPTO_KEYBYTES], mes[3] ); 
			
	}
	delta = a_Delta[PARA-1]; //[0]
	_2delta = mul2(delta);  
	delta = _mm_xor_si128(_mm_xor_si128(delta ,_2delta),mul2(_2delta));
	
	
	deltaC = a_DeltaC[PARA-1];
	__m128i _2deltaC = mul2(deltaC);  
	deltaC = _mm_xor_si128(_mm_xor_si128(deltaC ,_2deltaC),mul2(_2deltaC));
	
	if(fin_mes%16)
	{
		_2delta = mul2(delta);
		delta = _mm_xor_si128(_mm_xor_si128(delta ,_2delta),mul2(_2delta));
		_2deltaC = mul2(deltaC);
		deltaC = _mm_xor_si128(_mm_xor_si128(deltaC ,_2deltaC),mul2(_2deltaC));
	}
	__m128i MM = _mm_xor_si128( Ml,delta );
	X = encrypt_block(MM);
	
	_2W = mul2(W);
	__m128i Y = _mm_xor_si128( X,  _mm_xor_si128(W,_2W) ); 
	W = _mm_xor_si128( X,  _2W ); 
	__m128i CC = encrypt_block(Y);
	
	C = _mm_xor_si128(CC,deltaC);
	
	_mm_storeu_si128( (__m128i *)&c[mf*CRYPTO_KEYBYTES], C ); 
	
	delta = mul2(delta);
	deltaC = mul2(deltaC);
	
	MM = _mm_xor_si128( Ml,delta );
	X = encrypt_block(MM);
	_2W = mul2(W);
	Y = _mm_xor_si128( X,  _mm_xor_si128(W,_2W) ); 
	W = _mm_xor_si128( X,  _2W ); 
	CC = encrypt_block(Y);
	C = _mm_xor_si128(CC,deltaC);
	unsigned char c_fin[CRYPTO_KEYBYTES];
	
	_mm_storeu_si128( (__m128i *)&c_fin[0], C ); 
	*clen = mlen + CRYPTO_ABYTES;
	memcpy(c+numblocks_mes*CRYPTO_KEYBYTES,c_fin,fin_mes);
	return 0;
}
