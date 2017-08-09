#include <stdio.h>
#include "api.h"
#include "emmintrin.h"
#include "wmmintrin.h"
#include "auxfuncs.h"
#include <stdbool.h>

/* void print128_aschar(__m128i p) // Print 128-bit block as characters
{
	unsigned char *val = (unsigned char*) &p; // Line taken from http://stackoverflow.com/questions/13257166/print-a-m128i-variable (top answer)
	printf("%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c \n", val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7], val[8], val[9], val[10], val[11], val[12], val[13], val[14], val[15], val[16]); 
}

void print128_asint(__m128i p) // Print 128-bit block as integer
{
	unsigned char *val = (unsigned char*) &p; 
	printf("%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d \n", val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7], val[8], val[9], val[10], val[11], val[12], val[13], val[14], val[15], val[16]); 
}*/

__m128i mul2(__m128i x)
{
	const __m128i red  = _mm_set_epi64x(0x8700000000000000,0x0000000000000000); // This will be loaded in such that the last byte is 0x87, the remaining are zeros. I wish I was kidding.
	const __m128i ZERO = _mm_setzero_si128();
	
	__m128i mask = _mm_cmpgt_epi32(ZERO,x); 
	mask = _mm_shuffle_epi32(mask,0xff); 	
	
	__m128i x2 = _mm_or_si128(_mm_slli_epi64(x,1),_mm_srli_epi64(_mm_slli_si128(x,8),63)); 	
	return _mm_xor_si128(x2,_mm_and_si128(red,mask));
}

__m128i keys[20];

__m128i key_exp_assist(__m128i t1, __m128i t2)
{
	__m128i t3 = _mm_slli_si128(t1,0x04);
	t2 = _mm_shuffle_epi32(t2,0xFF);
	t1 = _mm_xor_si128(t1,t3);
	t3 = _mm_slli_si128(t1,0x04);
	t1 = _mm_xor_si128(t1,t3);
	t3 = _mm_slli_si128(t1,0x04);
	t1 = _mm_xor_si128(t1,t3);
	return _mm_xor_si128(t1,t2);
}

void generate_aes_key(__m128i key) 
{
	__m128i kt;
	keys[0] = key;
	kt = _mm_aeskeygenassist_si128(key, 0x01);
	keys[1] = key_exp_assist(keys[0],kt);
	kt = _mm_aeskeygenassist_si128(keys[1], 0x02);
	keys[2] = key_exp_assist(keys[1],kt);
	kt = _mm_aeskeygenassist_si128(keys[2], 0x04);
	keys[3] = key_exp_assist(keys[2],kt);
	kt = _mm_aeskeygenassist_si128(keys[3], 0x08);
	keys[4] = key_exp_assist(keys[3],kt);
	kt = _mm_aeskeygenassist_si128(keys[4], 0x10);
	keys[5] = key_exp_assist(keys[4],kt);
	kt = _mm_aeskeygenassist_si128(keys[5], 0x20);
	keys[6] = key_exp_assist(keys[5],kt);
	kt = _mm_aeskeygenassist_si128(keys[6], 0x40);
	keys[7] = key_exp_assist(keys[6],kt);
	kt = _mm_aeskeygenassist_si128(keys[7], 0x80);
	keys[8] = key_exp_assist(keys[7],kt);
	kt = _mm_aeskeygenassist_si128(keys[8], 0x1B);
	keys[9] = key_exp_assist(keys[8],kt);
	kt = _mm_aeskeygenassist_si128(keys[9], 0x36);
	keys[10] = key_exp_assist(keys[9],kt);
	keys[11] = _mm_aesimc_si128(keys[9]);
	keys[12] = _mm_aesimc_si128(keys[8]);
	keys[13] = _mm_aesimc_si128(keys[7]);
	keys[14] = _mm_aesimc_si128(keys[6]);
	keys[15] = _mm_aesimc_si128(keys[5]);
	keys[16] = _mm_aesimc_si128(keys[4]);
	keys[17] = _mm_aesimc_si128(keys[3]);
	keys[18] = _mm_aesimc_si128(keys[2]);
	keys[19] = _mm_aesimc_si128(keys[1]);
}

__m128i encrypt_block(__m128i pt) 
{
	__m128i tmp;
	tmp = _mm_xor_si128(pt,keys[0]);// print128_asint(tmp);

	tmp = _mm_aesenc_si128(tmp,keys[1]);// print128_asint(tmp);
	tmp = _mm_aesenc_si128(tmp,keys[2]);// print128_asint(tmp);
	tmp = _mm_aesenc_si128(tmp,keys[3]);// print128_asint(tmp);

	tmp = _mm_aesenc_si128(tmp,keys[4]);// print128_asint(tmp);
	tmp = _mm_aesenc_si128(tmp,keys[5]);// print128_asint(tmp);
	tmp = _mm_aesenc_si128(tmp,keys[6]);// print128_asint(tmp);

	tmp = _mm_aesenc_si128(tmp,keys[7]);// print128_asint(tmp);
	tmp = _mm_aesenc_si128(tmp,keys[8]);// print128_asint(tmp);
	tmp = _mm_aesenc_si128(tmp,keys[9]);// print128_asint(tmp);

	tmp = _mm_aesenclast_si128(tmp,keys[10]);
	return tmp;
}

__m128i decrypt_block(__m128i ct) 
{
	__m128i tmp;
	tmp = _mm_xor_si128(ct,keys[10]);

	tmp = _mm_aesdec_si128(tmp,keys[11]);
	tmp = _mm_aesdec_si128(tmp,keys[12]);
	tmp = _mm_aesdec_si128(tmp,keys[13]);

	tmp = _mm_aesdec_si128(tmp,keys[14]);
	tmp = _mm_aesdec_si128(tmp,keys[15]);
	tmp = _mm_aesdec_si128(tmp,keys[16]);

	tmp = _mm_aesdec_si128(tmp,keys[17]);
	tmp = _mm_aesdec_si128(tmp,keys[18]);
	tmp = _mm_aesdec_si128(tmp,keys[19]);

	tmp = _mm_aesdeclast_si128(tmp,keys[0]);
	return tmp;
}
// Changing to multi array method: Remove comment before void (Don't be concerned with the one after, there will be no issue)
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

void encrypt_4block(__m128i* in) 
{
	in[0] = _mm_xor_si128(in[0],keys[0]);
	in[1] = _mm_xor_si128(in[1],keys[0]);
	in[2] = _mm_xor_si128(in[2],keys[0]);
	in[3] = _mm_xor_si128(in[3],keys[0]);

	in[0] = _mm_aesenc_si128(in[0],keys[1]);
	in[1] = _mm_aesenc_si128(in[1],keys[1]);
	in[2] = _mm_aesenc_si128(in[2],keys[1]);
	in[3] = _mm_aesenc_si128(in[3],keys[1]);
	
	in[0] = _mm_aesenc_si128(in[0],keys[2]);
	in[1] = _mm_aesenc_si128(in[1],keys[2]);
	in[2] = _mm_aesenc_si128(in[2],keys[2]);
	in[3] = _mm_aesenc_si128(in[3],keys[2]);
	
	in[0] = _mm_aesenc_si128(in[0],keys[3]);
	in[1] = _mm_aesenc_si128(in[1],keys[3]);
	in[2] = _mm_aesenc_si128(in[2],keys[3]);
	in[3] = _mm_aesenc_si128(in[3],keys[3]);
	
	in[0] = _mm_aesenc_si128(in[0],keys[4]);
	in[1] = _mm_aesenc_si128(in[1],keys[4]);
	in[2] = _mm_aesenc_si128(in[2],keys[4]);
	in[3] = _mm_aesenc_si128(in[3],keys[4]);
	
	in[0] = _mm_aesenc_si128(in[0],keys[5]);
	in[1] = _mm_aesenc_si128(in[1],keys[5]);
	in[2] = _mm_aesenc_si128(in[2],keys[5]);
	in[3] = _mm_aesenc_si128(in[3],keys[5]);
	
	in[0] = _mm_aesenc_si128(in[0],keys[6]);
	in[1] = _mm_aesenc_si128(in[1],keys[6]);
	in[2] = _mm_aesenc_si128(in[2],keys[6]);
	in[3] = _mm_aesenc_si128(in[3],keys[6]);
	
	in[0] = _mm_aesenc_si128(in[0],keys[7]);
	in[1] = _mm_aesenc_si128(in[1],keys[7]);
	in[2] = _mm_aesenc_si128(in[2],keys[7]);
	in[3] = _mm_aesenc_si128(in[3],keys[7]);
	
	in[0] = _mm_aesenc_si128(in[0],keys[8]);
	in[1] = _mm_aesenc_si128(in[1],keys[8]);
	in[2] = _mm_aesenc_si128(in[2],keys[8]);
	in[3] = _mm_aesenc_si128(in[3],keys[8]);
	
	in[0] = _mm_aesenc_si128(in[0],keys[9]);
	in[1] = _mm_aesenc_si128(in[1],keys[9]);
	in[2] = _mm_aesenc_si128(in[2],keys[9]);
	in[3] = _mm_aesenc_si128(in[3],keys[9]);
	
	in[0] = _mm_aesenclast_si128(in[0],keys[10]);
	in[1] = _mm_aesenclast_si128(in[1],keys[10]);
	in[2] = _mm_aesenclast_si128(in[2],keys[10]);
	in[3] = _mm_aesenclast_si128(in[3],keys[10]);
}

void encrypt_8block2(__m128i* in) 
{
	// __m128i* tmp = malloc(8*sizeof(__m128i));
	
	in[0] = _mm_xor_si128(in[0],keys[0]);
	in[1] = _mm_xor_si128(in[1],keys[0]);
	in[2] = _mm_xor_si128(in[2],keys[0]);
	in[3] = _mm_xor_si128(in[3],keys[0]);
	in[4] = _mm_xor_si128(in[4],keys[0]);
	in[5] = _mm_xor_si128(in[5],keys[0]);
	in[6] = _mm_xor_si128(in[6],keys[0]);
	in[7] = _mm_xor_si128(in[7],keys[0]);
	// print128_asint(in[1]);

	in[0] = _mm_aesenc_si128(in[0],keys[1]);
	in[1] = _mm_aesenc_si128(in[1],keys[1]);
	in[2] = _mm_aesenc_si128(in[2],keys[1]);
	in[3] = _mm_aesenc_si128(in[3],keys[1]);
	in[4] = _mm_aesenc_si128(in[4],keys[1]);
	in[5] = _mm_aesenc_si128(in[5],keys[1]);
	in[6] = _mm_aesenc_si128(in[6],keys[1]);
	in[7] = _mm_aesenc_si128(in[7],keys[1]);
	// print128_asint(in[1]);
	
	in[0] = _mm_aesenc_si128(in[0],keys[2]);
	in[1] = _mm_aesenc_si128(in[1],keys[2]);
	in[2] = _mm_aesenc_si128(in[2],keys[2]);
	in[3] = _mm_aesenc_si128(in[3],keys[2]);
	in[4] = _mm_aesenc_si128(in[4],keys[2]);
	in[5] = _mm_aesenc_si128(in[5],keys[2]);
	in[6] = _mm_aesenc_si128(in[6],keys[2]);
	in[7] = _mm_aesenc_si128(in[7],keys[2]);
	// print128_asint(in[1]);
	
	in[0] = _mm_aesenc_si128(in[0],keys[3]);
	in[1] = _mm_aesenc_si128(in[1],keys[3]);
	in[2] = _mm_aesenc_si128(in[2],keys[3]);
	in[3] = _mm_aesenc_si128(in[3],keys[3]);
	in[4] = _mm_aesenc_si128(in[4],keys[3]);
	in[5] = _mm_aesenc_si128(in[5],keys[3]);
	in[6] = _mm_aesenc_si128(in[6],keys[3]);
	in[7] = _mm_aesenc_si128(in[7],keys[3]);
	// print128_asint(in[1]);

	in[0] = _mm_aesenc_si128(in[0],keys[4]);
	in[1] = _mm_aesenc_si128(in[1],keys[4]);
	in[2] = _mm_aesenc_si128(in[2],keys[4]);
	in[3] = _mm_aesenc_si128(in[3],keys[4]);
	in[4] = _mm_aesenc_si128(in[4],keys[4]);
	in[5] = _mm_aesenc_si128(in[5],keys[4]);
	in[6] = _mm_aesenc_si128(in[6],keys[4]);
	in[7] = _mm_aesenc_si128(in[7],keys[4]);
	// print128_asint(in[1]);
	
	in[0] = _mm_aesenc_si128(in[0],keys[5]);
	in[1] = _mm_aesenc_si128(in[1],keys[5]);
	in[2] = _mm_aesenc_si128(in[2],keys[5]);
	in[3] = _mm_aesenc_si128(in[3],keys[5]);
	in[4] = _mm_aesenc_si128(in[4],keys[5]);
	in[5] = _mm_aesenc_si128(in[5],keys[5]);
	in[6] = _mm_aesenc_si128(in[6],keys[5]);
	in[7] = _mm_aesenc_si128(in[7],keys[5]);
	// print128_asint(in[1]);
	
	in[0] = _mm_aesenc_si128(in[0],keys[6]);
	in[1] = _mm_aesenc_si128(in[1],keys[6]);
	in[2] = _mm_aesenc_si128(in[2],keys[6]);
	in[3] = _mm_aesenc_si128(in[3],keys[6]);
	in[4] = _mm_aesenc_si128(in[4],keys[6]);
	in[5] = _mm_aesenc_si128(in[5],keys[6]);
	in[6] = _mm_aesenc_si128(in[6],keys[6]);
	in[7] = _mm_aesenc_si128(in[7],keys[6]);
	// print128_asint(in[1]);

	in[0] = _mm_aesenc_si128(in[0],keys[7]);
	in[1] = _mm_aesenc_si128(in[1],keys[7]);
	in[2] = _mm_aesenc_si128(in[2],keys[7]);
	in[3] = _mm_aesenc_si128(in[3],keys[7]);
	in[4] = _mm_aesenc_si128(in[4],keys[7]);
	in[5] = _mm_aesenc_si128(in[5],keys[7]);
	in[6] = _mm_aesenc_si128(in[6],keys[7]);
	in[7] = _mm_aesenc_si128(in[7],keys[7]);
	// print128_asint(in[1]);
	
	in[0] = _mm_aesenc_si128(in[0],keys[8]);
	in[1] = _mm_aesenc_si128(in[1],keys[8]);
	in[2] = _mm_aesenc_si128(in[2],keys[8]);
	in[3] = _mm_aesenc_si128(in[3],keys[8]);
	in[4] = _mm_aesenc_si128(in[4],keys[8]);
	in[5] = _mm_aesenc_si128(in[5],keys[8]);
	in[6] = _mm_aesenc_si128(in[6],keys[8]);
	in[7] = _mm_aesenc_si128(in[7],keys[8]);
	// print128_asint(in[1]);
	
	in[0] = _mm_aesenc_si128(in[0],keys[9]);
	in[1] = _mm_aesenc_si128(in[1],keys[9]);
	in[2] = _mm_aesenc_si128(in[2],keys[9]);
	in[3] = _mm_aesenc_si128(in[3],keys[9]);
	in[4] = _mm_aesenc_si128(in[4],keys[9]);
	in[5] = _mm_aesenc_si128(in[5],keys[9]);
	in[6] = _mm_aesenc_si128(in[6],keys[9]);
	in[7] = _mm_aesenc_si128(in[7],keys[9]);
	// print128_asint(in[1]);

	in[0] = _mm_aesenclast_si128(in[0],keys[10]);
	in[1] = _mm_aesenclast_si128(in[1],keys[10]);
	in[2] = _mm_aesenclast_si128(in[2],keys[10]);
	in[3] = _mm_aesenclast_si128(in[3],keys[10]);
	in[4] = _mm_aesenclast_si128(in[4],keys[10]);
	in[5] = _mm_aesenclast_si128(in[5],keys[10]);
	in[6] = _mm_aesenclast_si128(in[6],keys[10]);
	in[7] = _mm_aesenclast_si128(in[7],keys[10]);
} // */

// Changing to multi array method: Remove comment before void (Don't be concerned with the one after, there will be no issue)
/* void decrypt_8block(__m128i* in, __m128i* out) 
{
	// __m128i* tmp = malloc(8*sizeof(__m128i));
	
	out[0] = _mm_xor_si128(in[0],keys[10]);
	out[1] = _mm_xor_si128(in[1],keys[10]);
	out[2] = _mm_xor_si128(in[2],keys[10]);
	out[3] = _mm_xor_si128(in[3],keys[10]);
	out[4] = _mm_xor_si128(in[4],keys[10]);
	out[5] = _mm_xor_si128(in[5],keys[10]);
	out[6] = _mm_xor_si128(in[6],keys[10]);
	out[7] = _mm_xor_si128(in[7],keys[10]);
	// print128_asint(out[1]);

	out[0] = _mm_aesdec_si128(out[0],keys[11]);
	out[1] = _mm_aesdec_si128(out[1],keys[11]);
	out[2] = _mm_aesdec_si128(out[2],keys[11]);
	out[3] = _mm_aesdec_si128(out[3],keys[11]);
	out[4] = _mm_aesdec_si128(out[4],keys[11]);
	out[5] = _mm_aesdec_si128(out[5],keys[11]);
	out[6] = _mm_aesdec_si128(out[6],keys[11]);
	out[7] = _mm_aesdec_si128(out[7],keys[11]);
	// print128_asint(out[1]);
	
	out[0] = _mm_aesdec_si128(out[0],keys[12]);
	out[1] = _mm_aesdec_si128(out[1],keys[12]);
	out[2] = _mm_aesdec_si128(out[2],keys[12]);
	out[3] = _mm_aesdec_si128(out[3],keys[12]);
	out[4] = _mm_aesdec_si128(out[4],keys[12]);
	out[5] = _mm_aesdec_si128(out[5],keys[12]);
	out[6] = _mm_aesdec_si128(out[6],keys[12]);
	out[7] = _mm_aesdec_si128(out[7],keys[12]);
	// print128_asint(out[1]);
	
	out[0] = _mm_aesdec_si128(out[0],keys[13]);
	out[1] = _mm_aesdec_si128(out[1],keys[13]);
	out[2] = _mm_aesdec_si128(out[2],keys[13]);
	out[3] = _mm_aesdec_si128(out[3],keys[13]);
	out[4] = _mm_aesdec_si128(out[4],keys[13]);
	out[5] = _mm_aesdec_si128(out[5],keys[13]);
	out[6] = _mm_aesdec_si128(out[6],keys[13]);
	out[7] = _mm_aesdec_si128(out[7],keys[13]);
	// print128_asint(out[1]);

	out[0] = _mm_aesdec_si128(out[0],keys[14]);
	out[1] = _mm_aesdec_si128(out[1],keys[14]);
	out[2] = _mm_aesdec_si128(out[2],keys[14]);
	out[3] = _mm_aesdec_si128(out[3],keys[14]);
	out[4] = _mm_aesdec_si128(out[4],keys[14]);
	out[5] = _mm_aesdec_si128(out[5],keys[14]);
	out[6] = _mm_aesdec_si128(out[6],keys[14]);
	out[7] = _mm_aesdec_si128(out[7],keys[14]);
	// print128_asint(out[1]);
	
	out[0] = _mm_aesdec_si128(out[0],keys[15]);
	out[1] = _mm_aesdec_si128(out[1],keys[15]);
	out[2] = _mm_aesdec_si128(out[2],keys[15]);
	out[3] = _mm_aesdec_si128(out[3],keys[15]);
	out[4] = _mm_aesdec_si128(out[4],keys[15]);
	out[5] = _mm_aesdec_si128(out[5],keys[15]);
	out[6] = _mm_aesdec_si128(out[6],keys[15]);
	out[7] = _mm_aesdec_si128(out[7],keys[15]);
	// print128_asint(out[1]);
	
	out[0] = _mm_aesdec_si128(out[0],keys[16]);
	out[1] = _mm_aesdec_si128(out[1],keys[16]);
	out[2] = _mm_aesdec_si128(out[2],keys[16]);
	out[3] = _mm_aesdec_si128(out[3],keys[16]);
	out[4] = _mm_aesdec_si128(out[4],keys[16]);
	out[5] = _mm_aesdec_si128(out[5],keys[16]);
	out[6] = _mm_aesdec_si128(out[6],keys[16]);
	out[7] = _mm_aesdec_si128(out[7],keys[16]);
	// print128_asint(out[1]);

	out[0] = _mm_aesdec_si128(out[0],keys[17]);
	out[1] = _mm_aesdec_si128(out[1],keys[17]);
	out[2] = _mm_aesdec_si128(out[2],keys[17]);
	out[3] = _mm_aesdec_si128(out[3],keys[17]);
	out[4] = _mm_aesdec_si128(out[4],keys[17]);
	out[5] = _mm_aesdec_si128(out[5],keys[17]);
	out[6] = _mm_aesdec_si128(out[6],keys[17]);
	out[7] = _mm_aesdec_si128(out[7],keys[17]);
	// print128_asint(out[1]);
	
	out[0] = _mm_aesdec_si128(out[0],keys[18]);
	out[1] = _mm_aesdec_si128(out[1],keys[18]);
	out[2] = _mm_aesdec_si128(out[2],keys[18]);
	out[3] = _mm_aesdec_si128(out[3],keys[18]);
	out[4] = _mm_aesdec_si128(out[4],keys[18]);
	out[5] = _mm_aesdec_si128(out[5],keys[18]);
	out[6] = _mm_aesdec_si128(out[6],keys[18]);
	out[7] = _mm_aesdec_si128(out[7],keys[18]);
	// print128_asint(out[1]);
	
	out[0] = _mm_aesdec_si128(out[0],keys[19]);
	out[1] = _mm_aesdec_si128(out[1],keys[19]);
	out[2] = _mm_aesdec_si128(out[2],keys[19]);
	out[3] = _mm_aesdec_si128(out[3],keys[19]);
	out[4] = _mm_aesdec_si128(out[4],keys[19]);
	out[5] = _mm_aesdec_si128(out[5],keys[19]);
	out[6] = _mm_aesdec_si128(out[6],keys[19]);
	out[7] = _mm_aesdec_si128(out[7],keys[19]);
	// print128_asint(out[1]);

	out[0] = _mm_aesdeclast_si128(out[0],keys[0]);
	out[1] = _mm_aesdeclast_si128(out[1],keys[0]);
	out[2] = _mm_aesdeclast_si128(out[2],keys[0]);
	out[3] = _mm_aesdeclast_si128(out[3],keys[0]);
	out[4] = _mm_aesdeclast_si128(out[4],keys[0]);
	out[5] = _mm_aesdeclast_si128(out[5],keys[0]);
	out[6] = _mm_aesdeclast_si128(out[6],keys[0]);
	out[7] = _mm_aesdeclast_si128(out[7],keys[0]);
} // */

void decrypt_8block2(__m128i* in) 
{
	// __m128i* tmp = malloc(8*sizeof(__m128i));
	
	in[0] = _mm_xor_si128(in[0],keys[10]);
	in[1] = _mm_xor_si128(in[1],keys[10]);
	in[2] = _mm_xor_si128(in[2],keys[10]);
	in[3] = _mm_xor_si128(in[3],keys[10]);
	in[4] = _mm_xor_si128(in[4],keys[10]);
	in[5] = _mm_xor_si128(in[5],keys[10]);
	in[6] = _mm_xor_si128(in[6],keys[10]);
	in[7] = _mm_xor_si128(in[7],keys[10]);
	// print128_asint(in[1]);

	in[0] = _mm_aesdec_si128(in[0],keys[11]);
	in[1] = _mm_aesdec_si128(in[1],keys[11]);
	in[2] = _mm_aesdec_si128(in[2],keys[11]);
	in[3] = _mm_aesdec_si128(in[3],keys[11]);
	in[4] = _mm_aesdec_si128(in[4],keys[11]);
	in[5] = _mm_aesdec_si128(in[5],keys[11]);
	in[6] = _mm_aesdec_si128(in[6],keys[11]);
	in[7] = _mm_aesdec_si128(in[7],keys[11]);
	// print128_asint(in[1]);
	
	in[0] = _mm_aesdec_si128(in[0],keys[12]);
	in[1] = _mm_aesdec_si128(in[1],keys[12]);
	in[2] = _mm_aesdec_si128(in[2],keys[12]);
	in[3] = _mm_aesdec_si128(in[3],keys[12]);
	in[4] = _mm_aesdec_si128(in[4],keys[12]);
	in[5] = _mm_aesdec_si128(in[5],keys[12]);
	in[6] = _mm_aesdec_si128(in[6],keys[12]);
	in[7] = _mm_aesdec_si128(in[7],keys[12]);
	// print128_asint(in[1]);
	
	in[0] = _mm_aesdec_si128(in[0],keys[13]);
	in[1] = _mm_aesdec_si128(in[1],keys[13]);
	in[2] = _mm_aesdec_si128(in[2],keys[13]);
	in[3] = _mm_aesdec_si128(in[3],keys[13]);
	in[4] = _mm_aesdec_si128(in[4],keys[13]);
	in[5] = _mm_aesdec_si128(in[5],keys[13]);
	in[6] = _mm_aesdec_si128(in[6],keys[13]);
	in[7] = _mm_aesdec_si128(in[7],keys[13]);
	// print128_asint(in[1]);

	in[0] = _mm_aesdec_si128(in[0],keys[14]);
	in[1] = _mm_aesdec_si128(in[1],keys[14]);
	in[2] = _mm_aesdec_si128(in[2],keys[14]);
	in[3] = _mm_aesdec_si128(in[3],keys[14]);
	in[4] = _mm_aesdec_si128(in[4],keys[14]);
	in[5] = _mm_aesdec_si128(in[5],keys[14]);
	in[6] = _mm_aesdec_si128(in[6],keys[14]);
	in[7] = _mm_aesdec_si128(in[7],keys[14]);
	// print128_asint(in[1]);
	
	in[0] = _mm_aesdec_si128(in[0],keys[15]);
	in[1] = _mm_aesdec_si128(in[1],keys[15]);
	in[2] = _mm_aesdec_si128(in[2],keys[15]);
	in[3] = _mm_aesdec_si128(in[3],keys[15]);
	in[4] = _mm_aesdec_si128(in[4],keys[15]);
	in[5] = _mm_aesdec_si128(in[5],keys[15]);
	in[6] = _mm_aesdec_si128(in[6],keys[15]);
	in[7] = _mm_aesdec_si128(in[7],keys[15]);
	// print128_asint(in[1]);
	
	in[0] = _mm_aesdec_si128(in[0],keys[16]);
	in[1] = _mm_aesdec_si128(in[1],keys[16]);
	in[2] = _mm_aesdec_si128(in[2],keys[16]);
	in[3] = _mm_aesdec_si128(in[3],keys[16]);
	in[4] = _mm_aesdec_si128(in[4],keys[16]);
	in[5] = _mm_aesdec_si128(in[5],keys[16]);
	in[6] = _mm_aesdec_si128(in[6],keys[16]);
	in[7] = _mm_aesdec_si128(in[7],keys[16]);
	// print128_asint(in[1]);

	in[0] = _mm_aesdec_si128(in[0],keys[17]);
	in[1] = _mm_aesdec_si128(in[1],keys[17]);
	in[2] = _mm_aesdec_si128(in[2],keys[17]);
	in[3] = _mm_aesdec_si128(in[3],keys[17]);
	in[4] = _mm_aesdec_si128(in[4],keys[17]);
	in[5] = _mm_aesdec_si128(in[5],keys[17]);
	in[6] = _mm_aesdec_si128(in[6],keys[17]);
	in[7] = _mm_aesdec_si128(in[7],keys[17]);
	// print128_asint(in[1]);
	
	in[0] = _mm_aesdec_si128(in[0],keys[18]);
	in[1] = _mm_aesdec_si128(in[1],keys[18]);
	in[2] = _mm_aesdec_si128(in[2],keys[18]);
	in[3] = _mm_aesdec_si128(in[3],keys[18]);
	in[4] = _mm_aesdec_si128(in[4],keys[18]);
	in[5] = _mm_aesdec_si128(in[5],keys[18]);
	in[6] = _mm_aesdec_si128(in[6],keys[18]);
	in[7] = _mm_aesdec_si128(in[7],keys[18]);
	// print128_asint(in[1]);
	
	in[0] = _mm_aesdec_si128(in[0],keys[19]);
	in[1] = _mm_aesdec_si128(in[1],keys[19]);
	in[2] = _mm_aesdec_si128(in[2],keys[19]);
	in[3] = _mm_aesdec_si128(in[3],keys[19]);
	in[4] = _mm_aesdec_si128(in[4],keys[19]);
	in[5] = _mm_aesdec_si128(in[5],keys[19]);
	in[6] = _mm_aesdec_si128(in[6],keys[19]);
	in[7] = _mm_aesdec_si128(in[7],keys[19]);
	// print128_asint(in[1]);

	in[0] = _mm_aesdeclast_si128(in[0],keys[0]);
	in[1] = _mm_aesdeclast_si128(in[1],keys[0]);
	in[2] = _mm_aesdeclast_si128(in[2],keys[0]);
	in[3] = _mm_aesdeclast_si128(in[3],keys[0]);
	in[4] = _mm_aesdeclast_si128(in[4],keys[0]);
	in[5] = _mm_aesdeclast_si128(in[5],keys[0]);
	in[6] = _mm_aesdeclast_si128(in[6],keys[0]);
	in[7] = _mm_aesdeclast_si128(in[7],keys[0]);
} // */ 
