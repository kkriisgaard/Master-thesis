#include <stdio.h>
#include "api.h"
#include "emmintrin.h"
#include "wmmintrin.h"
#include "tmmintrin.h"
#include "auxfuncs.h"
// #include <stdbool.h>

// const unsigned long long zero = 0; /* what a surprise. */
 
 /*
 
void print128_aschar(__m128i p) // Print 128-bit block as characters
{
	unsigned char *val = (unsigned char*) &p; // Line taken from http://stackoverflow.com/questions/13257166/print-a-m128i-variable (top answer)
	printf("%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c \n", val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7], val[8], val[9], val[10], val[11], val[12], val[13], val[14], val[15], val[16]); 
} 

void print128_asint(__m128i p) // Print 128-bit block as integer
{
	unsigned char *val = (unsigned char*) &p; 
	printf("%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d \n", val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7], val[8], val[9], val[10], val[11], val[12], val[13], val[14], val[15], val[16]); 
} // */

__m128i mul2(__m128i x)
{
	const __m128i red  = _mm_set_epi64x(0x8700000000000000,0x0000000000000000); // This will be loaded in such that the last byte is 0x87, the remaining are zeros. I wish I was kidding.
	const __m128i ZERO = _mm_setzero_si128();
	
	__m128i mask = _mm_cmpgt_epi32(ZERO,x); 
	mask = _mm_shuffle_epi32(mask,0xff); 	
	
	__m128i x2 = _mm_or_si128(_mm_slli_epi64(x,1),_mm_srli_epi64(_mm_slli_si128(x,8),63)); 	
	return _mm_xor_si128(x2,_mm_and_si128(red,mask));
}

// const unsigned char rcon[17] = {0x2f,0x5e,0xbc,0x63,0xc6,0x97,0x35,0x6a,0xd4,0xb3,0x7d,0xfa,0xef,0xc5,0x91,0x39,0x72}; 

// __m128i keys[28];

/*__m128i key_exp_assist(__m128i t1, __m128i t2)
{
	__m128i t3 = _mm_slli_si128(t1,0x04);
	t2 = _mm_shuffle_epi32(t2,0xFF);
	t1 = _mm_xor_si128(t1,t3);
	t3 = _mm_slli_si128(t1,0x04);
	t1 = _mm_xor_si128(t1,t3);
	t3 = _mm_slli_si128(t1,0x04);
	t1 = _mm_xor_si128(t1,t3);
	return _mm_xor_si128(t1,t2);
}*/

/*
#define LFSR2( key, new_key ) \
  new_key = xor( _mm_and_si128( mask_top_7_bits  , _mm_slli_epi32( key, 1 ) ) ,  \
  				 _mm_and_si128( mask_bottom_1_bit, _mm_srli_epi32( key, 7 ) ) ); \
  new_key = xor( _mm_and_si128( mask_bottom_1_bit, _mm_srli_epi32( key, 5 ) ),   \
			     new_key ); 
*/


__m128i LFSR22(__m128i k) /* No. It isn't a fucking multiple definition, when LFSR2 is local in encrypt.c, and encrypt.c doesn't depend on auxfuncs.c or .h. Fuck you gcc.*/
{
	__m128i mask_high = _mm_set1_epi8(0xfe);
	__m128i mask_low  = _mm_set1_epi8(0x01);
	__m128i tmp = _mm_xor_si128( _mm_and_si128( mask_high  , _mm_slli_epi32( k, 1 ) ) , 
				    _mm_and_si128( mask_low, _mm_srli_epi32( k, 7 ) ) );
	return _mm_xor_si128(_mm_and_si128( mask_low, _mm_srli_epi32( k, 5 ) ),tmp);
}


__m128i encrypt_block(__m128i pt, __m128i tweak, __m128i* keys) // Old one-block function
{
	__m128i h = _mm_set_epi8( 7,0,13,10, 11,4,1,14, 15,8,5,2, 3,12,9,6 );
	__m128i tmp = _mm_xor_si128(keys[0],tweak); // Round key
	__m128i ct = _mm_xor_si128(tmp,pt); // Ciphertext
	__m128i tweaks[8];
	tweaks[0] = tweak;
	tweaks[1] = _mm_shuffle_epi8(tweaks[0],h);
	tweaks[2] = _mm_shuffle_epi8(tweaks[1],h);
	tweaks[3] = _mm_shuffle_epi8(tweaks[2],h);
	tweaks[4] = _mm_shuffle_epi8(tweaks[3],h);
	tweaks[5] = _mm_shuffle_epi8(tweaks[4],h);
	tweaks[6] = _mm_shuffle_epi8(tweaks[5],h);
	tweaks[7] = _mm_shuffle_epi8(tweaks[6],h);
	
	tmp = _mm_xor_si128(keys[1],tweaks[1]);
	ct = _mm_aesenc_si128(ct,tmp);
	tmp = _mm_xor_si128(keys[2],tweaks[2]);
	ct = _mm_aesenc_si128(ct,tmp);
	tmp = _mm_xor_si128(keys[3],tweaks[3]);
	ct = _mm_aesenc_si128(ct,tmp);
	tmp = _mm_xor_si128(keys[4],tweaks[4]);
	ct = _mm_aesenc_si128(ct,tmp);
	tmp = _mm_xor_si128(keys[5],tweaks[5]);
	ct = _mm_aesenc_si128(ct,tmp);
	tmp = _mm_xor_si128(keys[6],tweaks[6]);
	ct = _mm_aesenc_si128(ct,tmp);
	tmp = _mm_xor_si128(keys[7],tweaks[7]);
	ct = _mm_aesenc_si128(ct,tmp);
	tmp = _mm_xor_si128(keys[8],tweaks[0]);
	ct = _mm_aesenc_si128(ct,tmp);
	tmp = _mm_xor_si128(keys[9],tweaks[1]);
	ct = _mm_aesenc_si128(ct,tmp);
	tmp = _mm_xor_si128(keys[10],tweaks[2]);
	ct = _mm_aesenc_si128(ct,tmp);
	tmp = _mm_xor_si128(keys[11],tweaks[3]);
	ct = _mm_aesenc_si128(ct,tmp);
	tmp = _mm_xor_si128(keys[12],tweaks[4]);
	ct = _mm_aesenc_si128(ct,tmp);
	tmp = _mm_xor_si128(keys[13],tweaks[5]);
	ct = _mm_aesenc_si128(ct,tmp);
	tmp = _mm_xor_si128(keys[14],tweaks[6]);
	ct = _mm_aesenc_si128(ct,tmp);

	return ct;

}


__m128i encrypt_block_ver(__m128i pt, __m128i tweak, __m128i* keys) // Old one-block function
{
	__m128i h = _mm_set_epi8( 7,0,13,10, 11,4,1,14, 15,8,5,2, 3,12,9,6 );
	__m128i tmp = _mm_xor_si128(keys[15],tweak); // Round key
	__m128i ct = _mm_xor_si128(tmp,pt); // Ciphertext
	__m128i tweaks[8];
	tweaks[0] = tweak;
	tweaks[1] = _mm_shuffle_epi8(tweaks[0],h);
	tweaks[2] = _mm_shuffle_epi8(tweaks[1],h);
	tweaks[3] = _mm_shuffle_epi8(tweaks[2],h);
	tweaks[4] = _mm_shuffle_epi8(tweaks[3],h);
	tweaks[5] = _mm_shuffle_epi8(tweaks[4],h);
	tweaks[6] = _mm_shuffle_epi8(tweaks[5],h);
	tweaks[7] = _mm_shuffle_epi8(tweaks[6],h);
	
	tmp = _mm_xor_si128(keys[16],tweaks[1]);
	ct = _mm_aesenc_si128(ct,tmp);
	tmp = _mm_xor_si128(keys[17],tweaks[2]);
	ct = _mm_aesenc_si128(ct,tmp);
	tmp = _mm_xor_si128(keys[18],tweaks[3]);
	ct = _mm_aesenc_si128(ct,tmp);
	tmp = _mm_xor_si128(keys[19],tweaks[4]);
	ct = _mm_aesenc_si128(ct,tmp);
	tmp = _mm_xor_si128(keys[20],tweaks[5]);
	ct = _mm_aesenc_si128(ct,tmp);
	tmp = _mm_xor_si128(keys[21],tweaks[6]);
	ct = _mm_aesenc_si128(ct,tmp);
	tmp = _mm_xor_si128(keys[22],tweaks[7]);
	ct = _mm_aesenc_si128(ct,tmp);
	tmp = _mm_xor_si128(keys[23],tweaks[0]);
	ct = _mm_aesenc_si128(ct,tmp);
	tmp = _mm_xor_si128(keys[24],tweaks[1]);
	ct = _mm_aesenc_si128(ct,tmp);
	tmp = _mm_xor_si128(keys[25],tweaks[2]);
	ct = _mm_aesenc_si128(ct,tmp);
	tmp = _mm_xor_si128(keys[26],tweaks[3]);
	ct = _mm_aesenc_si128(ct,tmp);
	tmp = _mm_xor_si128(keys[27],tweaks[4]);
	ct = _mm_aesenc_si128(ct,tmp);
	tmp = _mm_xor_si128(keys[28],tweaks[5]);
	ct = _mm_aesenc_si128(ct,tmp);
	tmp = _mm_xor_si128(keys[29],tweaks[6]);
	ct = _mm_aesenc_si128(ct,tmp);

	return ct;

}

/*void encrypt_8block3(__m128i* in, const __m128i tag, __m128i idx, const __m128i nonce) // And I though encrypt_8block in COLM was tedious to write...
{
	
	__m128i tmp;
	__m128i tweaks[8][8]; 
	__m128i n_tmp[8];
	__m128i h = _mm_set_epi8( 7,0,13,10, 11,4,1,14, 15,8,5,2, 3,12,9,6 );
	__m128i one = _mm_set_epi8(0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1);
	
	
	// idx = _mm_set_epi64x(zero,i);
	// tmp = encrypt_block(nonce,_mm_xor_si128(one_tag,idx) ); // tweak = _mm_xor_si128(one_tag,idx)
	
	tweaks[0][0] = idx;
	tweaks[0][1] = _mm_add_epi8(tweaks[0][0],one);
	tweaks[0][2] = _mm_add_epi8(tweaks[0][1],one);
	tweaks[0][3] = _mm_add_epi8(tweaks[0][2],one);
	tweaks[0][4] = _mm_add_epi8(tweaks[0][3],one);
	tweaks[0][5] = _mm_add_epi8(tweaks[0][4],one);
	tweaks[0][6] = _mm_add_epi8(tweaks[0][5],one);
	tweaks[0][7] = _mm_add_epi8(tweaks[0][6],one);
		
	/*__m128i tmp = _mm_xor_si128(keys[0],tweak); // Round key
	__m128i ct = _mm_xor_si128(tmp,pt); // Ciphertext*/
	
	// tmp = encrypt_block(nonce,_mm_xor_si128(one_tag,idx) );
	
	/* Building tweaks */ 
	/*
	tweaks[1][0] = _mm_shuffle_epi8(tweaks[0][0],h);
	tweaks[1][1] = _mm_shuffle_epi8(tweaks[0][1],h);
	tweaks[1][2] = _mm_shuffle_epi8(tweaks[0][2],h);
	tweaks[1][3] = _mm_shuffle_epi8(tweaks[0][3],h);
	tweaks[1][4] = _mm_shuffle_epi8(tweaks[0][4],h);
	tweaks[1][5] = _mm_shuffle_epi8(tweaks[0][5],h);
	tweaks[1][6] = _mm_shuffle_epi8(tweaks[0][6],h);
	tweaks[1][7] = _mm_shuffle_epi8(tweaks[0][7],h);
	
	
	tweaks[2][0] = _mm_shuffle_epi8(tweaks[1][0],h);
	tweaks[2][1] = _mm_shuffle_epi8(tweaks[1][1],h);
	tweaks[2][2] = _mm_shuffle_epi8(tweaks[1][2],h);
	tweaks[2][3] = _mm_shuffle_epi8(tweaks[1][3],h);
	tweaks[2][4] = _mm_shuffle_epi8(tweaks[1][4],h);
	tweaks[2][5] = _mm_shuffle_epi8(tweaks[1][5],h);
	tweaks[2][6] = _mm_shuffle_epi8(tweaks[1][6],h);
	tweaks[2][7] = _mm_shuffle_epi8(tweaks[1][7],h);
	
	
	tweaks[3][0] = _mm_shuffle_epi8(tweaks[2][0],h);
	tweaks[3][1] = _mm_shuffle_epi8(tweaks[2][1],h);
	tweaks[3][2] = _mm_shuffle_epi8(tweaks[2][2],h);
	tweaks[3][3] = _mm_shuffle_epi8(tweaks[2][3],h);
	tweaks[3][4] = _mm_shuffle_epi8(tweaks[2][4],h);
	tweaks[3][5] = _mm_shuffle_epi8(tweaks[2][5],h);
	tweaks[3][6] = _mm_shuffle_epi8(tweaks[2][6],h);
	tweaks[3][7] = _mm_shuffle_epi8(tweaks[2][7],h);
	
	
	tweaks[4][0] = _mm_shuffle_epi8(tweaks[3][0],h);
	tweaks[4][1] = _mm_shuffle_epi8(tweaks[3][1],h);
	tweaks[4][2] = _mm_shuffle_epi8(tweaks[3][2],h);
	tweaks[4][3] = _mm_shuffle_epi8(tweaks[3][3],h);
	tweaks[4][4] = _mm_shuffle_epi8(tweaks[3][4],h);
	tweaks[4][5] = _mm_shuffle_epi8(tweaks[3][5],h);
	tweaks[4][6] = _mm_shuffle_epi8(tweaks[3][6],h);
	tweaks[4][7] = _mm_shuffle_epi8(tweaks[3][7],h);
	
	
	tweaks[5][0] = _mm_shuffle_epi8(tweaks[4][0],h);
	tweaks[5][1] = _mm_shuffle_epi8(tweaks[4][1],h);
	tweaks[5][2] = _mm_shuffle_epi8(tweaks[4][2],h);
	tweaks[5][3] = _mm_shuffle_epi8(tweaks[4][3],h);
	tweaks[5][4] = _mm_shuffle_epi8(tweaks[4][4],h);
	tweaks[5][5] = _mm_shuffle_epi8(tweaks[4][5],h);
	tweaks[5][6] = _mm_shuffle_epi8(tweaks[4][6],h);
	tweaks[5][7] = _mm_shuffle_epi8(tweaks[4][7],h);
	
	
	tweaks[6][0] = _mm_shuffle_epi8(tweaks[5][0],h);
	tweaks[6][1] = _mm_shuffle_epi8(tweaks[5][1],h);
	tweaks[6][2] = _mm_shuffle_epi8(tweaks[5][2],h);
	tweaks[6][3] = _mm_shuffle_epi8(tweaks[5][3],h);
	tweaks[6][4] = _mm_shuffle_epi8(tweaks[5][4],h);
	tweaks[6][5] = _mm_shuffle_epi8(tweaks[5][5],h);
	tweaks[6][6] = _mm_shuffle_epi8(tweaks[5][6],h);
	tweaks[6][7] = _mm_shuffle_epi8(tweaks[5][7],h);
	
	
	tweaks[7][0] = _mm_shuffle_epi8(tweaks[6][0],h);
	tweaks[7][1] = _mm_shuffle_epi8(tweaks[6][1],h);
	tweaks[7][2] = _mm_shuffle_epi8(tweaks[6][2],h);
	tweaks[7][3] = _mm_shuffle_epi8(tweaks[6][3],h);
	tweaks[7][4] = _mm_shuffle_epi8(tweaks[6][4],h);
	tweaks[7][5] = _mm_shuffle_epi8(tweaks[6][5],h);
	tweaks[7][6] = _mm_shuffle_epi8(tweaks[6][6],h);
	tweaks[7][7] = _mm_shuffle_epi8(tweaks[6][7],h);
	
	/*__m128i tmp = _mm_xor_si128(keys[0],tweak); // Round key
	__m128i ct = _mm_xor_si128(tmp,pt); // Ciphertext*/
	
	/* Encrypting the nonce */
	/*
	tmp = _mm_xor_si128(keys[0],tweaks[0][0]);
	n_tmp[0] = _mm_xor_si128(tmp,nonce);
	tmp = _mm_xor_si128(keys[0],tweaks[0][1]);
	n_tmp[1] = _mm_xor_si128(tmp,nonce);
	tmp = _mm_xor_si128(keys[0],tweaks[0][2]);
	n_tmp[2] = _mm_xor_si128(tmp,nonce);
	tmp = _mm_xor_si128(keys[0],tweaks[0][3]);
	n_tmp[3] = _mm_xor_si128(tmp,nonce);
	tmp = _mm_xor_si128(keys[0],tweaks[0][4]);
	n_tmp[4] = _mm_xor_si128(tmp,nonce);
	tmp = _mm_xor_si128(keys[0],tweaks[0][5]);
	n_tmp[5] = _mm_xor_si128(tmp,nonce);
	tmp = _mm_xor_si128(keys[0],tweaks[0][6]);
	n_tmp[6] = _mm_xor_si128(tmp,nonce);
	tmp = _mm_xor_si128(keys[0],tweaks[0][7]);
	n_tmp[7] = _mm_xor_si128(tmp,nonce);
	
	
	tmp = _mm_xor_si128(keys[1],tweaks[1][0]); 
	n_tmp[0] = _mm_aesenc_si128(n_tmp[0],tmp);
	tmp = _mm_xor_si128(keys[1],tweaks[1][1]);
	n_tmp[1] = _mm_aesenc_si128(n_tmp[1],tmp);
	tmp = _mm_xor_si128(keys[1],tweaks[1][2]);
	n_tmp[2] = _mm_aesenc_si128(n_tmp[2],tmp);
	tmp = _mm_xor_si128(keys[1],tweaks[1][3]);
	n_tmp[3] = _mm_aesenc_si128(n_tmp[3],tmp);
	tmp = _mm_xor_si128(keys[1],tweaks[1][4]);
	n_tmp[4] = _mm_aesenc_si128(n_tmp[4],tmp);
	tmp = _mm_xor_si128(keys[1],tweaks[1][5]);
	n_tmp[5] = _mm_aesenc_si128(n_tmp[5],tmp);
	tmp = _mm_xor_si128(keys[1],tweaks[1][6]);
	n_tmp[6] = _mm_aesenc_si128(n_tmp[6],tmp);
	tmp = _mm_xor_si128(keys[1],tweaks[1][7]);
	n_tmp[7] = _mm_aesenc_si128(n_tmp[7],tmp);
	
	
	tmp = _mm_xor_si128(keys[2],tweaks[2][0]);
	n_tmp[0] = _mm_aesenc_si128(n_tmp[0],tmp);
	tmp = _mm_xor_si128(keys[2],tweaks[2][1]);
	n_tmp[1] = _mm_aesenc_si128(n_tmp[1],tmp);
	tmp = _mm_xor_si128(keys[2],tweaks[2][2]);
	n_tmp[2] = _mm_aesenc_si128(n_tmp[2],tmp);
	tmp = _mm_xor_si128(keys[2],tweaks[2][3]);
	n_tmp[3] = _mm_aesenc_si128(n_tmp[3],tmp);
	tmp = _mm_xor_si128(keys[2],tweaks[2][4]);
	n_tmp[4] = _mm_aesenc_si128(n_tmp[4],tmp);
	tmp = _mm_xor_si128(keys[2],tweaks[2][5]);
	n_tmp[5] = _mm_aesenc_si128(n_tmp[5],tmp);
	tmp = _mm_xor_si128(keys[2],tweaks[2][6]);
	n_tmp[6] = _mm_aesenc_si128(n_tmp[6],tmp);
	tmp = _mm_xor_si128(keys[2],tweaks[2][7]);
	n_tmp[7] = _mm_aesenc_si128(n_tmp[7],tmp);
	
	
	tmp = _mm_xor_si128(keys[3],tweaks[3][0]);
	n_tmp[0] = _mm_aesenc_si128(n_tmp[0],tmp);
	tmp = _mm_xor_si128(keys[3],tweaks[3][1]);
	n_tmp[1] = _mm_aesenc_si128(n_tmp[1],tmp);
	tmp = _mm_xor_si128(keys[3],tweaks[3][2]);
	n_tmp[2] = _mm_aesenc_si128(n_tmp[2],tmp);
	tmp = _mm_xor_si128(keys[3],tweaks[3][3]);
	n_tmp[3] = _mm_aesenc_si128(n_tmp[3],tmp);
	tmp = _mm_xor_si128(keys[3],tweaks[3][4]);
	n_tmp[4] = _mm_aesenc_si128(n_tmp[4],tmp);
	tmp = _mm_xor_si128(keys[3],tweaks[3][5]);
	n_tmp[5] = _mm_aesenc_si128(n_tmp[5],tmp);
	tmp = _mm_xor_si128(keys[3],tweaks[3][6]);
	n_tmp[6] = _mm_aesenc_si128(n_tmp[6],tmp);
	tmp = _mm_xor_si128(keys[3],tweaks[3][7]);
	n_tmp[7] = _mm_aesenc_si128(n_tmp[7],tmp);
	
	
	tmp = _mm_xor_si128(keys[4],tweaks[4][0]);
	n_tmp[0] = _mm_aesenc_si128(n_tmp[0],tmp);
	tmp = _mm_xor_si128(keys[4],tweaks[4][1]);
	n_tmp[1] = _mm_aesenc_si128(n_tmp[1],tmp);
	tmp = _mm_xor_si128(keys[4],tweaks[4][2]);
	n_tmp[2] = _mm_aesenc_si128(n_tmp[2],tmp);
	tmp = _mm_xor_si128(keys[4],tweaks[4][3]);
	n_tmp[3] = _mm_aesenc_si128(n_tmp[3],tmp);
	tmp = _mm_xor_si128(keys[4],tweaks[4][4]);
	n_tmp[4] = _mm_aesenc_si128(n_tmp[4],tmp);
	tmp = _mm_xor_si128(keys[4],tweaks[4][5]);
	n_tmp[5] = _mm_aesenc_si128(n_tmp[5],tmp);
	tmp = _mm_xor_si128(keys[4],tweaks[4][6]);
	n_tmp[6] = _mm_aesenc_si128(n_tmp[6],tmp);
	tmp = _mm_xor_si128(keys[4],tweaks[4][7]);
	n_tmp[7] = _mm_aesenc_si128(n_tmp[7],tmp);
	
	
	tmp = _mm_xor_si128(keys[5],tweaks[5][0]);
	n_tmp[0] = _mm_aesenc_si128(n_tmp[0],tmp);
	tmp = _mm_xor_si128(keys[5],tweaks[5][1]);
	n_tmp[1] = _mm_aesenc_si128(n_tmp[1],tmp);
	tmp = _mm_xor_si128(keys[5],tweaks[5][2]);
	n_tmp[2] = _mm_aesenc_si128(n_tmp[2],tmp);
	tmp = _mm_xor_si128(keys[5],tweaks[5][3]);
	n_tmp[3] = _mm_aesenc_si128(n_tmp[3],tmp);
	tmp = _mm_xor_si128(keys[5],tweaks[5][4]);
	n_tmp[4] = _mm_aesenc_si128(n_tmp[4],tmp);
	tmp = _mm_xor_si128(keys[5],tweaks[5][5]);
	n_tmp[5] = _mm_aesenc_si128(n_tmp[5],tmp);
	tmp = _mm_xor_si128(keys[5],tweaks[5][6]);
	n_tmp[6] = _mm_aesenc_si128(n_tmp[6],tmp);
	tmp = _mm_xor_si128(keys[5],tweaks[5][7]);
	n_tmp[7] = _mm_aesenc_si128(n_tmp[7],tmp);
	
	
	tmp = _mm_xor_si128(keys[6],tweaks[6][0]);
	n_tmp[0] = _mm_aesenc_si128(n_tmp[0],tmp);
	tmp = _mm_xor_si128(keys[6],tweaks[6][1]);
	n_tmp[1] = _mm_aesenc_si128(n_tmp[1],tmp);
	tmp = _mm_xor_si128(keys[6],tweaks[6][2]);
	n_tmp[2] = _mm_aesenc_si128(n_tmp[2],tmp);
	tmp = _mm_xor_si128(keys[6],tweaks[6][3]);
	n_tmp[3] = _mm_aesenc_si128(n_tmp[3],tmp);
	tmp = _mm_xor_si128(keys[6],tweaks[6][4]);
	n_tmp[4] = _mm_aesenc_si128(n_tmp[4],tmp);
	tmp = _mm_xor_si128(keys[6],tweaks[6][5]);
	n_tmp[5] = _mm_aesenc_si128(n_tmp[5],tmp);
	tmp = _mm_xor_si128(keys[6],tweaks[6][6]);
	n_tmp[6] = _mm_aesenc_si128(n_tmp[6],tmp);
	tmp = _mm_xor_si128(keys[6],tweaks[6][7]);
	n_tmp[7] = _mm_aesenc_si128(n_tmp[7],tmp);
	
	
	tmp = _mm_xor_si128(keys[7],tweaks[7][0]);
	n_tmp[0] = _mm_aesenc_si128(n_tmp[0],tmp);
	tmp = _mm_xor_si128(keys[7],tweaks[7][1]);
	n_tmp[1] = _mm_aesenc_si128(n_tmp[1],tmp);
	tmp = _mm_xor_si128(keys[7],tweaks[7][2]);
	n_tmp[2] = _mm_aesenc_si128(n_tmp[2],tmp);
	tmp = _mm_xor_si128(keys[7],tweaks[7][3]);
	n_tmp[3] = _mm_aesenc_si128(n_tmp[3],tmp);
	tmp = _mm_xor_si128(keys[7],tweaks[7][4]);
	n_tmp[4] = _mm_aesenc_si128(n_tmp[4],tmp);
	tmp = _mm_xor_si128(keys[7],tweaks[7][5]);
	n_tmp[5] = _mm_aesenc_si128(n_tmp[5],tmp);
	tmp = _mm_xor_si128(keys[7],tweaks[7][6]);
	n_tmp[6] = _mm_aesenc_si128(n_tmp[6],tmp);
	tmp = _mm_xor_si128(keys[7],tweaks[7][7]);
	n_tmp[7] = _mm_aesenc_si128(n_tmp[7],tmp);
	
	
	tmp = _mm_xor_si128(keys[8],tweaks[0][0]);
	n_tmp[0] = _mm_aesenc_si128(n_tmp[0],tmp);
	tmp = _mm_xor_si128(keys[8],tweaks[0][1]);
	n_tmp[1] = _mm_aesenc_si128(n_tmp[1],tmp);
	tmp = _mm_xor_si128(keys[8],tweaks[0][2]);
	n_tmp[2] = _mm_aesenc_si128(n_tmp[2],tmp);
	tmp = _mm_xor_si128(keys[8],tweaks[0][3]);
	n_tmp[3] = _mm_aesenc_si128(n_tmp[3],tmp);
	tmp = _mm_xor_si128(keys[8],tweaks[0][4]);
	n_tmp[4] = _mm_aesenc_si128(n_tmp[4],tmp);
	tmp = _mm_xor_si128(keys[8],tweaks[0][5]);
	n_tmp[5] = _mm_aesenc_si128(n_tmp[5],tmp);
	tmp = _mm_xor_si128(keys[8],tweaks[0][6]);
	n_tmp[6] = _mm_aesenc_si128(n_tmp[6],tmp);
	tmp = _mm_xor_si128(keys[8],tweaks[0][7]);
	n_tmp[7] = _mm_aesenc_si128(n_tmp[7],tmp);
	
	
	tmp = _mm_xor_si128(keys[9],tweaks[1][0]);
	n_tmp[0] = _mm_aesenc_si128(n_tmp[0],tmp);
	tmp = _mm_xor_si128(keys[9],tweaks[1][1]);
	n_tmp[1] = _mm_aesenc_si128(n_tmp[1],tmp);
	tmp = _mm_xor_si128(keys[9],tweaks[1][2]);
	n_tmp[2] = _mm_aesenc_si128(n_tmp[2],tmp);
	tmp = _mm_xor_si128(keys[9],tweaks[1][3]);
	n_tmp[3] = _mm_aesenc_si128(n_tmp[3],tmp);
	tmp = _mm_xor_si128(keys[9],tweaks[1][4]);
	n_tmp[4] = _mm_aesenc_si128(n_tmp[4],tmp);
	tmp = _mm_xor_si128(keys[9],tweaks[1][5]);
	n_tmp[5] = _mm_aesenc_si128(n_tmp[5],tmp);
	tmp = _mm_xor_si128(keys[9],tweaks[1][6]);
	n_tmp[6] = _mm_aesenc_si128(n_tmp[6],tmp);
	tmp = _mm_xor_si128(keys[9],tweaks[1][7]);
	n_tmp[7] = _mm_aesenc_si128(n_tmp[7],tmp);
	
	
	tmp = _mm_xor_si128(keys[10],tweaks[2][0]);
	n_tmp[0] = _mm_aesenc_si128(n_tmp[0],tmp);
	tmp = _mm_xor_si128(keys[10],tweaks[2][1]);
	n_tmp[1] = _mm_aesenc_si128(n_tmp[1],tmp);
	tmp = _mm_xor_si128(keys[10],tweaks[2][2]);
	n_tmp[2] = _mm_aesenc_si128(n_tmp[2],tmp);
	tmp = _mm_xor_si128(keys[10],tweaks[2][3]);
	n_tmp[3] = _mm_aesenc_si128(n_tmp[3],tmp);
	tmp = _mm_xor_si128(keys[10],tweaks[2][4]);
	n_tmp[4] = _mm_aesenc_si128(n_tmp[4],tmp);
	tmp = _mm_xor_si128(keys[10],tweaks[2][5]);
	n_tmp[5] = _mm_aesenc_si128(n_tmp[5],tmp);
	tmp = _mm_xor_si128(keys[10],tweaks[2][6]);
	n_tmp[6] = _mm_aesenc_si128(n_tmp[6],tmp);
	tmp = _mm_xor_si128(keys[10],tweaks[2][7]);
	n_tmp[7] = _mm_aesenc_si128(n_tmp[7],tmp);
	
	
	tmp = _mm_xor_si128(keys[11],tweaks[3][0]);
	n_tmp[0] = _mm_aesenc_si128(n_tmp[0],tmp);
	tmp = _mm_xor_si128(keys[11],tweaks[3][1]);
	n_tmp[1] = _mm_aesenc_si128(n_tmp[1],tmp);
	tmp = _mm_xor_si128(keys[11],tweaks[3][2]);
	n_tmp[2] = _mm_aesenc_si128(n_tmp[2],tmp);
	tmp = _mm_xor_si128(keys[11],tweaks[3][3]);
	n_tmp[3] = _mm_aesenc_si128(n_tmp[3],tmp);
	tmp = _mm_xor_si128(keys[11],tweaks[3][4]);
	n_tmp[4] = _mm_aesenc_si128(n_tmp[4],tmp);
	tmp = _mm_xor_si128(keys[11],tweaks[3][5]);
	n_tmp[5] = _mm_aesenc_si128(n_tmp[5],tmp);
	tmp = _mm_xor_si128(keys[11],tweaks[3][6]);
	n_tmp[6] = _mm_aesenc_si128(n_tmp[6],tmp);
	tmp = _mm_xor_si128(keys[11],tweaks[3][7]);
	n_tmp[7] = _mm_aesenc_si128(n_tmp[7],tmp);
	
	
	tmp = _mm_xor_si128(keys[12],tweaks[4][0]);
	n_tmp[0] = _mm_aesenc_si128(n_tmp[0],tmp);
	tmp = _mm_xor_si128(keys[12],tweaks[4][1]);
	n_tmp[1] = _mm_aesenc_si128(n_tmp[1],tmp);
	tmp = _mm_xor_si128(keys[12],tweaks[4][2]);
	n_tmp[2] = _mm_aesenc_si128(n_tmp[2],tmp);
	tmp = _mm_xor_si128(keys[12],tweaks[4][3]);
	n_tmp[3] = _mm_aesenc_si128(n_tmp[3],tmp);
	tmp = _mm_xor_si128(keys[12],tweaks[4][4]);
	n_tmp[4] = _mm_aesenc_si128(n_tmp[4],tmp);
	tmp = _mm_xor_si128(keys[12],tweaks[4][5]);
	n_tmp[5] = _mm_aesenc_si128(n_tmp[5],tmp);
	tmp = _mm_xor_si128(keys[12],tweaks[4][6]);
	n_tmp[6] = _mm_aesenc_si128(n_tmp[6],tmp);
	tmp = _mm_xor_si128(keys[12],tweaks[4][7]);
	n_tmp[7] = _mm_aesenc_si128(n_tmp[7],tmp);
	
	
	tmp = _mm_xor_si128(keys[13],tweaks[5][0]);
	n_tmp[0] = _mm_aesenc_si128(n_tmp[0],tmp);
	tmp = _mm_xor_si128(keys[13],tweaks[5][1]);
	n_tmp[1] = _mm_aesenc_si128(n_tmp[1],tmp);
	tmp = _mm_xor_si128(keys[13],tweaks[5][2]);
	n_tmp[2] = _mm_aesenc_si128(n_tmp[2],tmp);
	tmp = _mm_xor_si128(keys[13],tweaks[5][3]);
	n_tmp[3] = _mm_aesenc_si128(n_tmp[3],tmp);
	tmp = _mm_xor_si128(keys[13],tweaks[5][4]);
	n_tmp[4] = _mm_aesenc_si128(n_tmp[4],tmp);
	tmp = _mm_xor_si128(keys[13],tweaks[5][5]);
	n_tmp[5] = _mm_aesenc_si128(n_tmp[5],tmp);
	tmp = _mm_xor_si128(keys[13],tweaks[5][6]);
	n_tmp[6] = _mm_aesenc_si128(n_tmp[6],tmp);
	tmp = _mm_xor_si128(keys[13],tweaks[5][7]);
	n_tmp[7] = _mm_aesenc_si128(n_tmp[7],tmp);
	
	
	tmp = _mm_xor_si128(keys[14],tweaks[6][0]);
	n_tmp[0] = _mm_aesenc_si128(n_tmp[0],tmp);
	tmp = _mm_xor_si128(keys[14],tweaks[6][1]);
	n_tmp[1] = _mm_aesenc_si128(n_tmp[1],tmp);
	tmp = _mm_xor_si128(keys[14],tweaks[6][2]);
	n_tmp[2] = _mm_aesenc_si128(n_tmp[2],tmp);
	tmp = _mm_xor_si128(keys[14],tweaks[6][3]);
	n_tmp[3] = _mm_aesenc_si128(n_tmp[3],tmp);
	tmp = _mm_xor_si128(keys[14],tweaks[6][4]);
	n_tmp[4] = _mm_aesenc_si128(n_tmp[4],tmp);
	tmp = _mm_xor_si128(keys[14],tweaks[6][5]);
	n_tmp[5] = _mm_aesenc_si128(n_tmp[5],tmp);
	tmp = _mm_xor_si128(keys[14],tweaks[6][6]);
	n_tmp[6] = _mm_aesenc_si128(n_tmp[6],tmp);
	tmp = _mm_xor_si128(keys[14],tweaks[6][7]);
	n_tmp[7] = _mm_aesenc_si128(n_tmp[7],tmp);
	
	// C = _mm_xor_si128(M, tmp); 
	
	in[0] = _mm_xor_si128(in[0],n_tmp[0]);
	in[1] = _mm_xor_si128(in[1],n_tmp[1]);
	in[2] = _mm_xor_si128(in[2],n_tmp[2]);
	in[3] = _mm_xor_si128(in[3],n_tmp[3]);
	in[4] = _mm_xor_si128(in[4],n_tmp[4]);
	in[5] = _mm_xor_si128(in[5],n_tmp[5]);
	in[6] = _mm_xor_si128(in[6],n_tmp[6]);
	in[7] = _mm_xor_si128(in[7],n_tmp[7]);
	
}*/
