#include <stdio.h>
#include "api.h"
#include "emmintrin.h"
#include "wmmintrin.h"
#include "tmmintrin.h"
#include "crypto_aead.h"
#include "auxfuncs.h"
#include "debugfuncs.h"

const unsigned char rcon2[17] = {0x2f,0x5e,0xbc,0x63,0xc6,0x97,0x35,0x6a,0xd4,0xb3,0x7d,0xfa,0xef,0xc5,0x91,0x39,0x72};

void generate_keys(__m128i key, __m128i* keys) 
{
	__m128i h = _mm_set_epi8( 7,0,13,10, 11,4,1,14, 15,8,5,2, 3,12,9,6 );
	__m128i RC = _mm_set_epi8(0x01,0x02,0x04,0x08,rcon2[0],rcon2[0],rcon2[0],rcon2[0],0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);
	keys[0] = _mm_xor_si128(RC,key);
	// keys[15] = keys[0];
	int i;
	for(i=1;i<=14;++i)
	{
		key = _mm_shuffle_epi8(key,h);
		key = LFSR22(key);
		RC = _mm_set_epi8(0x01,0x02,0x04,0x08,rcon2[i],rcon2[i],rcon2[i],rcon2[i],0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);
		keys[i] = _mm_xor_si128(RC,key);
		// keys[i+15] = keys[i];
	}
}

int crypto_aead_decrypt(
       unsigned char *m,unsigned long long *mlen, 
       unsigned char *nsec,
       const unsigned char *c,unsigned long long clen,
       const unsigned char *ad,unsigned long long adlen,
       const unsigned char *npub,
       const unsigned char *k
     )
{
	unsigned char tweak[CRYPTO_KEYBYTES] = "What is a tweak?";
	__m128i keys[15];
	__m128i key = _mm_loadu_si128(k);
	generate_keys(key,keys);
	
	__m128i auth = _mm_setzero_si128();
	
	unsigned long long numblocks_ad = adlen/CRYPTO_KEYBYTES;
	unsigned long long numblocks_cip = clen/CRYPTO_KEYBYTES;
	int fin_ad = adlen%CRYPTO_KEYBYTES;
	int fin_cip = clen%CRYPTO_KEYBYTES;
	unsigned long long i;
	
	
	__m128i ad_reg = _mm_set_epi8(0x20,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0  ,0x0,0x0,0x0,0x0);
	// __m128i ad_fin = _mm_set_epi8(0x60,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0  ,0x0,0x0,0x0,0x0);
	__m128i MSB1    = _mm_set_epi8(0x80,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0  ,0x0,0x0,0x0,0x0);
	__m128i tag_fin =  _mm_set_epi8(0x40,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0  ,0x0,0x0,0x0,0x0);
	/*const unsigned long long ad_reg = 0x2000000000000000;*/
	const unsigned long long ad_fin = 0x6000000000000000;
	// const unsigned long long tag_fin = 0x4000000000000000; 
	const unsigned long long zero = 0; /* what a surprise. */
	__m128i zero_128 = _mm_setzero_si128();
	__m128i nonce = _mm_set_epi8(0x00,npub[14],npub[13],npub[12],npub[11],npub[10],npub[9],npub[8],npub[7],npub[6],npub[5],npub[4],npub[3],npub[2],npub[1],npub[0]);
	__m128i h = _mm_set_epi8( 7,0,13,10, 11,4,1,14, 15,8,5,2, 3,12,9,6 );
	__m128i one = _mm_set_epi8(0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1);
	__m128i prop    = _mm_set_epi8(0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x80,0x0,0x0,0x0  ,0x0,0x0,0x0,0x0);
	__m128i prop_mask = _mm_set_epi8(8,9,10,11,12,13,14,15,  0,1,2,3,4,5,6,7  );
	__m128i A,idx,M,C,tmp;
	unsigned char A_star[CRYPTO_KEYBYTES];
	unsigned char M_star[CRYPTO_KEYBYTES];
	unsigned char tmp_ar[CRYPTO_KEYBYTES];
	unsigned long long nbm = numblocks_cip-1;
	int z = 0;
	
	__m128i ctr;
	__m128i tweaks[8],z_s[8][4],eight[8],xx[4],mes[4],N[4],tweaks_sin[8];
	
	
	
	// Initialization
	
	tmp = one; 
	 /*Good */
	for(i=0;i<8;++i)
	{
		z_s[i][0] = _mm_add_epi8(tmp, zero_128  );
		z_s[i][1] = _mm_add_epi8(tmp, z_s[i][0] );
		z_s[i][2] = _mm_add_epi8(tmp, z_s[i][1] );
		tmp = _mm_shuffle_epi8(tmp,h);
	} // */
	
	
	tweaks[0] = zero_128; 
	tweaks[1] = zero_128;
	tweaks[2] = zero_128;
	tweaks[3] = zero_128;
	tweaks[4] = zero_128;
	tweaks[5] = zero_128;
	tweaks[6] = zero_128;
	tweaks[7] = zero_128; // */
	
	eight[0] = _mm_set_epi8(0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,4); 
	eight[1] = _mm_shuffle_epi8(eight[0],h); 		     
	eight[2] = _mm_shuffle_epi8(eight[1],h);
	eight[3] = _mm_shuffle_epi8(eight[2],h);
	eight[4] = _mm_shuffle_epi8(eight[3],h);
	eight[5] = _mm_shuffle_epi8(eight[4],h);
	eight[6] = _mm_shuffle_epi8(eight[5],h);
	eight[7] = _mm_shuffle_epi8(eight[6],h); // */
	
	// Decryption
	__m128i tag = _mm_loadu_si128(c+nbm*CRYPTO_KEYBYTES+fin_cip);
	__m128i tag1 = _mm_or_si128(tag,MSB1); // This truncating is silly.
	
	
	for(i=0;i<7;++i)
	{
		keys[i] = _mm_xor_si128(keys[i],tag1);
		keys[i+8] = _mm_xor_si128(keys[i+8],tag1);
		tag1 = _mm_shuffle_epi8(tag1,h);
	}
	keys[7] = _mm_xor_si128(keys[7],tag1); /*Getting rid of a shuffle and pipelining some xor's*/
	tag1 = _mm_shuffle_epi8(tag1,h);
	
	
	*mlen = clen-CRYPTO_KEYBYTES;
	
	// Decryption
	
	// __m128i zero_128 = _mm_setzero_si128();
	idx = zero_128;
	
	z = 0;
	int fin_encr = nbm%4;
	int sin = 1;
	int t_off = 0;
	if(!fin_encr){
		sin = 0;
	}
	
	for(i=0;i<(nbm-4*sin);i+=4)
	{
		tmp = _mm_xor_si128(tweaks[0] ,keys[0]);
		
		N[0] = _mm_xor_si128(nonce,tmp );
		N[1] = _mm_xor_si128(N[0],z_s[0][0] ); /* N[1] = _mm_xor_si128(nonce,_mm_xor_si128(tmp,z_s[0][1]) ); */
		N[2] = _mm_xor_si128(N[0],z_s[0][1] );  /* All second indeces in z_s decremented by 1 from working version */
		N[3] = _mm_xor_si128(N[0],z_s[0][2] ); /* N -> N */ 
			
			tmp = _mm_xor_si128(keys[1],tweaks[1]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[1][0]); /* Previously inlined in enc's. Gives minor (0.03 cpb) increase when running xors by themselves.*/
			xx[1] = _mm_xor_si128(tmp,z_s[1][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[1][2]);
			
			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[2],tweaks[2]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[2][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[2][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[2][2]);
			
			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[3],tweaks[3]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[3][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[3][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[3][2]);
			
			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[4],tweaks[4]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[4][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[4][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[4][2]);
			
			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[5],tweaks[5]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[5][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[5][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[5][2]);
			
			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[6],tweaks[6]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[6][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[6][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[6][2]);
			
			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[7],tweaks[7]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[7][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[7][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[7][2]);
			
			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[8],tweaks[0]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[0][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[0][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[0][2]);
			
			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[9],tweaks[1]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[1][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[1][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[1][2]);
			
			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[10],tweaks[2]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[2][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[2][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[2][2]);
			
			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[11],tweaks[3]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[3][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[3][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[3][2]);
			
			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[12],tweaks[4]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[4][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[4][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[4][2]);
			
			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[13],tweaks[5]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[5][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[5][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[5][2]);
			
			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[14],tweaks[6]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[6][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[6][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[6][2]);
			
			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
		
		
		
		/* Can't do shit about the next three blocks */
		
		mes[0] = _mm_loadu_si128(c+(i  )*CRYPTO_KEYBYTES); 
		mes[1] = _mm_loadu_si128(c+(i+1)*CRYPTO_KEYBYTES);
		mes[2] = _mm_loadu_si128(c+(i+2)*CRYPTO_KEYBYTES);
		mes[3] = _mm_loadu_si128(c+(i+3)*CRYPTO_KEYBYTES);
		
		mes[0] = _mm_xor_si128(N[0],mes[0]); 
		mes[1] = _mm_xor_si128(N[1],mes[1]);
		mes[2] = _mm_xor_si128(N[2],mes[2]);
		mes[3] = _mm_xor_si128(N[3],mes[3]);
		
		_mm_storeu_si128( (__m128i *)&m[(i  )*CRYPTO_KEYBYTES], mes[0] ); 
		_mm_storeu_si128( (__m128i *)&m[(i+1)*CRYPTO_KEYBYTES], mes[1] ); 
		_mm_storeu_si128( (__m128i *)&m[(i+2)*CRYPTO_KEYBYTES], mes[2] ); 
		_mm_storeu_si128( (__m128i *)&m[(i+3)*CRYPTO_KEYBYTES], mes[3] ); 
		
		/* End of sticking blocks */
		
			tweaks[0] = _mm_add_epi64(tweaks[0],eight[0]);
			tweaks[1] = _mm_add_epi64(tweaks[1],eight[1]);
			tweaks[2] = _mm_add_epi64(tweaks[2],eight[2]);
			tweaks[3] = _mm_add_epi64(tweaks[3],eight[3]);
			tweaks[4] = _mm_add_epi64(tweaks[4],eight[4]);
			tweaks[5] = _mm_add_epi64(tweaks[5],eight[5]);
			tweaks[6] = _mm_add_epi64(tweaks[6],eight[6]);
			tweaks[7] = _mm_add_epi64(tweaks[7],eight[7]);	
	}
	ctr = zero_128;
	for(i=0;i<fin_encr;++i){
		if(t_off>0){ctr = z_s[0][t_off-1];}
		tmp = _mm_xor_si128(keys[0],_mm_xor_si128(ctr,tweaks[0]) );
		
		N[0] = _mm_xor_si128(tmp,nonce);
		mes[0] = _mm_loadu_si128(c+(i+nbm-fin_encr)*CRYPTO_KEYBYTES);
				
		tweaks_sin[0] = _mm_xor_si128(tweaks[0],ctr);
		tweaks_sin[1] = _mm_shuffle_epi8(tweaks_sin[0],h);
		tweaks_sin[2] = _mm_shuffle_epi8(tweaks_sin[1],h);
		tweaks_sin[3] = _mm_shuffle_epi8(tweaks_sin[2],h);
		tweaks_sin[4] = _mm_shuffle_epi8(tweaks_sin[3],h);
		tweaks_sin[5] = _mm_shuffle_epi8(tweaks_sin[4],h);
		tweaks_sin[6] = _mm_shuffle_epi8(tweaks_sin[5],h);
		tweaks_sin[7] = _mm_shuffle_epi8(tweaks_sin[6],h);
	
		xx[0] = _mm_xor_si128(keys[1],tweaks_sin[1]);
		xx[1] = _mm_xor_si128(keys[2],tweaks_sin[2]);
		xx[2] = _mm_xor_si128(keys[3],tweaks_sin[3]);
		N[0] = _mm_aesenc_si128(N[0],xx[0]);
		N[0] = _mm_aesenc_si128(N[0],xx[1]);
		N[0] = _mm_aesenc_si128(N[0],xx[2]);
	
		xx[0] = _mm_xor_si128(keys[4],tweaks_sin[4]);
		xx[1] = _mm_xor_si128(keys[5],tweaks_sin[5]);
		xx[2] = _mm_xor_si128(keys[6],tweaks_sin[6]);
		N[0] = _mm_aesenc_si128(N[0],xx[0]);
		N[0] = _mm_aesenc_si128(N[0],xx[1]);
		N[0] = _mm_aesenc_si128(N[0],xx[2]);
	
		xx[0] = _mm_xor_si128(keys[7],tweaks_sin[7]);
		xx[1] = _mm_xor_si128(keys[8],tweaks_sin[0]);
		xx[2] = _mm_xor_si128(keys[9],tweaks_sin[1]);
		N[0] = _mm_aesenc_si128(N[0],xx[0]);
		N[0] = _mm_aesenc_si128(N[0],xx[1]);
		N[0] = _mm_aesenc_si128(N[0],xx[2]);
	
		xx[0] = _mm_xor_si128(keys[10],tweaks_sin[2]);
		xx[1] = _mm_xor_si128(keys[11],tweaks_sin[3]);
		xx[2] = _mm_xor_si128(keys[12],tweaks_sin[4]);
		N[0] = _mm_aesenc_si128(N[0],xx[0]);
		N[0] = _mm_aesenc_si128(N[0],xx[1]);
		N[0] = _mm_aesenc_si128(N[0],xx[2]);
	
		xx[0] = _mm_xor_si128(keys[13],tweaks_sin[5]);
		xx[1] = _mm_xor_si128(keys[14],tweaks_sin[6]);
		N[0] = _mm_aesenc_si128(N[0],xx[0]);
		N[0] = _mm_aesenc_si128(N[0],xx[1]);
		++t_off;
		
		mes[0] = _mm_xor_si128(N[0],mes[0]);
		_mm_storeu_si128( (__m128i *)&m[(i+nbm-fin_encr)*CRYPTO_KEYBYTES], mes[0] ); 
	}
	
	if(fin_cip) 
	{
		memcpy(M_star,c+nbm*CRYPTO_KEYBYTES,fin_cip); 
		
		M = _mm_loadu_si128(M_star);
		
		if(t_off>0){ctr = z_s[0][t_off-1];}
		idx = _mm_xor_si128(ctr,tweaks[0]);
		
		C = _mm_xor_si128(M,encrypt_block(nonce,idx,keys ) );
		_mm_storeu_si128( (__m128i *)&tmp_ar[0], C );
		memcpy(m+nbm*CRYPTO_KEYBYTES,tmp_ar,fin_cip); 
	}
	
	
	// Associated data
	
	tag1 = _mm_or_si128(tag,MSB1); /* Untagging the nonce */
	
	for(i=0;i<7;++i)
	{
		keys[i] = _mm_xor_si128(keys[i],tag1);
		keys[i+8] = _mm_xor_si128(keys[i+8],tag1);
		tag1 = _mm_shuffle_epi8(tag1,h);
	} // */ 
	
	keys[7] = _mm_xor_si128(keys[7],tag1); /*Getting rid of a shuffle and pipelining some xor's*/
	tag1 = _mm_shuffle_epi8(tag1,h);
	
	
	tweaks[0] = ad_reg; /*Tweak reset*/
	tweaks[1] = _mm_shuffle_epi8(tweaks[0],h);
	tweaks[2] = _mm_shuffle_epi8(tweaks[1],h);
	tweaks[3] = _mm_shuffle_epi8(tweaks[2],h);
	tweaks[4] = _mm_shuffle_epi8(tweaks[3],h);
	tweaks[5] = _mm_shuffle_epi8(tweaks[4],h);
	tweaks[6] = _mm_shuffle_epi8(tweaks[5],h);
	tweaks[7] = _mm_shuffle_epi8(tweaks[6],h); 
	
	/* Old loop in untitled 1*/
	
	fin_encr = numblocks_ad%4;
	sin = 1;
	if(!fin_encr){
		sin = 0;
	}
	z = 0;
	// printf("%d\n",numblocks_ad);
	for(i=0;i<numblocks_ad-(4*sin);i+=4)
	{
		mes[0] = _mm_loadu_si128(ad+(i  )*CRYPTO_KEYBYTES);
		mes[1] = _mm_loadu_si128(ad+(i+1)*CRYPTO_KEYBYTES);
		mes[2] = _mm_loadu_si128(ad+(i+2)*CRYPTO_KEYBYTES);
		mes[3] = _mm_loadu_si128(ad+(i+3)*CRYPTO_KEYBYTES);
				
		tmp = _mm_xor_si128(keys[0],tweaks[0]);  
		
		mes[0] = _mm_xor_si128(mes[0],tmp);
		mes[1] = _mm_xor_si128(mes[1],_mm_xor_si128(tmp,z_s[0][0]) ); // index 1..7
		mes[2] = _mm_xor_si128(mes[2],_mm_xor_si128(tmp,z_s[0][1]) );  
		mes[3] = _mm_xor_si128(mes[3],_mm_xor_si128(tmp,z_s[0][2]) );		
		
			tmp = _mm_xor_si128(keys[1],tweaks[1]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[1][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[1][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[1][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[2],tweaks[2]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[2][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[2][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[2][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[3],tweaks[3]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[3][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[3][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[3][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[4],tweaks[4]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[4][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[4][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[4][2]);

			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[5],tweaks[5]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[5][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[5][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[5][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[6],tweaks[6]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[6][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[6][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[6][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[7],tweaks[7]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[7][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[7][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[7][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[8],tweaks[0]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[0][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[0][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[0][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );

			tmp = _mm_xor_si128(keys[9],tweaks[1]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[1][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[1][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[1][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[10],tweaks[2]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[2][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[2][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[2][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[11],tweaks[3]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[3][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[3][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[3][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[12],tweaks[4]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[4][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[4][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[4][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[13],tweaks[5]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[5][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[5][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[5][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );

			tmp = _mm_xor_si128(keys[14],tweaks[6]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[6][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[6][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[6][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );// */
			
		
			tweaks[0] = _mm_add_epi64(tweaks[0],eight[0]);
			tweaks[1] = _mm_add_epi64(tweaks[1],eight[1]);
			tweaks[2] = _mm_add_epi64(tweaks[2],eight[2]);
			tweaks[3] = _mm_add_epi64(tweaks[3],eight[3]);
			tweaks[4] = _mm_add_epi64(tweaks[4],eight[4]);
			tweaks[5] = _mm_add_epi64(tweaks[5],eight[5]);
			tweaks[6] = _mm_add_epi64(tweaks[6],eight[6]);
			tweaks[7] = _mm_add_epi64(tweaks[7],eight[7]);
	
	
		auth = mes[0]^mes[1]^mes[2]^mes[3]^auth;
		// print128_asint(auth);
	}
	ctr = zero_128;
	for(i=0;i<fin_encr;++i){
	
		if(t_off>0){
			ctr = z_s[0][t_off-1];
		}
		
		tmp = _mm_xor_si128(keys[0],_mm_xor_si128(ctr,tweaks[0]) );
		mes[0] = _mm_loadu_si128(ad+(i+numblocks_ad-fin_encr)*CRYPTO_KEYBYTES);
		mes[0] = _mm_xor_si128(tmp,mes[0]);

		

		tweaks_sin[0] = _mm_xor_si128(ctr,tweaks[0]);
		tweaks_sin[1] = _mm_shuffle_epi8(tweaks_sin[0],h);
		tweaks_sin[2] = _mm_shuffle_epi8(tweaks_sin[1],h);
		tweaks_sin[3] = _mm_shuffle_epi8(tweaks_sin[2],h);
		tweaks_sin[4] = _mm_shuffle_epi8(tweaks_sin[3],h);
		tweaks_sin[5] = _mm_shuffle_epi8(tweaks_sin[4],h);
		tweaks_sin[6] = _mm_shuffle_epi8(tweaks_sin[5],h);
		tweaks_sin[7] = _mm_shuffle_epi8(tweaks_sin[6],h);
	
		xx[0] = _mm_xor_si128(keys[1],tweaks_sin[1]);
		xx[1] = _mm_xor_si128(keys[2],tweaks_sin[2]);
		xx[2] = _mm_xor_si128(keys[3],tweaks_sin[3]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[0]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[1]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[2]);
	
		xx[0] = _mm_xor_si128(keys[4],tweaks_sin[4]);
		xx[1] = _mm_xor_si128(keys[5],tweaks_sin[5]);
		xx[2] = _mm_xor_si128(keys[6],tweaks_sin[6]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[0]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[1]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[2]);
	
		xx[0] = _mm_xor_si128(keys[7],tweaks_sin[7]);
		xx[1] = _mm_xor_si128(keys[8],tweaks_sin[0]);
		xx[2] = _mm_xor_si128(keys[9],tweaks_sin[1]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[0]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[1]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[2]);
	
		xx[0] = _mm_xor_si128(keys[10],tweaks_sin[2]);
		xx[1] = _mm_xor_si128(keys[11],tweaks_sin[3]);
		xx[2] = _mm_xor_si128(keys[12],tweaks_sin[4]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[0]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[1]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[2]);
	
		xx[0] = _mm_xor_si128(keys[13],tweaks_sin[5]);
		xx[1] = _mm_xor_si128(keys[14],tweaks_sin[6]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[0]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[1]);
		++t_off;
		
		auth = _mm_xor_si128(auth,mes[0]);
	}
	
	if(fin_ad)
	{
		memcpy(A_star,ad+numblocks_ad*CRYPTO_KEYBYTES,fin_ad);
		A_star[fin_ad] = 0x80;
		memset(A_star+fin_ad+1,0,CRYPTO_KEYBYTES-(fin_ad+1));
		A = _mm_loadu_si128(A_star);
		if(t_off>0){ctr = z_s[0][t_off-1];}
		idx = _mm_xor_si128(tag_fin,_mm_xor_si128(ctr,tweaks[0]));
		// idx = _mm_set_epi64x(ad_fin,numblocks_ad);
		tmp = encrypt_block(A,idx,keys);
		auth = _mm_xor_si128(auth,tmp);
	}
	
	// print128_asint(auth);
	
	///* Tag for decr nicked from here */
	
	
	
	// Verification
	
	unsigned long long j;// int z;
	
	__m128i tagp = zero_128;
		
	tweaks[0] = zero_128; 
	tweaks[1] = zero_128;
	tweaks[2] = zero_128;
	tweaks[3] = zero_128;
	tweaks[4] = zero_128;
	tweaks[5] = zero_128;
	tweaks[6] = zero_128;
	tweaks[7] = zero_128; 
	
	idx = zero_128;
	z=0;
	t_off=0;
	fin_encr = nbm%4;
	sin = 1;
	if(!fin_encr){
		sin = 0;
	}
	tagp = auth;
	
	for(i=0;i<(nbm-4*sin);i+=4) 
	{
		mes[0] = _mm_loadu_si128(m+(i  )*CRYPTO_KEYBYTES); 
		mes[1] = _mm_loadu_si128(m+(i+1)*CRYPTO_KEYBYTES);
		mes[2] = _mm_loadu_si128(m+(i+2)*CRYPTO_KEYBYTES);
		mes[3] = _mm_loadu_si128(m+(i+3)*CRYPTO_KEYBYTES);
		
		// ENCR_8_BLOCKS(mes);
		
		tmp = _mm_xor_si128(keys[0],tweaks[0]);
		
		mes[0] = _mm_xor_si128(mes[0],tmp);
		mes[1] = _mm_xor_si128(mes[1],_mm_xor_si128(tmp,z_s[0][0]) ); // index 1..7
		mes[2] = _mm_xor_si128(mes[2],_mm_xor_si128(tmp,z_s[0][1]) );  
		mes[3] = _mm_xor_si128(mes[3],_mm_xor_si128(tmp,z_s[0][2]) );
	
		
			tmp = _mm_xor_si128(keys[1],tweaks[1]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[1][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[1][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[1][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[2],tweaks[2]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[2][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[2][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[2][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[3],tweaks[3]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[3][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[3][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[3][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[4],tweaks[4]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[4][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[4][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[4][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[5],tweaks[5]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[5][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[5][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[5][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[6],tweaks[6]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[6][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[6][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[6][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[7],tweaks[7]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[7][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[7][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[7][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[8],tweaks[0]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[0][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[0][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[0][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[9],tweaks[1]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[1][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[1][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[1][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[10],tweaks[2]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[2][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[2][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[2][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[11],tweaks[3]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[3][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[3][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[3][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[12],tweaks[4]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[4][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[4][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[4][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			
			tmp = _mm_xor_si128(keys[13],tweaks[5]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[5][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[5][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[5][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );

			tmp = _mm_xor_si128(keys[14],tweaks[6]);
			
			xx[0] = _mm_xor_si128(tmp,z_s[6][0]); 
			xx[1] = _mm_xor_si128(tmp,z_s[6][1]); 
			xx[2] = _mm_xor_si128(tmp,z_s[6][2]);
			
			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
		
			tweaks[0] = _mm_add_epi64(tweaks[0],eight[0]);
			tweaks[1] = _mm_add_epi64(tweaks[1],eight[1]);
			tweaks[2] = _mm_add_epi64(tweaks[2],eight[2]);
			tweaks[3] = _mm_add_epi64(tweaks[3],eight[3]);
			tweaks[4] = _mm_add_epi64(tweaks[4],eight[4]);
			tweaks[5] = _mm_add_epi64(tweaks[5],eight[5]);
			tweaks[6] = _mm_add_epi64(tweaks[6],eight[6]);
			tweaks[7] = _mm_add_epi64(tweaks[7],eight[7]);
		
		
		tagp = tagp^mes[0]^mes[1]^mes[2]^mes[3]; // ^mes[4]^mes[5]^mes[6]^mes[7]; 
		// print128_asint(tagp);

	}
	
	ctr = zero_128;
	for(i=0;i<fin_encr;++i){
		
		if(t_off>0){ctr = z_s[0][t_off-1];}
		
		tmp = _mm_xor_si128(keys[0],_mm_xor_si128(ctr,tweaks[0]) );
		mes[0] = _mm_loadu_si128(m+(i+nbm-fin_encr)*CRYPTO_KEYBYTES);
		mes[0] = _mm_xor_si128(tmp,mes[0]);
		
		

		tweaks_sin[0] = _mm_xor_si128(ctr,tweaks[0]);
		tweaks_sin[1] = _mm_shuffle_epi8(tweaks_sin[0],h);
		tweaks_sin[2] = _mm_shuffle_epi8(tweaks_sin[1],h);
		tweaks_sin[3] = _mm_shuffle_epi8(tweaks_sin[2],h);
		tweaks_sin[4] = _mm_shuffle_epi8(tweaks_sin[3],h);
		tweaks_sin[5] = _mm_shuffle_epi8(tweaks_sin[4],h);
		tweaks_sin[6] = _mm_shuffle_epi8(tweaks_sin[5],h);
		tweaks_sin[7] = _mm_shuffle_epi8(tweaks_sin[6],h);
	
		xx[0] = _mm_xor_si128(keys[1],tweaks_sin[1]);
		xx[1] = _mm_xor_si128(keys[2],tweaks_sin[2]);
		xx[2] = _mm_xor_si128(keys[3],tweaks_sin[3]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[0]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[1]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[2]);
	
		xx[0] = _mm_xor_si128(keys[4],tweaks_sin[4]);
		xx[1] = _mm_xor_si128(keys[5],tweaks_sin[5]);
		xx[2] = _mm_xor_si128(keys[6],tweaks_sin[6]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[0]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[1]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[2]);
	
		xx[0] = _mm_xor_si128(keys[7],tweaks_sin[7]);
		xx[1] = _mm_xor_si128(keys[8],tweaks_sin[0]);
		xx[2] = _mm_xor_si128(keys[9],tweaks_sin[1]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[0]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[1]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[2]);
	
		xx[0] = _mm_xor_si128(keys[10],tweaks_sin[2]);
		xx[1] = _mm_xor_si128(keys[11],tweaks_sin[3]);
		xx[2] = _mm_xor_si128(keys[12],tweaks_sin[4]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[0]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[1]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[2]);
	
		xx[0] = _mm_xor_si128(keys[13],tweaks_sin[5]);
		xx[1] = _mm_xor_si128(keys[14],tweaks_sin[6]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[0]);
		mes[0] = _mm_aesenc_si128(mes[0],xx[1]);
		++t_off;
		
		tagp = _mm_xor_si128(tagp,mes[0]);
	}
	if(fin_cip)
	{
		memcpy(M_star,m+nbm*CRYPTO_KEYBYTES,fin_cip);
		M_star[fin_cip] = 0x80;
		memset(M_star+fin_cip+1,0,CRYPTO_KEYBYTES-(fin_cip+1));
		M = _mm_loadu_si128(M_star); 
		if(t_off>0){ctr = z_s[0][t_off-1];}
		idx = _mm_xor_si128(tag_fin,_mm_xor_si128(ctr,tweaks[0]) );
		
		tmp = encrypt_block(M,idx,keys); 
		
		tagp = _mm_xor_si128(tagp,tmp);
		
	}// 
	
	nonce = _mm_set_epi8(0x10,npub[14],npub[13],npub[12],npub[11],npub[10],npub[9],npub[8],npub[7],npub[6],npub[5],npub[4],npub[3],npub[2],npub[1],npub[0]);
	
	// print128_asint(tagp);
	tagp = encrypt_block(tagp,nonce,keys); // 
	
	__m128i ver = _mm_xor_si128(tag,tagp);
	unsigned char v[CRYPTO_KEYBYTES];
	_mm_storeu_si128( (__m128i *)&v[0], ver );
	
	for(i=0;i<CRYPTO_KEYBYTES;++i)
	{
		if(v[i]!=0) // Maybe there's a beter way to do this.
		{
			goto EXIT_FAIL; /* I'm not sorry at all*/
		}
	}
	
	return 0;
	
	EXIT_FAIL:
	return -1;
}
