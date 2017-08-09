#include <stdio.h>
#include "api.h"
#include "emmintrin.h"
#include "wmmintrin.h"
#include "crypto_aead.h"
#include "auxfuncs.h"
#include <stdbool.h>

// const unsigned char zero[CRYPTO_KEYBYTES] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// 

bool check_zero(__m128i v)
{
	unsigned char c_arr[CRYPTO_KEYBYTES];
	_mm_store_si128( (__m128i *)&c_arr[0], v );
	for(int i=0;i<CRYPTO_KEYBYTES;++i)
	{
		if(c_arr[i] != 0x00)
		{
			return false;
		}
	}
	return true;
}

bool check_pad(__m128i ver, __m128i M_star,int fin)
{
	unsigned char c_arr[CRYPTO_KEYBYTES];
	unsigned char M_arr[CRYPTO_KEYBYTES];
	/*print128_asint(ver);
	print128_asint(M_star);*/
	_mm_store_si128( (__m128i *)&c_arr[0], ver );
	_mm_store_si128( (__m128i *)&M_arr[0], M_star );
	if(M_arr[fin] != 0x80)
	{
		// printf("fails 0x80\n");
		return false;
	}
	for(int i=0;i<fin;++i)
	{
		if(c_arr[i] != 0x00)
		{
			// printf("fails comparison on iteration in c_arr %d\n",i);
			return false;
		}
	}
	for(int i=fin+1;i<CRYPTO_KEYBYTES;++i)
	{
		if(M_arr[i] != 0x00)
		{
			// printf("fails star check on iteration in M_arr %d\n",i);
			return false;
		}
	}
	return true;
}

__m128i reverse_128(__m128i in)
{
	unsigned char temp[CRYPTO_KEYBYTES];
	_mm_store_si128( (__m128i *)&temp[0], in ); // store straight
	return generate_128i_char(temp); // Reverse. 
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
       const unsigned char zero[CRYPTO_KEYBYTES] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
       const unsigned char param[CRYPTO_NPUBBYTES] = {0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00};
       
	__m128i zero_mes = generate_128i_char(zero);
	__m128i key = generate_128i_char(k);
	
	generate_aes_key(key);
	
	int fin_cip = clen%CRYPTO_KEYBYTES; 
	int numblocks_cip = clen/CRYPTO_KEYBYTES;
	int fin_ad = adlen%CRYPTO_KEYBYTES; // 
	int numblocks_ad = adlen/CRYPTO_KEYBYTES; // if |A*[a]| < 128, numblocks_ad = a-1. Otherwise, numblocks_ad = a
	bool pad_ad = (fin_ad > 0);
	bool pad_cip = (fin_cip > 0);
	
	
	// IV (and subkey) generation
	
	__m128i L = encrypt_block(zero_mes);
	__m128i L1 = _mm_xor_si128(L,mul2(L));
	__m128i L2 = _mm_xor_si128(L1,mul2(L1)); 
	unsigned char *Aa = malloc(CRYPTO_KEYBYTES); 
	if(pad_ad) // TODO: Get rid of for loop - memset 
	{
		memcpy(Aa, ad+(numblocks_ad*CRYPTO_KEYBYTES), fin_ad);
		Aa[fin_ad] = 0x80;
		memset(Aa+fin_ad+1,0,CRYPTO_KEYBYTES-(fin_ad+1));
		/*for(int i=fin_ad+1;i<CRYPTO_KEYBYTES;++i)
		{
			Aa[i] = 0x00;
		}*/
		++numblocks_ad;
	}
	__m128i Wp,AA,Z;
	unsigned char *Ai_t = malloc(CRYPTO_KEYBYTES);
	__m128i Ai;
	__m128i IV;
	
	
	__m128i delta = L1;
	Wp = encrypt_block( _mm_xor_si128( conc_two_8_byte(npub,param),delta ) ); // Nasty function call
	int upper = numblocks_ad-1; 
	for(int i=0;i<upper;++i) 
	{
		delta = mul2(delta);
		memcpy(Ai_t,ad+i*CRYPTO_KEYBYTES,CRYPTO_KEYBYTES);
		Ai = generate_128i_char(Ai_t);
		AA = _mm_xor_si128( Ai,delta );
		Z = encrypt_block(AA); // TODO: Parallel
		Wp = _mm_xor_si128( Z,Wp );
	}
	
	if(pad_ad)
	{
		Ai = generate_128i_char(Aa);
		delta = _mm_xor_si128( _mm_xor_si128( delta,mul2(delta) ) , mul2( mul2(delta) ) );  
	}
	else
	{
		memcpy(Ai_t,ad+upper*CRYPTO_KEYBYTES,CRYPTO_KEYBYTES);
		Ai = generate_128i_char(Ai_t);
		delta = mul2(delta); 
	}
	AA = _mm_xor_si128( Ai,delta );
	Z = encrypt_block(AA);
	IV = _mm_xor_si128( Z,Wp );
	
	// Decryption
	
	__m128i W = IV;
	
	__m128i C,Y,X,CC,deltaC,M1,MM,M,M_stor;
	__m128i M_star = zero_mes; 
	unsigned char *Ci_t = malloc(CRYPTO_KEYBYTES);
	unsigned char *m_t = malloc(CRYPTO_KEYBYTES);
	if(!pad_cip)
	{
		--numblocks_cip;
		fin_cip = CRYPTO_KEYBYTES;
	}
	upper = numblocks_cip-1;
	deltaC = L2;
	delta = L;
	for(int i=0;i<upper;++i)
	{
		memcpy(Ci_t,c+i*CRYPTO_KEYBYTES,CRYPTO_KEYBYTES);
		
		C = generate_128i_char_dec(Ci_t);
		
		deltaC = mul2(deltaC); 
		
		
		CC = _mm_xor_si128(C,deltaC);
		
		Y = decrypt_block(CC);
		
		rho_inv(&X,Y,&W);
				
		MM = decrypt_block(X);
		delta = mul2(delta);
		
		M = _mm_xor_si128(MM,delta);
		M_star = _mm_xor_si128(M_star,M);
		M_stor = reverse_128(M);
		_mm_store_si128( (__m128i *)&m_t[0], M_stor ); // Store straight - beware
		memcpy(m+i*CRYPTO_KEYBYTES,m_t,CRYPTO_KEYBYTES);
	}
	memcpy(Ci_t,c+upper*CRYPTO_KEYBYTES,CRYPTO_KEYBYTES);
	C = generate_128i_char_dec(Ci_t);
		
	// TODO: Optimize
	__m128i _2delta = mul2(delta); // To use extra memory or extra time, that's the question
	delta = _mm_xor_si128(_mm_xor_si128(delta ,_2delta),mul2(_2delta));
	__m128i _2deltaC = mul2(deltaC);
	deltaC = _mm_xor_si128(_mm_xor_si128(deltaC ,_2deltaC),mul2(_2deltaC));
	
	if(pad_cip)
	{
		_2delta = mul2(delta);
		delta = _mm_xor_si128(_mm_xor_si128(delta ,_2delta),mul2(_2delta));
		_2deltaC = mul2(deltaC);
		deltaC = _mm_xor_si128(_mm_xor_si128(deltaC ,_2deltaC),mul2(_2deltaC));
	}
		
	CC = _mm_xor_si128(C,deltaC);
	Y = decrypt_block(CC);
	rho_inv(&X,Y,&W);
	MM = decrypt_block(X);
	M = _mm_xor_si128(MM,delta);
	M1 = M;
	
	M_star = _mm_xor_si128(M_star,M);
	M_stor = reverse_128(M_star);
	_mm_store_si128( (__m128i *)&m_t[0], M_stor ); // Store straight - beware
	memcpy(m+upper*CRYPTO_KEYBYTES,m_t,fin_cip);
	
	
	// Verification
	
	__m128i MM1,Cv,ver,C1;
	delta = mul2(delta); 
	deltaC =  mul2(deltaC);
	
	bool good = false;
	MM1 = _mm_xor_si128(delta,M1);
	
	X = encrypt_block(MM1);
	rho(X,&Y,&W);
	CC = encrypt_block(Y);
	Cv = _mm_xor_si128(CC,deltaC);
	memcpy(Ci_t,c+numblocks_cip*CRYPTO_KEYBYTES,CRYPTO_KEYBYTES);
	// Ci_t[0] = 0x00; // Test for bad verification
	C1 = generate_128i_char_dec(Ci_t);
	
	
	ver = _mm_xor_si128(C1,Cv);
	if(!pad_cip) // TODO: Fix
	{
		good = check_zero(ver);
	}
	else
	{
		good = check_pad(ver,M_stor,fin_cip);
	}
	if(!good)
	{
		// printf("Oh shit!, ");printf("also mlen = %d\n",*mlen);
		memset(m,0,*mlen); // We don't want a plaintext bouncing around memory
		return -1;
	}
	
	return 0;
}

