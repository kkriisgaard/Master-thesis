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
	_mm_storeu_si128( (__m128i *)&c_arr[0], v );
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
	_mm_storeu_si128( (__m128i *)&c_arr[0], ver );
	_mm_storeu_si128( (__m128i *)&M_arr[0], M_star );
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

bool check_int(__m128i in)
{
	unsigned char c_arr[CRYPTO_KEYBYTES];
	_mm_storeu_si128( (__m128i *)&c_arr[0], in );
	// 	print128_asint(in);
	for(int i=0;i<CRYPTO_KEYBYTES;++i)
	{
		if(c_arr[i] != 0x00)
		{
			return false;
		}
	}
	return true;
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
        __m64 param = _mm_set_pi8(0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00);
	__m64 nonce = _mm_set_pi8(npub[7],npub[6],npub[5],npub[4],npub[3],npub[2],npub[1],npub[0]);
	
	__m128i zero_mes = _mm_setzero_si128(); 
	__m128i key = _mm_loadu_si128(k);
	
	generate_aes_key(key);
	
	int fin_cip = clen%CRYPTO_KEYBYTES; 
	int numblocks_cip = clen/CRYPTO_KEYBYTES;
	int fin_ad = adlen%CRYPTO_KEYBYTES;  
	int numblocks_ad = adlen/CRYPTO_KEYBYTES; // if |A*[a]| < 128, numblocks_ad = a-1. Otherwise, numblocks_ad = a
	bool pad_ad = (fin_ad > 0);
	bool pad_cip = (fin_cip > 0);
	
	
	// IV (and subkey) generation
	
	__m128i L = encrypt_block(zero_mes);
	__m128i L1 = _mm_xor_si128(L,mul2(L));
	__m128i L2 = _mm_xor_si128(L1,mul2(L1)); 
	unsigned char Aa[CRYPTO_KEYBYTES]; // = malloc(CRYPTO_KEYBYTES); 
	__m128i Wp,AA,Z;
	unsigned char Ai_t[CRYPTO_KEYBYTES]; // = malloc(CRYPTO_KEYBYTES);
	__m128i Ai;
	__m128i IV;
	
	
	__m128i delta = L1;
	__m128i nonceparam = _mm_set_epi64(nonce,param); // I don't honestly know how much faster it it. It's definitely prettier
	
	Wp = encrypt_block( _mm_xor_si128( nonceparam,delta )); 
	int upper = numblocks_ad-1; 
	for(int i=0;i<upper;++i) 
	{
		delta = mul2(delta);
		Ai = _mm_loadu_si128(ad+i*CRYPTO_KEYBYTES);
		AA = _mm_xor_si128( Ai,delta );
		Z = encrypt_block(AA); // TODO: Parallel
		Wp = _mm_xor_si128( Z,Wp );
		
	}
	
	if(pad_ad)
	{
		memcpy(Aa, ad+(numblocks_ad*CRYPTO_KEYBYTES), fin_ad);
		Aa[fin_ad] = 0x80;
		memset(Aa+fin_ad+1,0,CRYPTO_KEYBYTES-(fin_ad+1));
		++numblocks_ad;
		Ai = _mm_loadu_si128(Aa);
		delta = _mm_xor_si128( _mm_xor_si128( delta,mul2(delta) ) , mul2( mul2(delta) ) );  
	}
	else
	{
		Ai = _mm_loadu_si128(ad+upper*CRYPTO_KEYBYTES);
		delta = mul2(delta); 
	}
	AA = _mm_xor_si128( Ai,delta );
	Z = encrypt_block(AA);
	IV = _mm_xor_si128( Z,Wp );
	// Decryption
	
	__m128i W = IV;
	
	__m128i C,Y,X,CC,deltaC,M1,MM,M,TT,_2W; 
	__m128i M_star = zero_mes; 
	unsigned char Ci_t[CRYPTO_KEYBYTES]; // = malloc(CRYPTO_KEYBYTES);
	unsigned char m_t[CRYPTO_KEYBYTES]; // = malloc(CRYPTO_KEYBYTES);
	if(!pad_cip)
	{
		--numblocks_cip;
		fin_cip = CRYPTO_KEYBYTES;
	}
	int tags = ((clen-CRYPTO_KEYBYTES)/2048);
	numblocks_cip -= tags;
	int mf = numblocks_cip-1; // numblocks_cip = l-1 !! 
	int hi=0;
	deltaC = L2;
	delta = L;

	__m128i Wj,Wc,Wpj,T,deltaCh;
	unsigned char T_a[CRYPTO_KEYBYTES];

	__m128i Cg[8];
	int i,j;
	// upper = mf/8;
	bool n = false;
	int os = CRYPTO_KEYBYTES - fin_cip;
	
	int sin =1;
	int ij;
	int fin_encr=mf%8;
	if(!fin_encr){
		sin=0;
	}
	
	for(i=0;i<(mf-sin*8);i+=8) // i = 1..(l-1)
	{
		for(j=0;j<8;++j)
		{
			
			deltaC = mul2(deltaC); 
			if((i+j)%127==0 && i!=0)
			{
				deltaCh = deltaC;
				deltaC = mul2(deltaC);
			}
			C = _mm_loadu_si128(c+(i+j)*CRYPTO_KEYBYTES);
			Cg[j] = _mm_xor_si128(C,deltaC);
			
		}
				
		decrypt_8block2(Cg); 
		
		for(j=0;j<8;++j)
		{
			
			_2W = mul2(W);
			Y = Cg[j];
			Cg[j] = _mm_xor_si128( Y, _mm_xor_si128(W,_2W ) )  ;
			W = _mm_xor_si128( Y,W );
			if((i+j)%127==126)
			{
				Wj = W;
				n = true;
				// print128_asint(Wj);
			}
			
			if((i+j)%127==0 && i!=0)
			{
				T = _mm_loadu_si128(c+((numblocks_cip+1+hi)*CRYPTO_KEYBYTES-os));
				TT = _mm_xor_si128(deltaCh,T);
				Wpj = decrypt_block(TT);
				if(!check_int(_mm_xor_si128(Wpj,Wj) ) )
				{
					// printf("Verification went wrong in the main loop\n");
					memset(m,0,*mlen);
					return -1;
				}
				++hi;
				n = false;
			}
		}
		 			
		decrypt_8block2(Cg/*,Mg*/);
		for(j=0;j<8;++j)
		{
			
			delta = mul2(delta);
			M = _mm_xor_si128(Cg[j],delta);
			
			M_star = _mm_xor_si128(M_star,M);
			_mm_storeu_si128( (__m128i *)&m[(i+j)*CRYPTO_KEYBYTES], M );
			ij = i+j;
		}
		 
	}
	ij = ij%127;
	for(i=0;i<fin_encr;++i){
		++ij;
		deltaC = mul2(deltaC); 
		if(ij==127)
		{
			deltaCh = deltaC;
			deltaC = mul2(deltaC);
		}
		printf(" d.. %d\n",(i+mf-fin_encr)*CRYPTO_KEYBYTES);
		C = _mm_loadu_si128(c+(i+mf-fin_encr)*CRYPTO_KEYBYTES);
		
		C = _mm_xor_si128(C,deltaC);
		
		C = decrypt_block(C);
		
		_2W = mul2(W);
		Y = C;
		C = _mm_xor_si128( Y, _mm_xor_si128(W,_2W ) )  ;
		W = _mm_xor_si128( Y,W );
		if(ij==126)
		{
			Wj = W;
			n = true;
		}
		if(ij==127)
		{
			T = _mm_loadu_si128(c+((numblocks_cip+1+hi)*CRYPTO_KEYBYTES-os));
			TT = _mm_xor_si128(deltaCh,T);
			Wpj = decrypt_block(TT);
			if(!check_int(_mm_xor_si128(Wpj,Wj) ) )
			{
				printf("Verification went wrong in the final loop\n");
				// memset(m,0,*mlen);
				return -1;
			}
			++hi;
			n = false;
		}
		
		C = decrypt_block(C);
		printf("C = ");print128_asint(C);
		delta = mul2(delta);
		M = _mm_xor_si128(C,delta);
		M_star = _mm_xor_si128(M_star,M);
		_mm_storeu_si128( (__m128i *)&m[(i+mf-fin_encr)*CRYPTO_KEYBYTES], M );
		
	}
	
	
	// i = l
	
	C = _mm_loadu_si128(c+mf*CRYPTO_KEYBYTES);
		
	__m128i _2delta = mul2(delta); 
	delta = _mm_xor_si128(_mm_xor_si128(delta ,_2delta),mul2(_2delta));
	if(pad_cip) // Assumption: delta_m independent from h
	{
		_2delta = mul2(delta);
		delta = _mm_xor_si128(_mm_xor_si128(delta ,_2delta),mul2(_2delta));
	}
	__m128i _2deltaC;
	
	if(n) // Wj hanging - hi = h-1 
	{
		deltaC = mul2(deltaC); // deltaC[l+h-1]
		T = _mm_loadu_si128(c+((numblocks_cip+1+hi)*CRYPTO_KEYBYTES-os));
		TT = _mm_xor_si128(deltaC,T);
		Wpj = decrypt_block(TT);
		if(!check_int(_mm_xor_si128(Wpj,Wj) ) )
		{
			// printf("Fails spec. check\n");
			memset(m,0,*mlen);
			return -1;
		}
		++hi;
		n = false;
		
	}
	
	if((mf)%127 == 126) // final regular iteration with Wj generation - hi = h - 1 
	{
		deltaC = mul2(deltaC); 
		CC = _mm_xor_si128(C,deltaC);
		Y = decrypt_block(CC);
		// print128_asint(W);
		_2W = mul2(W);
		X = _mm_xor_si128( Y, _mm_xor_si128(W,_2W ) )  ;
		W = _mm_xor_si128( Y,W ); 
		Wj = W;
		MM = decrypt_block(X);
		M = _mm_xor_si128(MM,delta);
		M1 = M;
		
		_2deltaC = mul2(deltaC); 
		deltaC = _mm_xor_si128(_mm_xor_si128(deltaC ,_2deltaC),mul2(_2deltaC));
		if(pad_cip) 
		{
			_2deltaC = mul2(deltaC);
			deltaC = _mm_xor_si128(_mm_xor_si128(deltaC ,_2deltaC),mul2(_2deltaC));
		}
		
	}
	else // General hi = h.
	{
		_2deltaC = mul2(deltaC);  // deltaC[l+h]
		deltaC = _mm_xor_si128(_mm_xor_si128(deltaC ,_2deltaC),mul2(_2deltaC));
		if(pad_cip) 
		{
			_2deltaC = mul2(deltaC);
			deltaC = _mm_xor_si128(_mm_xor_si128(deltaC ,_2deltaC),mul2(_2deltaC));
		}
		
		CC = _mm_xor_si128(C,deltaC);
		Y = decrypt_block(CC);
	
		_2W = mul2(W);
		X = _mm_xor_si128( Y, _mm_xor_si128(W,_2W ) );
		W = _mm_xor_si128( Y,W ); 
		
		MM = decrypt_block(X);
		M = _mm_xor_si128(MM,delta);
		M1 = M;
	}
	
			
	
	// print128_aschar(M);
	M_star = _mm_xor_si128(M_star,M);
	_mm_storeu_si128( (__m128i *)&m_t[0], M_star ); // Store straight 
	// print128_asint(M_star); 
	memcpy(m+mf*CRYPTO_KEYBYTES,m_t,fin_cip);
	

	
	// Verification and i = l+1
	
	__m128i MM1,Cv,ver,C1;
	delta = mul2(delta);
	
	deltaC = mul2(deltaC); 
	
	if((mf)%127 == 126) // Final int tag check 
	{
		T = _mm_loadu_si128(c+(numblocks_cip+1+hi)*CRYPTO_KEYBYTES-os);
		TT = _mm_xor_si128(deltaC,T);
		Wpj = decrypt_block(TT);
		if(!check_int(_mm_xor_si128(Wpj,Wj) ) )
		{
			memset(m,0,*mlen);
			return -1;
		}
		++hi;
		deltaC = mul2(deltaC); 
	}
	
	
	
	bool good = false;
	MM1 = _mm_xor_si128(delta,M1);
	
	X = encrypt_block(MM1);
	_2W = mul2(W);
	Y = _mm_xor_si128( X,  _mm_xor_si128(W,_2W) ); 
	W = _mm_xor_si128( X,  _2W ); 
	CC = encrypt_block(Y);
	Cv = _mm_xor_si128(CC,deltaC);
	// print128_asint(Cv);
	C1 = _mm_loadu_si128(c+numblocks_cip*CRYPTO_KEYBYTES);
	// print128_asint(C1);
	
	ver = _mm_xor_si128(C1,Cv);
	if(!pad_cip)
	{
		good = check_zero(ver);
	}
	else
	{
		good = check_pad(ver,M_star,fin_cip);
	}
	if(!good)
	{
		// printf("Oh shit!\n");
		// memset(m,0,*mlen); // We don't want a plaintext bouncing around memory
		return -1;
	}
	
	*mlen = clen - (1+tags)*CRYPTO_KEYBYTES;
	return 0;
}

