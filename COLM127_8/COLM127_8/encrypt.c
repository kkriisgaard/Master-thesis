#include <stdio.h>
#include "api.h"
#include "emmintrin.h"
#include "wmmintrin.h"
#include "crypto_aead.h"
#include "auxfuncs.h"
#include <stdbool.h>

// const unsigned char zero[CRYPTO_KEYBYTES] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
// const unsigned char param[CRYPTO_NPUBBYTES] = {0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00};

int crypto_aead_encrypt( // Requires plaintext of length n*8*16 + 16
       unsigned char *c,unsigned long long *clen, // c = cipher, clen = cipher length - not const, as they may change in size.
       const unsigned char *m,unsigned long long mlen,
       const unsigned char *ad,unsigned long long adlen, // 
       const unsigned char *nsec, // = param??
       const unsigned char *npub, // = nonce
       const unsigned char *k
     )
{
	// Setup
	
	__m64 param = _mm_set_pi8(0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00);
	__m64 nonce = _mm_set_pi8(npub[7],npub[6],npub[5],npub[4],npub[3],npub[2],npub[1],npub[0]);
	
	__m128i zero_mes = _mm_setzero_si128(); // set zero function
	__m128i key = _mm_loadu_si128(k); // TODO: Load
	
	generate_aes_key(key);
	
	int fin_mes = mlen%CRYPTO_KEYBYTES; 
	int numblocks_mes = mlen/CRYPTO_KEYBYTES; // if |M*[l]| < 128, numblocks_ad = l-1. Otherwise, numblocks_ad = l
	int fin_ad = adlen%CRYPTO_KEYBYTES; // 
	int numblocks_ad = adlen/CRYPTO_KEYBYTES; // if |A*[a]| < 128, numblocks_ad = a-1. Otherwise, numblocks_ad = a
	bool pad_ad = (fin_ad > 0);
	bool pad_mes = (fin_mes > 0);
	
	// IV (and subkey) generation
	
	__m128i L = encrypt_block(zero_mes);
	__m128i L1 = _mm_xor_si128(L,mul2(L));
	__m128i L2 = _mm_xor_si128(L1,mul2(L1)); 

	unsigned char Aa[CRYPTO_KEYBYTES]; // = malloc(CRYPTO_KEYBYTES); 
	if(pad_ad)
	{
		
	}
	__m128i Wp,AA,Z;
	unsigned char Ai_t[CRYPTO_KEYBYTES]; // = malloc(CRYPTO_KEYBYTES);
	__m128i Ai;
	__m128i a_Ai[8];
	__m128i IV;
	__m128i a_delta[8];
	a_delta[7] = L1;
	__m128i delta = L1;
	__m128i nonceparam = _mm_set_epi64(nonce,param);
	Wp = encrypt_block( _mm_xor_si128( nonceparam,delta )); 
	int upper = numblocks_ad-1; 
	for(int i=0;i<upper;++i) 
	{
		a_delta[0] = mul2(a_delta[7]); 
		a_delta[1] = mul2(a_delta[0]); 
		a_delta[2] = mul2(a_delta[1]); 
		a_delta[3] = mul2(a_delta[2]); 
		a_delta[4] = mul2(a_delta[3]); 
		a_delta[5] = mul2(a_delta[4]); 
		a_delta[6] = mul2(a_delta[5]); 
		a_delta[7] = mul2(a_delta[6]); 
		
		a_Ai[0] = _mm_loadu_si128(ad+(i)*CRYPTO_KEYBYTES);
		a_Ai[1] = _mm_loadu_si128(ad+(i+1)*CRYPTO_KEYBYTES);
		a_Ai[2] = _mm_loadu_si128(ad+(i+2)*CRYPTO_KEYBYTES);
		a_Ai[3] = _mm_loadu_si128(ad+(i+3)*CRYPTO_KEYBYTES);
		a_Ai[4] = _mm_loadu_si128(ad+(i+4)*CRYPTO_KEYBYTES);
		a_Ai[5] = _mm_loadu_si128(ad+(i+5)*CRYPTO_KEYBYTES);
		a_Ai[6] = _mm_loadu_si128(ad+(i+6)*CRYPTO_KEYBYTES);
		a_Ai[7] = _mm_loadu_si128(ad+(i+7)*CRYPTO_KEYBYTES);
		
		a_Ai[0] = _mm_xor_si128( a_Ai[0],a_delta[0] );
		a_Ai[1] = _mm_xor_si128( a_Ai[1],a_delta[1] );
		a_Ai[2] = _mm_xor_si128( a_Ai[2],a_delta[2] );
		a_Ai[3] = _mm_xor_si128( a_Ai[3],a_delta[3] );
		a_Ai[4] = _mm_xor_si128( a_Ai[4],a_delta[4] );
		a_Ai[5] = _mm_xor_si128( a_Ai[5],a_delta[5] );
		a_Ai[6] = _mm_xor_si128( a_Ai[6],a_delta[6] );
		a_Ai[7] = _mm_xor_si128( a_Ai[7],a_delta[7] );
		
		encrypt_8block2(a_Ai); // TODO: Parallel
		Wp = Wp^a_Ai[0]^a_Ai[1]^a_Ai[2]^a_Ai[3]^a_Ai[4]^a_Ai[5]^a_Ai[6]^a_Ai[7];
	}
	
	if(pad_ad)
	{
		memcpy(Aa, ad+(numblocks_ad*CRYPTO_KEYBYTES), fin_ad);
		Aa[fin_ad] = 0x80;
		memset(Aa+fin_ad+1,0,CRYPTO_KEYBYTES-(fin_ad+1));
		++numblocks_ad;
		Ai = _mm_loadu_si128(Aa); 
		delta =  _mm_xor_si128( _mm_xor_si128(a_delta[7],mul2(a_delta[7])) , mul2(mul2(a_delta[7])) );
	}
	else
	{
		Ai = _mm_loadu_si128(ad+upper*CRYPTO_KEYBYTES); 
		delta = mul2(a_delta[7]); 
	}
	AA = _mm_xor_si128( Ai,delta );
	Z = encrypt_block(AA);
	IV = _mm_xor_si128( Z,Wp );

	// Encryption
	upper = numblocks_mes-1;
	unsigned char M_star[CRYPTO_KEYBYTES]; // = malloc(CRYPTO_KEYBYTES); // TODO: Check redundancy
	if(pad_mes)
	{
		memcpy(M_star, m+(numblocks_mes*CRYPTO_KEYBYTES), fin_mes);
		M_star[fin_mes] = 0x80;
		memset(M_star+fin_mes+1,0,CRYPTO_KEYBYTES-(fin_mes+1));
		++numblocks_mes;
	}
	else
	{
		memcpy(M_star,m+CRYPTO_KEYBYTES*upper,CRYPTO_KEYBYTES);
		fin_mes = CRYPTO_KEYBYTES;
	}
	// printf("%d\n",numblocks_mes);
	__m128i M;
	__m128i Ml;
	unsigned char Mi_t[CRYPTO_KEYBYTES]; // = malloc(CRYPTO_KEYBYTES);
	unsigned char ctb[CRYPTO_KEYBYTES]; // = malloc(CRYPTO_KEYBYTES);
	upper = numblocks_mes-1; // l-1 
	// if(!pad_mes) // TODO: Optimize
	
	Ml = _mm_loadu_si128(M_star);
	
	__m128i MM;
	__m128i W = IV;
	__m128i X,_2W;
	__m128i Y;
	__m128i CC;
	__m128i C;
	__m128i TT;
	__m128i deltaC = L2;
	
	delta = L;
	a_delta[7];
	int hi = 0;
	int h = upper/127;
	int tags = (numblocks_mes/127);
	__m128i *T = malloc(tags*sizeof(__m128i)); // I know that malloc can be evil, and the number of tags can precomputed knowing the size of the plaintext (see and compile countchars.c), but I'll leave it here for now.
	bool n = false;
	// printf("upper = %d\n",upper);
	__m128i Mg[8];
	/* __m128i Xg[8];
	__m128i Cg[8];
	__m128i Yg[8]; // */
	int i,j;
	// upper /= 8;
	for(i=0;i<upper;i+=8) // i=1 -> i=l-1
	{
		
			Mg[0] = _mm_loadu_si128(m+(i+0)*CRYPTO_KEYBYTES);
			Mg[1] = _mm_loadu_si128(m+(i+1)*CRYPTO_KEYBYTES);
			Mg[2] = _mm_loadu_si128(m+(i+2)*CRYPTO_KEYBYTES);
			Mg[3] = _mm_loadu_si128(m+(i+3)*CRYPTO_KEYBYTES);
			Mg[4] = _mm_loadu_si128(m+(i+4)*CRYPTO_KEYBYTES);
			Mg[5] = _mm_loadu_si128(m+(i+5)*CRYPTO_KEYBYTES);
			Mg[6] = _mm_loadu_si128(m+(i+6)*CRYPTO_KEYBYTES);
			Mg[7] = _mm_loadu_si128(m+(i+7)*CRYPTO_KEYBYTES);
			
			Ml = Ml^Mg[0]^Mg[1]^Mg[2]^Mg[3]^Mg[4]^Mg[5]^Mg[6]^Mg[7]; //  _mm_xor_si128( M,Ml );
			
			a_delta[0] = mul2(a_delta[7]); 
			a_delta[1] = mul2(a_delta[0]); 
			a_delta[2] = mul2(a_delta[1]); 
			a_delta[3] = mul2(a_delta[2]);
			a_delta[4] = mul2(a_delta[3]); 
			a_delta[5] = mul2(a_delta[4]); 
			a_delta[6] = mul2(a_delta[5]); 
			a_delta[7] = mul2(a_delta[6]);
			 
			Mg[0] = _mm_xor_si128( Mg[0],a_delta[0] );
			Mg[1] = _mm_xor_si128( Mg[1],a_delta[1] );
			Mg[2] = _mm_xor_si128( Mg[2],a_delta[2] );
			Mg[3] = _mm_xor_si128( Mg[3],a_delta[3] );
			Mg[4] = _mm_xor_si128( Mg[4],a_delta[4] );
			Mg[5] = _mm_xor_si128( Mg[5],a_delta[5] );
			Mg[6] = _mm_xor_si128( Mg[6],a_delta[6] );
			Mg[7] = _mm_xor_si128( Mg[7],a_delta[7] );
		
		
		
		/*for(j=0;j<8;++j)
		{
			M = _mm_loadu_si128(m+(i*8+j)*CRYPTO_KEYBYTES);
			Ml = _mm_xor_si128( M,Ml );
			delta = mul2(delta); 
			Mg[j] = _mm_xor_si128( M,delta );
		}*/
		
		encrypt_8block2(Mg); // See COLM_0 encrypt.c for how to change back to multi array
		
		/*
		_2W = mul2(W);
		// X = Xg[j];
		Y = _mm_xor_si128( X,  _mm_xor_si128(W,_2W) ); 
		W = _mm_xor_si128( X,  _2W ); 
		if((i)%127 == 126) 
		{
			TT = encrypt_block(W);
			n = true;
		}
		CC = encrypt_block(Y);
		*/
		
		for(j=0;j<8;++j)
		{
			_2W = mul2(W);
			X = Mg[j];
			Mg[j] = _mm_xor_si128( X,  _mm_xor_si128(W,_2W) ); 
			W = _mm_xor_si128( X,  _2W ); 
			if((i+j)%127 == 126) 
			{
				TT = encrypt_block(W);
				n = true;
			}
		}
		
		encrypt_8block2(Mg/*,Cg*/); // CC
		/*
		deltaC = mul2(deltaC);
		if(n && (i)%127==0)
		{
			T[hi] = _mm_xor_si128(deltaC,TT);
			deltaC = mul2(deltaC);
			++hi;
			n = false;
		}
		C = _mm_xor_si128(CC,deltaC);
		_mm_storeu_si128( (__m128i *)&c[i*CRYPTO_KEYBYTES], C );
		*/
		
		for(j=0;j<8;++j)
		{
			deltaC = mul2(deltaC);
			if(n && (i+j)%127==0) 
			{
				T[hi] = _mm_xor_si128(deltaC,TT);
				deltaC = mul2(deltaC);
				++hi;
				n = false;
			}
			C = _mm_xor_si128(Mg[j],deltaC);
			_mm_storeu_si128( (__m128i *)&c[(i+j)*CRYPTO_KEYBYTES], C ); 
		}
	}
	
	// Assumption: delta_m independent from h
	__m128i _2delta = mul2(a_delta[7]); 
	delta = _mm_xor_si128(_mm_xor_si128(a_delta[7] ,_2delta),mul2(_2delta));
	if(pad_mes)
	{
		_2delta = mul2(delta);
		delta = _mm_xor_si128(_mm_xor_si128(delta ,_2delta),mul2(_2delta));
	}
	// i = l
	
	if(n) // Temp tag hanging - hi = h-1
	{
		// printf("case TT hang applies\n");
		deltaC = mul2(deltaC); // i = l + h -1 -> regular shift
		T[hi] = _mm_xor_si128(deltaC,TT);
		n = false; // Problem solved
		__m128i _2deltaC = mul2(deltaC);
		deltaC = _mm_xor_si128(_mm_xor_si128(deltaC ,_2deltaC),mul2(_2deltaC));
		if(pad_mes)
		{
			_2deltaC = mul2(deltaC);
			deltaC = _mm_xor_si128(_mm_xor_si128(deltaC ,_2deltaC),mul2(_2deltaC));
		}
		
		MM = _mm_xor_si128( Ml,delta );
		
		X = encrypt_block(MM);
	
		// rho(X,&Y,&W);
		
		_2W = mul2(W);
		// X = Xg[j];
		Y/*g[j]*/ = _mm_xor_si128( X,  _mm_xor_si128(W,_2W) ); 
		W = _mm_xor_si128( X,  _2W ); 
		CC = encrypt_block(Y);
		
		C = _mm_xor_si128(CC,deltaC);
		_mm_storeu_si128( (__m128i *)&c[upper*CRYPTO_KEYBYTES], C ); // Store straight!! beware
		// memcpy(c+upper*CRYPTO_KEYBYTES,ctb,CRYPTO_KEYBYTES);
	}
	else if(upper%127 == 126) // final regular iteration with TT generation - hi = h - 1 
	{
		// delta = mul2(delta); // Assumption is that delta_m is independent from h, meaning that this computation is done earlier.
		// printf("case TT on upper applies\n");
		MM = _mm_xor_si128( Ml,delta );
		X = encrypt_block(MM);
		// rho(X,&Y,&W);
		_2W = mul2(W);
		// X = Xg[j];
		Y/*g[j]*/ = _mm_xor_si128( X,  _mm_xor_si128(W,_2W) ); 
		W = _mm_xor_si128( X,  _2W ); 
		TT = encrypt_block(W);
		CC = encrypt_block(Y);
		deltaC = mul2(deltaC); 
		
		
		C = _mm_xor_si128(CC,deltaC);
		_mm_storeu_si128( (__m128i *)&c[upper*CRYPTO_KEYBYTES], C ); // Store straight!! beware
		// memcpy(c+upper*CRYPTO_KEYBYTES,ctb,CRYPTO_KEYBYTES);
		n = true;
		
		
		__m128i _2deltaC = mul2(deltaC);
		deltaC = _mm_xor_si128(_mm_xor_si128(deltaC ,_2deltaC),mul2(_2deltaC));
	
		if(pad_mes)
		{
			_2deltaC = mul2(deltaC);
			deltaC = _mm_xor_si128(_mm_xor_si128(deltaC ,_2deltaC),mul2(_2deltaC));
		}
	}
	else
	{
		// printf("General case applies\n");
		__m128i _2deltaC = mul2(deltaC);
		deltaC = _mm_xor_si128(_mm_xor_si128(deltaC ,_2deltaC),mul2(_2deltaC));
	
		if(pad_mes)
		{
			_2deltaC = mul2(deltaC);
			deltaC = _mm_xor_si128(_mm_xor_si128(deltaC ,_2deltaC),mul2(_2deltaC));
		}
	
	
	
		MM = _mm_xor_si128( Ml,delta );
		
		X = encrypt_block(MM);
	
		// rho(X,&Y,&W);
		
		_2W = mul2(W);
		// X = Xg[j];
		Y/*g[j]*/ = _mm_xor_si128( X,  _mm_xor_si128(W,_2W) ); 
		W = _mm_xor_si128( X,  _2W ); 
		CC = encrypt_block(Y);
		
		C = _mm_xor_si128(CC,deltaC);
		_mm_storeu_si128( (__m128i *)&c[upper*CRYPTO_KEYBYTES], C ); // Store straight!! beware
		// memcpy(c+upper*CRYPTO_KEYBYTES,ctb,CRYPTO_KEYBYTES);
	}
	

	
	
	// i = l + 1 
		
	
	delta = mul2(delta);
	
	MM = _mm_xor_si128( Ml,delta );
	
	X = encrypt_block(MM);
	
	//rho(X,&Y,&W);
	_2W = mul2(W);
	// X = Xg[j];
	Y/*g[j]*/ = _mm_xor_si128( X,  _mm_xor_si128(W,_2W) ); 
	W = _mm_xor_si128( X,  _2W ); 
	bool fin_n = false;
		
	deltaC = mul2(deltaC);
	
	CC = encrypt_block(Y);

	if(n)
	{
		T[hi] = _mm_xor_si128(deltaC,TT);
		deltaC = mul2(deltaC);
		++hi;
		n = false;
	}
	
	C = _mm_xor_si128(CC,deltaC);
	
	
	_mm_storeu_si128( (__m128i *)&ctb[0], C ); // Store straight - beware
	
	int os = CRYPTO_KEYBYTES - fin_mes;
	memcpy(c+numblocks_mes*CRYPTO_KEYBYTES,ctb,fin_mes);
	for(int i=1;i<=tags;++i)
	{
		// printf("Entry of int tag loop number: %d\n",i);
		_mm_storeu_si128( (__m128i *)&c[( (numblocks_mes+i)*CRYPTO_KEYBYTES ) - os], T[i-1] );
		// memcpy(c+( ( (numblocks_mes+i)*CRYPTO_KEYBYTES ) - os),ctb,CRYPTO_KEYBYTES);
	}
	
	*clen = mlen + ((numblocks_mes/127)+1)*CRYPTO_KEYBYTES; 
	// printf("nbm = %d\nmlen = %d\nclen = %d\nfin_mes = %d\n",numblocks_mes,mlen,*clen,fin_mes);
	
	return 0;
}
