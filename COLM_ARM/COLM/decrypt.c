#include <stdio.h>
#include "api.h"
#include "emmintrin.h"
#include "wmmintrin.h"
#include "crypto_aead.h"
#include "auxfuncs.h"
#include <stdbool.h>
// #include "debugfuncs.h"

__m128i dec_keys[20];

void generate_dec_key(__m128i key) 
{
	__m128i kt;
	dec_keys[0] = key;
	kt = _mm_aeskeygenassist_si128(key, 0x01);
	dec_keys[1] = key_exp_assist(dec_keys[0],kt);
	kt = _mm_aeskeygenassist_si128(dec_keys[1], 0x02);
	dec_keys[2] = key_exp_assist(dec_keys[1],kt);
	kt = _mm_aeskeygenassist_si128(dec_keys[2], 0x04);
	dec_keys[3] = key_exp_assist(dec_keys[2],kt);
	kt = _mm_aeskeygenassist_si128(dec_keys[3], 0x08);
	dec_keys[4] = key_exp_assist(dec_keys[3],kt);
	kt = _mm_aeskeygenassist_si128(dec_keys[4], 0x10);
	dec_keys[5] = key_exp_assist(dec_keys[4],kt);
	kt = _mm_aeskeygenassist_si128(dec_keys[5], 0x20);
	dec_keys[6] = key_exp_assist(dec_keys[5],kt);
	kt = _mm_aeskeygenassist_si128(dec_keys[6], 0x40);
	dec_keys[7] = key_exp_assist(dec_keys[6],kt);
	kt = _mm_aeskeygenassist_si128(dec_keys[7], 0x80);
	dec_keys[8] = key_exp_assist(dec_keys[7],kt);
	kt = _mm_aeskeygenassist_si128(dec_keys[8], 0x1B);
	dec_keys[9] = key_exp_assist(dec_keys[8],kt);
	kt = _mm_aeskeygenassist_si128(dec_keys[9], 0x36);
	dec_keys[10] = key_exp_assist(dec_keys[9],kt);
	dec_keys[11] = _mm_aesimc_si128(dec_keys[9]); // Even on the pipeline, this is a heavy function...
	dec_keys[12] = _mm_aesimc_si128(dec_keys[8]);
	dec_keys[13] = _mm_aesimc_si128(dec_keys[7]);
	dec_keys[14] = _mm_aesimc_si128(dec_keys[6]);
	dec_keys[15] = _mm_aesimc_si128(dec_keys[5]);
	dec_keys[16] = _mm_aesimc_si128(dec_keys[4]);
	dec_keys[17] = _mm_aesimc_si128(dec_keys[3]);
	dec_keys[18] = _mm_aesimc_si128(dec_keys[2]);
	dec_keys[19] = _mm_aesimc_si128(dec_keys[1]);
}

void decrypt_8block2(__m128i* in) 
{
	// __m128i* tmp = malloc(8*sizeof(__m128i));
	
	in[0] = _mm_xor_si128(in[0],dec_keys[10]);
	in[1] = _mm_xor_si128(in[1],dec_keys[10]);
	in[2] = _mm_xor_si128(in[2],dec_keys[10]);
	in[3] = _mm_xor_si128(in[3],dec_keys[10]);
	in[4] = _mm_xor_si128(in[4],dec_keys[10]);
	in[5] = _mm_xor_si128(in[5],dec_keys[10]);
	in[6] = _mm_xor_si128(in[6],dec_keys[10]);
	in[7] = _mm_xor_si128(in[7],dec_keys[10]);
	// print128_asint(in[1]);

	in[0] = _mm_aesdec_si128(in[0],dec_keys[11]);
	in[1] = _mm_aesdec_si128(in[1],dec_keys[11]);
	in[2] = _mm_aesdec_si128(in[2],dec_keys[11]);
	in[3] = _mm_aesdec_si128(in[3],dec_keys[11]);
	in[4] = _mm_aesdec_si128(in[4],dec_keys[11]);
	in[5] = _mm_aesdec_si128(in[5],dec_keys[11]);
	in[6] = _mm_aesdec_si128(in[6],dec_keys[11]);
	in[7] = _mm_aesdec_si128(in[7],dec_keys[11]);
	// print128_asint(in[1]);
	
	in[0] = _mm_aesdec_si128(in[0],dec_keys[12]);
	in[1] = _mm_aesdec_si128(in[1],dec_keys[12]);
	in[2] = _mm_aesdec_si128(in[2],dec_keys[12]);
	in[3] = _mm_aesdec_si128(in[3],dec_keys[12]);
	in[4] = _mm_aesdec_si128(in[4],dec_keys[12]);
	in[5] = _mm_aesdec_si128(in[5],dec_keys[12]);
	in[6] = _mm_aesdec_si128(in[6],dec_keys[12]);
	in[7] = _mm_aesdec_si128(in[7],dec_keys[12]);
	// print128_asint(in[1]);
	
	in[0] = _mm_aesdec_si128(in[0],dec_keys[13]);
	in[1] = _mm_aesdec_si128(in[1],dec_keys[13]);
	in[2] = _mm_aesdec_si128(in[2],dec_keys[13]);
	in[3] = _mm_aesdec_si128(in[3],dec_keys[13]);
	in[4] = _mm_aesdec_si128(in[4],dec_keys[13]);
	in[5] = _mm_aesdec_si128(in[5],dec_keys[13]);
	in[6] = _mm_aesdec_si128(in[6],dec_keys[13]);
	in[7] = _mm_aesdec_si128(in[7],dec_keys[13]);
	// print128_asint(in[1]);

	in[0] = _mm_aesdec_si128(in[0],dec_keys[14]);
	in[1] = _mm_aesdec_si128(in[1],dec_keys[14]);
	in[2] = _mm_aesdec_si128(in[2],dec_keys[14]);
	in[3] = _mm_aesdec_si128(in[3],dec_keys[14]);
	in[4] = _mm_aesdec_si128(in[4],dec_keys[14]);
	in[5] = _mm_aesdec_si128(in[5],dec_keys[14]);
	in[6] = _mm_aesdec_si128(in[6],dec_keys[14]);
	in[7] = _mm_aesdec_si128(in[7],dec_keys[14]);
	// print128_asint(in[1]);
	
	in[0] = _mm_aesdec_si128(in[0],dec_keys[15]);
	in[1] = _mm_aesdec_si128(in[1],dec_keys[15]);
	in[2] = _mm_aesdec_si128(in[2],dec_keys[15]);
	in[3] = _mm_aesdec_si128(in[3],dec_keys[15]);
	in[4] = _mm_aesdec_si128(in[4],dec_keys[15]);
	in[5] = _mm_aesdec_si128(in[5],dec_keys[15]);
	in[6] = _mm_aesdec_si128(in[6],dec_keys[15]);
	in[7] = _mm_aesdec_si128(in[7],dec_keys[15]);
	// print128_asint(in[1]);
	
	in[0] = _mm_aesdec_si128(in[0],dec_keys[16]);
	in[1] = _mm_aesdec_si128(in[1],dec_keys[16]);
	in[2] = _mm_aesdec_si128(in[2],dec_keys[16]);
	in[3] = _mm_aesdec_si128(in[3],dec_keys[16]);
	in[4] = _mm_aesdec_si128(in[4],dec_keys[16]);
	in[5] = _mm_aesdec_si128(in[5],dec_keys[16]);
	in[6] = _mm_aesdec_si128(in[6],dec_keys[16]);
	in[7] = _mm_aesdec_si128(in[7],dec_keys[16]);
	// print128_asint(in[1]);

	in[0] = _mm_aesdec_si128(in[0],dec_keys[17]);
	in[1] = _mm_aesdec_si128(in[1],dec_keys[17]);
	in[2] = _mm_aesdec_si128(in[2],dec_keys[17]);
	in[3] = _mm_aesdec_si128(in[3],dec_keys[17]);
	in[4] = _mm_aesdec_si128(in[4],dec_keys[17]);
	in[5] = _mm_aesdec_si128(in[5],dec_keys[17]);
	in[6] = _mm_aesdec_si128(in[6],dec_keys[17]);
	in[7] = _mm_aesdec_si128(in[7],dec_keys[17]);
	// print128_asint(in[1]);
	
	in[0] = _mm_aesdec_si128(in[0],dec_keys[18]);
	in[1] = _mm_aesdec_si128(in[1],dec_keys[18]);
	in[2] = _mm_aesdec_si128(in[2],dec_keys[18]);
	in[3] = _mm_aesdec_si128(in[3],dec_keys[18]);
	in[4] = _mm_aesdec_si128(in[4],dec_keys[18]);
	in[5] = _mm_aesdec_si128(in[5],dec_keys[18]);
	in[6] = _mm_aesdec_si128(in[6],dec_keys[18]);
	in[7] = _mm_aesdec_si128(in[7],dec_keys[18]);
	// print128_asint(in[1]);
	
	in[0] = _mm_aesdec_si128(in[0],dec_keys[19]);
	in[1] = _mm_aesdec_si128(in[1],dec_keys[19]);
	in[2] = _mm_aesdec_si128(in[2],dec_keys[19]);
	in[3] = _mm_aesdec_si128(in[3],dec_keys[19]);
	in[4] = _mm_aesdec_si128(in[4],dec_keys[19]);
	in[5] = _mm_aesdec_si128(in[5],dec_keys[19]);
	in[6] = _mm_aesdec_si128(in[6],dec_keys[19]);
	in[7] = _mm_aesdec_si128(in[7],dec_keys[19]);
	// print128_asint(in[1]);

	in[0] = _mm_aesdeclast_si128(in[0],dec_keys[0]);
	in[1] = _mm_aesdeclast_si128(in[1],dec_keys[0]);
	in[2] = _mm_aesdeclast_si128(in[2],dec_keys[0]);
	in[3] = _mm_aesdeclast_si128(in[3],dec_keys[0]);
	in[4] = _mm_aesdeclast_si128(in[4],dec_keys[0]);
	in[5] = _mm_aesdeclast_si128(in[5],dec_keys[0]);
	in[6] = _mm_aesdeclast_si128(in[6],dec_keys[0]);
	in[7] = _mm_aesdeclast_si128(in[7],dec_keys[0]);
} // */ 

__m128i encypt_block_d(__m128i pt) 
{
	__m128i tmp;
	tmp = _mm_xor_si128(pt,dec_keys[0]);// print128_asint(tmp);

	tmp = _mm_aesenc_si128(tmp,dec_keys[1]);// print128_asint(tmp);
	tmp = _mm_aesenc_si128(tmp,dec_keys[2]);// print128_asint(tmp);
	tmp = _mm_aesenc_si128(tmp,dec_keys[3]);// print128_asint(tmp);

	tmp = _mm_aesenc_si128(tmp,dec_keys[4]);// print128_asint(tmp);
	tmp = _mm_aesenc_si128(tmp,dec_keys[5]);// print128_asint(tmp);
	tmp = _mm_aesenc_si128(tmp,dec_keys[6]);// print128_asint(tmp);

	tmp = _mm_aesenc_si128(tmp,dec_keys[7]);// print128_asint(tmp);
	tmp = _mm_aesenc_si128(tmp,dec_keys[8]);// print128_asint(tmp);
	tmp = _mm_aesenc_si128(tmp,dec_keys[9]);// print128_asint(tmp);

	tmp = _mm_aesenclast_si128(tmp,dec_keys[10]);
	return tmp;
}

__m128i decrypt_block(__m128i ct) 
{
	__m128i tmp;
	tmp = _mm_xor_si128(ct,dec_keys[10]);

	tmp = _mm_aesdec_si128(tmp,dec_keys[11]);
	tmp = _mm_aesdec_si128(tmp,dec_keys[12]);
	tmp = _mm_aesdec_si128(tmp,dec_keys[13]);

	tmp = _mm_aesdec_si128(tmp,dec_keys[14]);
	tmp = _mm_aesdec_si128(tmp,dec_keys[15]);
	tmp = _mm_aesdec_si128(tmp,dec_keys[16]);

	tmp = _mm_aesdec_si128(tmp,dec_keys[17]);
	tmp = _mm_aesdec_si128(tmp,dec_keys[18]);
	tmp = _mm_aesdec_si128(tmp,dec_keys[19]);

	tmp = _mm_aesdeclast_si128(tmp,dec_keys[0]);
	return tmp;
}

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
	
	generate_dec_key(key);
	
	int fin_cip = clen%CRYPTO_KEYBYTES; 
	int numblocks_cip = clen/CRYPTO_KEYBYTES;
	int fin_ad = adlen%CRYPTO_KEYBYTES; // 
	int numblocks_ad = adlen/CRYPTO_KEYBYTES; // if |A*[a]| < 128, numblocks_ad = a-1. Otherwise, numblocks_ad = a
	bool pad_ad = (fin_ad > 0 || adlen == 0);
	bool pad_cip = (fin_cip > 0 || clen == CRYPTO_KEYBYTES);
	
	
	// IV (and subkey) generation
	
	__m128i L = encypt_block_d(zero_mes);
	__m128i L1 = _mm_xor_si128(L,mul2(L));
	__m128i L2 = _mm_xor_si128(L1,mul2(L1)); 
	__m128i delta = L1; 
	
	__m128i Wp,AA,Z,Ai,IV,_2delta;
	
	
	__m128i nonceparam = _mm_set_epi64(nonce,param); 
	Wp = encypt_block_d( _mm_xor_si128( nonceparam,delta )); 
	// print128_asint(Wp);
	int upper = numblocks_ad-1; 
	
	unsigned char Aa[CRYPTO_KEYBYTES]; 
	for(int i=0;i<upper;++i) // Current case |AD|<8 blocks
	{
		delta = mul2(delta); 
		Ai = _mm_loadu_si128(ad+i*CRYPTO_KEYBYTES); 
		AA = _mm_xor_si128( Ai,delta );
		Z = encypt_block_d(AA); 
		Wp = _mm_xor_si128( Z,Wp );
	}
	// print128_asint(Wp);
	if(pad_ad)
	{
		memcpy(Aa, ad+(numblocks_ad*CRYPTO_KEYBYTES), fin_ad); // More variable length stuff
		Aa[fin_ad] = 0x80;
		memset(Aa+fin_ad+1,0,CRYPTO_KEYBYTES-(fin_ad+1));
		++numblocks_ad;
		Ai = _mm_loadu_si128(Aa); 
		_2delta = mul2(delta);
		delta =  _mm_xor_si128( _mm_xor_si128(delta,_2delta) , mul2(_2delta) );
	}
	else
	{
		Ai = _mm_loadu_si128(ad+upper*CRYPTO_KEYBYTES); 
		delta = mul2(delta); 
	}
	AA = _mm_xor_si128( Ai,delta );
	Z = encypt_block_d(AA); // Same function as "encrypt_block" in encrypt
	IV = _mm_xor_si128( Z,Wp );
	// print128_asint(IV);
	
	// Decryption
	
	__m128i W = IV;
	__m128i C,Y,deltaC,M;
	__m128i M_star = zero_mes; 
	__m128i Cg[8]; 
	/*__m128i Yg[8]; 
	__m128i Xg[8]; 
	__m128i Mg[8]; // */ 
	if(!pad_cip)
	{
		--numblocks_cip;
		fin_cip = CRYPTO_KEYBYTES;
	}
	
	int mf = numblocks_cip-1; 
	upper = mf/8;
	int j;
	deltaC = L2;
	delta = L;
	// upper /= 8;
	for(int i=0;i<upper;++i) // See encrypt.c for instructions on how to change to a multi-array setup.
	{
		for(j=0;j<8;++j)
		{
			C= _mm_loadu_si128(c+((i*8+j  )*CRYPTO_KEYBYTES));
			deltaC = mul2(deltaC); 
			Cg[j] = _mm_xor_si128(C,deltaC);
		}		
		
		decrypt_8block2(Cg/*,Yg*/);
		
		for(j=0;j<8;++j) // rho_inv loop
		{
			Y = Cg[j];
			Cg[j] = _mm_xor_si128( Y, _mm_xor_si128(W,mul2(W) ) )  ;
			W = _mm_xor_si128( Y,W );
		}	
		
		decrypt_8block2(Cg/*,Mg*/);
		for(j=0;j<8;++j)
		{
			delta = mul2(delta);
			M = _mm_xor_si128(Cg[j],delta);
			M_star = _mm_xor_si128(M_star,M);
			_mm_storeu_si128( (__m128i *)&m[(i*8+j)*CRYPTO_KEYBYTES], M ); // Store straight
			
		}
	}
	
	C = _mm_loadu_si128(c+mf*CRYPTO_KEYBYTES);
	// print128_asint(C);
	
	// print128_asint(delta);
	_2delta = mul2(delta); 
	delta = _mm_xor_si128(_mm_xor_si128(delta ,_2delta),mul2(_2delta));
	// print128_asint(deltaC);
	__m128i _2deltaC = mul2(deltaC);
	deltaC = _mm_xor_si128(_mm_xor_si128(deltaC ,_2deltaC),mul2(_2deltaC));
	
	if(fin_cip%16)
	{
		_2delta = mul2(delta);
		delta = _mm_xor_si128(_mm_xor_si128(delta ,_2delta),mul2(_2delta));
		_2deltaC = mul2(deltaC);
		deltaC = _mm_xor_si128(_mm_xor_si128(deltaC ,_2deltaC),mul2(_2deltaC));
	}
	
	__m128i CC = _mm_xor_si128(C,deltaC);
		
	Y = decrypt_block(CC);
	__m128i X = _mm_xor_si128( Y, _mm_xor_si128(W,mul2(W) ) )  ;
	
	W = _mm_xor_si128( Y,W );
	__m128i MM = decrypt_block(X);
	// print128_asint(delta);
	M = _mm_xor_si128(MM,delta);
	__m128i M1 = M;
	M_star = _mm_xor_si128(M_star,M);
	unsigned char m_t[CRYPTO_KEYBYTES];
	_mm_storeu_si128( (__m128i *)&m_t[0], M_star ); 
	memcpy(m+(mf*CRYPTO_KEYBYTES),m_t,fin_cip); // Variable length array. Can't get rid of this memcpy.
	*mlen = mf*CRYPTO_KEYBYTES + fin_cip;
	
	
	// Verification
	
	__m128i MM1,Cv,ver,C1,_2W;
	delta = mul2(delta); 
	deltaC =  mul2(deltaC);
	
	bool good = false;
	MM1 = _mm_xor_si128(delta,M1);
	
	X = encypt_block_d(MM1);
	_2W = mul2(W);
	Y = _mm_xor_si128( X,  _mm_xor_si128(W,_2W) ); 
	W = _mm_xor_si128( X,  _2W ); 
	CC = encypt_block_d(Y);
	Cv = _mm_xor_si128(CC,deltaC);
	C1 = _mm_loadu_si128(c+numblocks_cip*CRYPTO_KEYBYTES);
	// printf("numblocks_cip = %d\n",numblocks_cip);
	// print128_asint(Cv);
	// print128_asint(C1);
	ver = _mm_xor_si128(C1,Cv);
	if(!(fin_cip%16)) 
	{
		good = check_zero(ver);
	}
	else
	{
		good = check_pad(ver,M_star,fin_cip); // May require fixing
	}
	if(!good)
	{
		// printf("Oh shit!\n");
		// memset(m,0,*mlen); // We don't want a plaintext bouncing around memory
		return -1;
	}
	
	return 0;
}

