#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arm_neon.h>

#include "macros.kkr"

/*Timing related stuff*/

#include <inttypes.h>
#include <stdint.h>
// #include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

#define _GNU_SOURCE             /* See feature_test_macros(7) */
#define __USE_GNU
#include <sched.h>

#define MAX_ITER 6

#ifndef REPEAT
	#define REPEAT 100000
#endif
#ifndef WARMUP
	#define WARMUP REPEAT/4
#endif
	uint64_t start_clk,end_clk;
	double total_clk;
int i;
__inline uint64_t get_Clks(void) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1e6 + tv.tv_usec); // usec
	//return clock();
}
#define MEASURE(x)  for (i=0; i< WARMUP; i++)		   \
								 {x;}				   \
					start_clk=get_Clks();			   \
					for (i = 0; i < REPEAT; i++)		\
					{								   \
								 {x;}				   \
					}								   \
					end_clk=get_Clks();				 \
					total_clk=(double)(end_clk-start_clk)*2.1e3/REPEAT;

#define TIME_IT(name, func, nbytes, MULTIPLE) \
	/*printf("%s-%d: ", name, nbytes);*/ \
	MEASURE(func); \
	fprintf(resdump,"%g \n" /*cpb\n"*/, total_clk/(nbytes)/(MULTIPLE));

/*Auxiliary functions*/

u128 keys[12];

void print128_asint(const u128 in){
	printf("%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n",in[0],in[1],in[2],in[3],in[4],in[5],in[6],in[7],in[8],in[9],in[10],in[11],in[12],in[13],in[14],in[15]); 
}

u128 mul2(u128 x)
{
	u128 red = {0x01,0x02,0x03,0x04, 0x05,0x06,0x07,0x08, 0x09,0x0a,0x0b,0x0c, 0x0d,0x0e,0x0f,0x0f}; // LOAD(rijn);
	u128 sm =  {0x01,0x02,0x03,0x04, 0x05,0x06,0x07,0x08, 0x09,0x0a,0x0b,0x0c, 0x0d,0x0e,0x0f,0x0f}; // LOAD(shift_mask);
	u128 ca = SR(x,7);
	u128 r_shift = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0x00}; // LOAD(right_mask);
	u8 cmp[16] = {0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff};
	u128 CMPT = {0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff}; // LOAD(cmp);
	u128 check = vcgtq_u8(ca, CMPT); /*Check if ca > CMPT, which is only possible on the first register*/
	check = PERMUTE(check,r_shift); /* Set up to and with field polynomial*/
	
	
	u128 o = SL(x,1);
	ca = PERMUTE(ca,sm);
	ca = ca & r_shift; /* Reuse to avoid loading twice. ca may be 0x01 in the rightmost register, and this absolutely needs to be 0. */
	o = o | ca;
	// u8 ds[16];
	int i;
	
	o = o^(red & check);
	return o;
	
	
} // */ 

int check_zero(u128 v)
{
	unsigned char c_arr[CRYPTO_KEYBYTES];
	STORE(c_arr,v); // ( (__m128i *)&c_arr[0], v );
	for(int i=0;i<CRYPTO_KEYBYTES;++i)
	{
		if(c_arr[i] != 0x00)
		{
			// printf("Wait what?!\n");
			return 0;
		}
	}
	return 1;
}

int check_pad(u128 ver, u128 M_star,int fin)
{
	unsigned char c_arr[CRYPTO_KEYBYTES];
	unsigned char M_arr[CRYPTO_KEYBYTES];
	STORE(c_arr,ver);
	STORE(M_arr,M_star);
	if(M_arr[fin] != 0x80)
	{
		// printf("fails 0x80\n");
		return 0;
	}
	for(int i=0;i<fin;++i)
	{
		if(c_arr[i] != 0x00)
		{
			// printf("fails comparison on iteration in c_arr %d\n",i);
			return 0;
		}
	}
	for(int i=fin+1;i<CRYPTO_KEYBYTES;++i)
	{
		if(M_arr[i] != 0x00)
		{
			// printf("fails star check on iteration in M_arr %d\n",i);
			return 0;
		}
	}
	return 1;
}

u8 sbox(u8 in) { /* Source: http://www.samiam.org/s-box.html , fitted with my macros  */ 
        u8 c, s, x;
        if(in){
        	s = x = atable[(255 - ltable[in])];
        }
        else{
        	s = x = 0x00;
        }
        for(c = 0; c < 4; ++c) {
                /* One bit circular rotate to the left */
                s = (s << 1) | (s >> 7);
                /* xor with x */
                x ^= s;
        }
        x ^= 99; /* 0x63 */
        return x;
}

u128 keygenassist(u128 key, u8 rc) /* I'm not sure if I'm adding RCON correctly. Intel didn't describe their "ZeroExtend" operation*/
{
	u8 tmp[16],res[16];
	u128 ret;
	STORE(tmp,key);
	res[0] = sbox(tmp[4]);
	res[1] = sbox(tmp[5]);
	res[2] = sbox(tmp[6]);
	res[3] = sbox(tmp[7]);
	
	res[4] = res[1];
	res[5] = res[2];
	res[6] = res[3];
	res[7] = res[0]^rc;
	
	res[8] = sbox(tmp[12]);
	res[9] = sbox(tmp[13]);
	res[10] = sbox(tmp[14]);
	res[11] = sbox(tmp[15]);
	
	res[12] = res[9];
	res[13] = res[10];
	res[14] = res[11];
	res[15] = res[8]^rc;
	
	ret=LOAD(res);
	return ret;
} // */

u128 key_exp_assist(u128 t1, u128 t2){
	
	u128 t2mask = {0x00,0x01,0x02,0x03, 0x00,0x01,0x02,0x03, 0x00,0x01,0x02,0x03, 0x00,0x01,0x02,0x03}; // LOAD(t2m);
	u128 shift_4 = {0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x00, 0x00, 0x00}; // LOAD(tv);
	u128 mask_4 = {0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,  0xff,0xff,0xff,0xff,  0x00,0x00,0x00,0x00}; //  LOAD(something);
	
	
	u128 t3 = PERMUTE(t1,shift_4);
	t3 = AND(t3,mask_4);
	t2 = PERMUTE(t2,t2mask); // _mm_shuffle_epi32(t2,0xFF);
	t1 = t1^t3; // _mm_xor_si128(t1,t3);
	t3 = PERMUTE(t1,shift_4);// _mm_slli_si128(t1,0x04);
	t3 = AND(t3,mask_4);
	t1 = t1^t3; // _mm_xor_si128(t1,t3);
	t3 = PERMUTE(t1,shift_4);// _mm_slli_si128(t1,0x04);
	t3 = AND(t3,mask_4);
	t1 = t1^t3; // _mm_xor_si128(t1,t3);
	return t1^t2; // _mm_xor_si128(t1,t2);
	
} // */

void key_expansion(u128 k)
{
	u128 kt;
	u128 zero = {0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,  0x00,0x00,0x00,0x00,  0x00,0x00,0x00,0x00};
	keys[11] = zero;
	keys[0] = k;
	kt = keygenassist(k,0x01);
	keys[1] = key_exp_assist(keys[0],kt);
	kt = keygenassist(keys[1], 0x02);
	keys[2] = key_exp_assist(keys[1],kt);
	kt = keygenassist(keys[2], 0x04);
	keys[3] = key_exp_assist(keys[2],kt);
	kt = keygenassist(keys[3], 0x08);
	keys[4] = key_exp_assist(keys[3],kt);
	kt = keygenassist(keys[4], 0x10);
	keys[5] = key_exp_assist(keys[4],kt);
	kt = keygenassist(keys[5], 0x20);
	keys[6] = key_exp_assist(keys[5],kt);
	kt = keygenassist(keys[6], 0x40);
	keys[7] = key_exp_assist(keys[6],kt);
	kt = keygenassist(keys[7], 0x80);
	keys[8] = key_exp_assist(keys[7],kt);
	kt = keygenassist(keys[8], 0x1B);
	keys[9] = key_exp_assist(keys[8],kt);
	kt = keygenassist(keys[9], 0x36);
	keys[10] = key_exp_assist(keys[9],kt);
}

/*Encrypt and decrypt functions*/


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
	// printf("Pointer for clen is %lu\nand pointer for cipher is %lu\n",clen,c+8);
	u8 nonceparam[16];
	memcpy(nonceparam+8,npub,8);
	nonceparam[0]=0x00;nonceparam[1]=0x00;nonceparam[2]=0x80;nonceparam[3]=0x00;nonceparam[4]=0x00;nonceparam[5]=0x00;nonceparam[6]=0x00;nonceparam[7]=0x00;
	
	u128 nonp = LOAD(nonceparam);
	u128 tmp_key = LOAD(k);
	key_expansion(tmp_key);

	
	u64 fin_mes = mlen%CRYPTO_KEYBYTES; 
	u64 numblocks_mes =  mlen/CRYPTO_KEYBYTES; // if |M*[l]| < 128, numblocks_ad = l-1. Otherwise, numblocks_ad = l
	u64 fin_ad =  adlen%CRYPTO_KEYBYTES;  
	u64 numblocks_ad = adlen/CRYPTO_KEYBYTES; // if |A*[a]| < 128, numblocks_ad = a-1. Otherwise, numblocks_ad = a
	
	// IV (and subkey) generation
	
	u128 L; ENCRYPT1(keys[11],L);
	u128 L1 = mul2(L); /* 3*L */
	L1 = L1 ^ L;
	u128 L2 = mul2(L1); /* 3^2*L */
	L2 = L2 ^ L1;

	
	// u128 a_Delta[8];
	u128 a_Delta[PARA];
	// a_Delta[0] = mul2(L1);
	a_Delta[PARA-1] = L1;
	u128 delta; //u128 delta; // = L1; 
	
	u128 Wp,AA,Z,Ai,IV,_2delta;// u128 Wp,AA,Z,Ai,IV,_2delta;
	u128 a_Ai[PARA];// u128 a_Ai[8];
	Wp = keys[11]; // keys[11] = 0
	ENCRYPT1(nonp^L1,Wp); // Wp = encrypt_block( _mm_xor_si128( nonceparam,L1 )); 
	u64 i,j,y;
	u64 upper = numblocks_ad; 
		
	if(!fin_ad){
		--upper;
	}
	
	int sin =1;
	int fin_encr=upper%PARA;
	if(!fin_encr){
		sin=0;
	}
	
	u8 Aa[CRYPTO_KEYBYTES]; 
	for(i=0;i<(upper-PARA*sin);i+=PARA) 
	{
		a_Delta[0] = mul2(a_Delta[PARA-1]);

		for(j=1;j<PARA;++j){
			
			a_Delta[j] = mul2(a_Delta[j-1]);
		}
		
	
		
		for(j=0;j<PARA;++j){
			a_Ai[j] = LOAD(ad+(i+j)*CRYPTO_KEYBYTES);
		}
		
		
		
		for(j=0;j<PARA;++j){
			a_Ai[j] = a_Ai[j]^a_Delta[j]; 
		}
		
		
		
		ENCRYPTPARA(a_Ai);
		
		for(j=0;j<PARA;++j){
			Wp ^= a_Ai[j];
		}
		
		
	}

	for(i=0;i<fin_encr;++i){
		a_Delta[PARA-1] = mul2(a_Delta[PARA-1]);
		a_Ai[0] = LOAD(ad+(i+upper-fin_encr)*CRYPTO_KEYBYTES);
		a_Ai[0] = a_Ai[0]^a_Delta[PARA-1];
		ENCRYPT1(a_Ai[0],a_Ai[0]);
		Wp = Wp^a_Ai[0];
	}
	
	
	if(fin_ad)
	{
		memcpy(Aa, ad+(numblocks_ad*CRYPTO_KEYBYTES), fin_ad); 
		Aa[fin_ad] = 0x80;
		memset(Aa+fin_ad+1,0,CRYPTO_KEYBYTES-(fin_ad+1));
		++numblocks_ad;
		Ai = LOAD(Aa); 
		_2delta = mul2(a_Delta[PARA-1]); 
		delta =  (mul2(_2delta) ^ ((a_Delta[PARA-1])^(_2delta))  ); 
	}
	else
	{
		Ai = LOAD(ad+upper*CRYPTO_KEYBYTES); 
		delta = mul2(a_Delta[PARA-1]); //mul2(a_Delta[0]); 
	}
	AA = Ai^delta; // _mm_xor_si128( Ai,delta );
	ENCRYPT1(AA,Z); //Z = encrypt_block(AA);
	IV = Z^Wp; // _mm_xor_si128( Z,Wp );
	printf("encr, IV: ");print128_asint(IV);
	// Encryption
	unsigned char M_star[CRYPTO_KEYBYTES]; 
	int mf = numblocks_mes-1; // l-1
	// upper = mf/8;
	if(fin_mes)
	{
		memcpy(M_star, m+(numblocks_mes*CRYPTO_KEYBYTES), fin_mes);
		M_star[fin_mes] = 0x80;
		memset(M_star+fin_mes+1,0,CRYPTO_KEYBYTES-(fin_mes+1));
		++numblocks_mes;
		++mf;
	}
	else
	{
		memcpy(M_star,m+CRYPTO_KEYBYTES*mf,CRYPTO_KEYBYTES);
		fin_mes = CRYPTO_KEYBYTES;
	}
	
	u128 Ml = LOAD(M_star); 
	
	u128 Mg[PARA]; 
	u128 M,X,C,_2W;
	u128 W = IV;
	u128 deltaC = L2;	
	delta = L;
	
	a_Delta[PARA-1] = L; /*COLM is one-indexed by nature...*/
	u128 a_DeltaC[PARA];
	a_DeltaC[PARA-1] = L2; /*Warning: COLM is one-indexed by nature...*/
	 u128 mes[PARA];
	 
	sin =1;
	fin_encr=mf%PARA;
	if(!fin_encr){
		sin=0;
	}

	for(i=0;i<(mf-sin*PARA);i+=PARA)
	{
		// for(j=0;j<8;++j)
		//{
			a_Delta[0] = mul2(a_Delta[PARA-1]);
			for(j=1;j<PARA;++j){
				
				a_Delta[j] = mul2(a_Delta[j-1]);
			} // */
			
			
				
			for(j=0;j<PARA;++j){		
				mes[j] = LOAD(m+((i+j)*CRYPTO_KEYBYTES));
			} // */
			
			
			
			for(j=0;j<PARA;++j){		
				Ml ^= mes[j]; 
			} // */		
			
			
			for(j=0;j<PARA;++j){		
				Mg[j] = mes[j]^a_Delta[j];
				
			} // */
			
		ENCRYPTPARA(Mg); // encrypt_8block2(Mg/*,Xg*/  ); // Change this to encrypt_8block, and remove the commented Xg
		
		for(j=0;j<PARA;++j)		
		{
			
			// _2W = mul2(W);
			Wp = Mg[j]^(mul2(W)); // _mm_xor_si128(Mg[j],mul2(W));
			Mg[j] = Wp^W; // _mm_xor_si128(Wp,W);
			W = Wp;
			
		}
		
		
		ENCRYPTPARA(Mg);
		
			
			a_DeltaC[0] = mul2(a_DeltaC[PARA-1]);
			
			
			for(j=1;j<PARA;++j){		
				a_DeltaC[j] = mul2(a_DeltaC[j-1]);
			} 
			
			
			for(j=0;j<PARA;++j){						
				mes[j] = Mg[j]^a_DeltaC[j]; 
			} // */ 
			
			for(j=0;j<PARA;++j){
				
				STORE( c+(i+j)*CRYPTO_KEYBYTES, mes[j] );
			}
	}
	
	for(i=0;i<fin_encr;++i){
		a_Delta[PARA-1] = mul2(a_Delta[PARA-1]);
		mes[0] = LOAD(m+((i+mf-fin_encr)*CRYPTO_KEYBYTES));
		Ml = mes[0]^Ml;
		Mg[0] = mes[0]^a_Delta[PARA-1];
		ENCRYPT1(Mg[0],Mg[0]);
		Wp = Mg[0]^mul2(W);
		Mg[0] = Wp^W; 
		W = Wp;
		ENCRYPT1(Mg[0],Mg[0]);
		
		a_DeltaC[PARA-1] = mul2(a_DeltaC[PARA-1]);
		mes[0] = Mg[0]^a_DeltaC[PARA-1];
		
		STORE( c+(i+mf-fin_encr)*CRYPTO_KEYBYTES, mes[0] );
	}
	
	delta = a_Delta[PARA-1]; //[0]
	// print128_asint(delta);
	_2delta = mul2(delta);  
	delta = ((delta ^_2delta)^(mul2(_2delta))  );// _mm_xor_si128(_mm_xor_si128(delta ,_2delta),mul2(_2delta));
	
	
	deltaC = a_DeltaC[PARA-1];
	u128 _2deltaC = mul2(deltaC);  
	deltaC = ((deltaC ^_2deltaC)^ (mul2(_2deltaC)) );//_mm_xor_si128(_mm_xor_si128(deltaC ,_2deltaC),mul2(_2deltaC));
	
	if(fin_mes%16)
	{
		_2delta = mul2(delta);
		delta = ((delta ^_2delta)^(mul2(_2delta))  );//_mm_xor_si128(_mm_xor_si128(delta ,_2delta),mul2(_2delta));
		_2deltaC = mul2(deltaC);
		deltaC = ((deltaC ^_2deltaC)^(mul2(_2deltaC)) );//_mm_xor_si128(_mm_xor_si128(deltaC ,_2deltaC),mul2(_2deltaC));
	}

	u128 MM = Ml^delta; //  u128 MM = _mm_xor_si128( Ml,delta );
	// print128_asint(delta);
	ENCRYPT1(MM,X); // X = encrypt_block(MM);
	
	_2W = mul2(W);
	u128 Y = X ^(W^_2W); //  _mm_xor_si128( X,  _mm_xor_si128(W,_2W) ); 
	W = X^_2W; //_mm_xor_si128( X,  _2W ); 
	
	u128 CC; ENCRYPT1(Y,CC); // u128 CC = encrypt_block(Y);
	
	C = CC^deltaC; //  _mm_xor_si128(CC,deltaC);
	// print128_asint(C);
	
	STORE( c+mf*CRYPTO_KEYBYTES , C ); /*(u128 *)&c[mf*CRYPTO_KEYBYTES]*/
	
	delta = mul2(delta);
	deltaC = mul2(deltaC);
	
	MM = Ml^delta; //_mm_xor_si128( Ml,delta );
	ENCRYPT1(MM,X); // X = encrypt_block(MM);
	_2W = mul2(W);
	Y = X ^(W^_2W); // _mm_xor_si128( X,  _mm_xor_si128(W,_2W) ); 
	W = X^_2W; // _mm_xor_si128( X,  _2W ); 
	ENCRYPT1(Y,CC); //CC = encrypt_block(Y);
	C = CC^deltaC; //_mm_xor_si128(CC,deltaC);
	unsigned char c_fin[CRYPTO_KEYBYTES];
	STORE( c_fin, C ); /*(u128 *)&c_fin[0]*/
	

	*clen = mlen + CRYPTO_ABYTES;

	
	
	memcpy(c+numblocks_mes*CRYPTO_KEYBYTES,c_fin,fin_mes);
	
	

	
	return 0;
}

/* DECRYPT */ 

int crypto_aead_decrypt(
       unsigned char *m,unsigned long long *mlen,
       unsigned char *nsec,
       const unsigned char *c,unsigned long long clen,
       const unsigned char *ad,unsigned long long adlen,
       const unsigned char *npub,
       const unsigned char *k
     )
{
	// printf("Pointer for cipher is %lu\n",c+8);
	// printf("Entering dec function\n");
        u8 nonceparam[16];
       
        // printf("%d %d\n",npub[0],npub[7]);
	memcpy(nonceparam+8,npub,8);
	nonceparam[0]=0x00;nonceparam[1]=0x00;nonceparam[2]=0x80;nonceparam[3]=0x00;nonceparam[4]=0x00;nonceparam[5]=0x00;nonceparam[6]=0x00;nonceparam[7]=0x00;
	
	u128 nonp = LOAD(nonceparam);
	// u128 tmp_key = LOAD(k);
	// key_expansion(tmp_key); /*Running it globally from the same main means that I'm not going to call it here*/ 
	
	u64 fin_cip = clen%CRYPTO_KEYBYTES; 
	u64 numblocks_cip = clen/CRYPTO_KEYBYTES;
	u64 fin_ad = adlen%CRYPTO_KEYBYTES; // 
	u64 numblocks_ad = adlen/CRYPTO_KEYBYTES; // if |A*[a]| < 128, numblocks_ad = a-1. Otherwise, numblocks_ad = a
	int pad_ad = (fin_ad > 0 || adlen == 0);
	int pad_cip = (fin_cip > 0 || clen == CRYPTO_KEYBYTES);
	
	
	// IV (and subkey) generation
	
	u128 L; ENCRYPT1(keys[11],L); //  = encypt_block_d(zero_mes);
	u128 L1 = L^(mul2(L)); // _mm_xor_si128(L,mul2(L));
	u128 L2 = L1^(mul2(L1)); //   _mm_xor_si128(L1,mul2(L1)); 
	u128 delta = L1; 
	
	u128 Wp,AA,Z,Ai,IV,_2delta;
	
	ENCRYPT1(nonp^L1, Wp); //  encypt_block_d( _mm_xor_si128( nonceparam,delta )); 
	
	u64 upper = numblocks_ad;
	if(!fin_ad){
		--upper;
	}
	
	unsigned char Aa[CRYPTO_KEYBYTES]; 
	for(int i=0;i<upper;++i) // Current case |AD|<8 blocks
	{
		delta = mul2(delta); 
		Ai = LOAD(ad+i*CRYPTO_KEYBYTES); 
		AA = Ai^delta; // _mm_xor_si128( Ai,delta );
		ENCRYPT1(AA,Z); // = encypt_block_d(AA); 
		Wp = Z^Wp; // _mm_xor_si128( Z,Wp );
		}
	
	if(pad_ad)
	{
		memcpy(Aa, ad+(numblocks_ad*CRYPTO_KEYBYTES), fin_ad); // More variable length stuff
		Aa[fin_ad] = 0x80;
		memset(Aa+fin_ad+1,0,CRYPTO_KEYBYTES-(fin_ad+1));
		++numblocks_ad;
		Ai = LOAD(Aa); 
		_2delta = mul2(delta);
		delta =  (mul2(_2delta))^(delta^_2delta);  // _mm_xor_si128( _mm_xor_si128(delta,_2delta) , mul2(_2delta) );
	}
	else
	{
		
		Ai = LOAD(ad+upper*CRYPTO_KEYBYTES); 
		delta = mul2(delta); 
	}
	AA = Ai^delta; // _mm_xor_si128( Ai,delta );
	ENCRYPT1(AA,Z); // Z = encypt_block_d(AA); // Same function as "encrypt_block" in encrypt
	IV = Z^Wp; // _mm_xor_si128( Z,Wp );
	// printf("IV, decr\n");
	printf("decr, IV: ");print128_asint(IV);
	// Decryption
	
	u128 W = IV;
	u128 C,Y,deltaC,M;
	u128 M_star = keys[11]; 
	u128 Cg[PARA]; 

	if(!pad_cip)
	{
		--numblocks_cip;
		fin_cip = CRYPTO_KEYBYTES;
	}
	
	int mf = numblocks_cip-1; 

	int j;
	deltaC = L2;
	delta = L;
	
	
	int sin =1;
	int fin_encr=mf%4;
	if(!fin_encr){
		sin=0;
	}

	for(int i=0;i<(mf-sin*PARA);i+=PARA) 
	{
		// printf("I don't want to see this more than once\n");
		for(j=0;j<PARA;++j) 
		{
			C= LOAD(c+((i+j  )*CRYPTO_KEYBYTES)    );
				
			deltaC = mul2(deltaC); 
			Cg[j] = C^deltaC; // _mm_xor_si128(C,deltaC);
			
		}		

		DECRYPT4(Cg);

		for(j=0;j<PARA;++j) // rho_inv loop
		{
			
			Y = Cg[j];
			Cg[j] = Y^(W^(mul2(W) ) );   // _mm_xor_si128( Y, _mm_xor_si128(W,mul2(W) ) )  ;
			W = Y^W; // _mm_xor_si128( Y,W );
			
		}	
		
		// decrypt_8block2(Cg/*,Mg*/);
		DECRYPT4(Cg);
		
		
		
		for(j=0;j<PARA;++j)
		{
			
			delta = mul2(delta);
			M = Cg[j]^delta; // _mm_xor_si128(Cg[j],delta);
			M_star = M_star^M; // _mm_xor_si128(M_star,M);
			STORE(m+(i+j)*CRYPTO_KEYBYTES,M ); // Store straight (__m128i *)&m[(i*8+j)*CRYPTO_KEYBYTES]	
		}

	}
	
	for(i=0;i<fin_encr;++i){
		deltaC = mul2(deltaC);
		C = LOAD( c+(mf+i-fin_encr)*CRYPTO_KEYBYTES );
		
		C = C^deltaC;
		
		DECRYPT1(C,C);
		Y = C;
		C = Y^(W^mul2(W) );
		W = Y^W;
		DECRYPT1(C,C);
		delta = mul2(delta);
		M = C^delta;
		M_star = M_star^M;
		printf("%d\n: ",(mf+i-fin_encr)*CRYPTO_KEYBYTES);print128_asint(M);
		STORE(m+(mf+i-fin_encr)*CRYPTO_KEYBYTES,M );
	}
	
	
	C = LOAD(c+mf*CRYPTO_KEYBYTES);
	_2delta = mul2(delta); 
	delta =  (delta^_2delta)^(mul2(_2delta)); // _mm_xor_si128(_mm_xor_si128(delta ,_2delta),mul2(_2delta));
	u128 _2deltaC = mul2(deltaC);
	deltaC = (deltaC^_2deltaC)^(mul2(_2deltaC)); //_mm_xor_si128(_mm_xor_si128(deltaC ,_2deltaC),mul2(_2deltaC));
	
	if(fin_cip%16)
	{
		_2delta = mul2(delta);
		delta =  (delta^_2delta)^(mul2(_2delta)); // _mm_xor_si128(_mm_xor_si128(delta ,_2delta),mul2(_2delta));
		u128 _2deltaC = mul2(deltaC);
		deltaC = (deltaC^_2deltaC)^(mul2(_2deltaC));
	}
	
	u128 CC = C^deltaC; //  _mm_xor_si128(C,deltaC);
		
	DECRYPT1(CC,Y); // Y = decrypt_block(CC);
	u128 X = Y^(W^(mul2(W))); // _mm_xor_si128( Y, _mm_xor_si128(W,mul2(W) ) )  ;
	
	W = Y^W; // _mm_xor_si128( Y,W );
	u128 MM; DECRYPT1(X,MM); // = decrypt_block(X);
	M = MM^delta; // _mm_xor_si128(MM,delta);
	u128 M1 = M;
	M_star = M_star^M; //  _mm_xor_si128(M_star,M);
	unsigned char m_t[CRYPTO_KEYBYTES];
	STORE( m_t, M_star ); // (u128 *)&m_t[0], M_star 
	memcpy(m+(mf*CRYPTO_KEYBYTES),m_t,fin_cip); // Variable length array. Can't get rid of this memcpy.
	*mlen = mf*CRYPTO_KEYBYTES + fin_cip;
	
	
	// Verification
	
	u128 MM1,Cv,ver,C1,_2W;
	delta = mul2(delta); 
	deltaC =  mul2(deltaC);
	
	int good = 0;
	MM1 = delta^M1; // _mm_xor_si128(delta,M1);
	
	/*X = */ENCRYPT1(MM1,X); // encypt_block_d(MM1);
	_2W = mul2(W);
	Y = X^(W^_2W); // _mm_xor_si128( X,  _mm_xor_si128(W,_2W) ); 
	W = X^_2W; // _mm_xor_si128( X,  _2W ); 
	/*CC = */ENCRYPT1(Y,CC); //  encypt_block_d(Y);
	Cv = CC^deltaC; // _mm_xor_si128(CC,deltaC);
	C1 = LOAD(c+numblocks_cip*CRYPTO_KEYBYTES);
	ver = C1^Cv; // _mm_xor_si128(C1,Cv);
	if(!(fin_cip%16)) 
	{
		// printf("Please tell me we're here\n");
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

#define LENGTH 164

int main(){

	/*FILE *fp;
	fp = fopen("infile128.txt","r");
	if(fp==NULL){printf("Couldn't open file. Terminating\n");return 0;}
	fseek(fp, 0L, SEEK_END);
	u64 sz = ftell(fp);
	rewind(fp);*/
	int i;
	
	u64 mlen = LENGTH;
	u8 pt[LENGTH] = "@@@@nwlrbbmqbhcdarzowkkyhiddqscdxrjmowfrxsjybldbefsarcbynecdyggxxpklorellnmpapqfwkhopkmcoqhnwnkuewhsqmgbbuqcljjivswmdkqtbxixmvtrrbljptnsnfwzqfjmafadfedcba9876543210"; 
	/////////////////////////////////////////////////
	//u8 *pt = malloc(sz);
	// u8 pt[80] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
	u8 ch;
	u64 j=0;
	/*while ( j<sz) 
	{
		ch = fgetc(fp);
		*(pt+j) = (unsigned char)ch;
		++j;
	}
	fclose(fp);*/
	
	u8 ct[LENGTH + CRYPTO_ABYTES]; //  = malloc(sz + CRYPTO_ABYTES);
	u8 key[CRYPTO_KEYBYTES] = "keykeykeykeykey!";
	u8 ad[162] = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210!!";
	u8 nonce[8] = "WTFnonce";
	// u64 mlen = 80;
	u64 clen,olen;
	u8 out[LENGTH]; // = malloc(sz);
	
	/*FILE *resdump;
	resdump = fopen("COLM_ARM_16384","w");
	for(j=0;j<200;++j){
		TIME_IT("COLM_ARM",crypto_aead_encrypt(&ct,&clen,&pt,mlen,&ad,144,0x00,&nonce,&key),mlen,1);
	}
	fclose(resdump);*/
	// printf("sz is %lu\n",sz);
	
	crypto_aead_encrypt(&ct,&clen,&pt,mlen,&ad,162,0x00,&nonce,&key);
	// printf("Entering decrypt\n");
	int ver = crypto_aead_decrypt(&out,&olen,0x00,&ct,clen,&ad,162,&nonce,&key);
       

	// printf("Lenght of the cipher is %d, length of the output is %d\n",clen,olen);
	if(!ver){
		printf("Verification succeeds\n");
		/* for(j=0;j<olen/16;++j){for(i=0;i<16;++i){
			printf("%d ",out[16*j+i]); }printf("\n");
		}// */
	}
	else{
		printf("Verification fails\n");
		for(i=0;i<164;++i){
			printf("%c",out[i]); 
		} 
	} 
	printf("\n"); 
	
	return 0;
}
