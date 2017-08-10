#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include <arm_neon.h>

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
	fprintf(resdump,"%g\n" /*cpb\n"*/, total_clk/(nbytes)/(MULTIPLE));
	
/*Globals and auxiliary functions*/

u128 keys[16];

const unsigned char rcon[17] = {0x2f,0x5e,0xbc,0x63,0xc6,0x97,0x35,0x6a,0xd4,0xb3,0x7d,0xfa,0xef,0xc5,0x91,0x39,0x72};

u128 h;

void print128_asint(const u128 in){
	printf("%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n",in[0],in[1],in[2],in[3],in[4],in[5],in[6],in[7],in[8],in[9],in[10],in[11],in[12],in[13],in[14],in[15]); 
}

u128 LFSR2(u128 k) 
{
	// u8 mh[16] = {0xfe,0xfe,0xfe,0xfe, 0xfe,0xfe,0xfe,0xfe, 0xfe,0xfe,0xfe,0xfe, 0xfe,0xfe,0xfe,0xfe};
	// u8 ml[16] = {0x01,0x01,0x01,0x01, 0x01,0x01,0x01,0x01, 0x01,0x01,0x01,0x01, 0x01,0x01,0x01,0x01};
	u128 mask_high = /*cov*/ {0xfe,0xfe,0xfe,0xfe, 0xfe,0xfe,0xfe,0xfe, 0xfe,0xfe,0xfe,0xfe, 0xfe,0xfe,0xfe,0xfe}; // LOAD(mh);
	u128 mask_low  = {0x01,0x01,0x01,0x01, 0x01,0x01,0x01,0x01, 0x01,0x01,0x01,0x01, 0x01,0x01,0x01,0x01}; // LOAD(ml);
	u128 tmp1 = SL(k,1);
	tmp1 = mask_high & tmp1;
	u128 tmp2 = SR(k,7);
	tmp2 = mask_low & tmp2;
	u128 tmp = tmp1^tmp2;
	u128 tmp3 = SR(k,5);
	tmp3 = mask_low & tmp3;
	return tmp^tmp3;
} // */ 

void generate_keys_new(u128 key) 
{
	// u8 zero[16] = {0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,  0x00,0x00,0x00,0x00,  0x00,0x00,0x00,0x00};
	u128 zero = {0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,  0x00,0x00,0x00,0x00,  0x00,0x00,0x00,0x00};
	keys[15] = zero;  // LOAD(zero);
	// u8 RCA[16] = {0x01,0x02,0x04,0x08,rcon[0],rcon[0],rcon[0],rcon[0],0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	u128 RC = {0x01,0x02,0x04,0x08,rcon[0],rcon[0],rcon[0],rcon[0],0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}; // LOAD(RCA);
	keys[0] = key^RC; //  _mm_xor_si128(RC,key);
	int i;
	for(i=1;i<=14;++i)
	{
		key = PERMUTE(key,h); // PERMUTE(key,h);
		key = LFSR2(key);
		RC[4] = rcon[i];RC[5] = rcon[i];RC[6] = rcon[i];RC[7] = rcon[i];
		keys[i] = key^RC; //  _mm_xor_si128(RC,key);
	}
} // */ 

u128 mul2(u128 x)
{
	// u8 shift_mask[16] = {0x01,0x02,0x03,0x04, 0x05,0x06,0x07,0x08, 0x09,0x0a,0x0b,0x0c, 0x0d,0x0e,0x0f,0x0f};
	// u8 right_mask[16] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0x00};
	// u8 rijn[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x1b};
	u128 red = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x1b}; // LOAD(rijn);
	u128 sm = {0x01,0x02,0x03,0x04, 0x05,0x06,0x07,0x08, 0x09,0x0a,0x0b,0x0c, 0x0d,0x0e,0x0f,0x0f}; // LOAD(shift_mask);
	u128 ca = SR(x,7);
	u128 r_shift = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0x00}; // LOAD(right_mask);
	// u8 cmp[16] = {0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff};
	u128 CMPT = {0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff}; // LOAD(cmp);
	u128 check = vcgtq_u8(ca, CMPT); /*Check if ca > CMPT, which is only possible on the first register*/
	check = PERMUTE(check,r_shift); /* Set up to and with rijndael polynomial*/
	u128 o = SL(x,1);
	ca = PERMUTE(ca,sm);
	ca = ca & r_shift; /* Reuse to avoid loading twice. ca may be 0x01 in the rightmost register, and this absolutely needs to be 0. */
	o = o | ca;
	int i;
	o = o^(red & check);
	return o;
	
	
} // */ 

int check_zero(u128 v)
{
	unsigned char c_arr[CRYPTO_KEYBYTES];
	STORE(c_arr,v); // ( (/*Check RHS first*/u128 *)&c_arr[0], v );
	for(int i=0;i<CRYPTO_KEYBYTES;++i)
	{
		if(c_arr[i] != 0x00)
		{
			return 0;
		}
	}
	return 1;
}


u128 encr_one_block(u128 pt, u128 tweak) // Old one-block function
{
	u128 tmp = keys[0]^tweak; // _mm_xor_si128(keys[0],tweak); // Round key
	u128 ct = tmp^pt; // _mm_xor_si128(tmp,pt); // Ciphertext
	u128 tweaks[8];
	tweaks[0] = tweak;
	u8 i;
	for(i=1;i<8;++i){
		tweaks[i] = PERMUTE(tweaks[0],h);
	}
	for(i=1;i<8;++i){
		tmp = keys[i]^tweaks[i];
		ct = ENC(ct,tmp);
		ct = MC(ct);
	}
	for(i=8;i<15;++i){
		tmp = keys[i]^tweaks[i-8];
		ct = ENC(ct,tmp);
		ct = MC(ct);
	}
	return ct;
}


int crypto_aead_encrypt(
       unsigned char *c,unsigned long long *clen, // c = cipher, clen = cipher length - not const, as they may change in size.
       const unsigned char *m,unsigned long long mlen,
       const unsigned char *ad,unsigned long long adlen, // To whoever is behind the CAESAR competition - THANK YOU
       const unsigned char *nsec, // = param??
       const unsigned char *npub, // = nonce
       const unsigned char *k
     )
{
	u8 h_mask[16] = {0x07, 0x00, 0x0d, 0x0a,  0x0b, 0x04, 0x01, 0x0e,  0x0f, 0x08, 0x05, 0x02, 0x03, 0x0c, 0x09, 0x06};
	h = LOAD(h_mask); // BFD
	unsigned char tweak[CRYPTO_KEYBYTES] = "What is a tweak?"; // Couldn't resist ;) 
	u128 key = LOAD(k);
	generate_keys_new(key);
	
	
	u128 auth = keys[15]; // keys[15];
	
	unsigned long long numblocks_ad = adlen/CRYPTO_KEYBYTES;
	unsigned long long numblocks_mes = mlen/CRYPTO_KEYBYTES;
	int fin_ad = adlen%CRYPTO_KEYBYTES;
	int fin_mes = mlen%CRYPTO_KEYBYTES;
	u64 i,j,y;
	int z;
		
	/*u8 ad_mask[16]  = {0x20,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0  ,0x0,0x0,0x0,0x0};
	u8 tag_mask[16]  = {0x40,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0  ,0x0,0x0,0x0,0x0};
	u8 MSB_mask[16]  = {0x80,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0  ,0x0,0x0,0x0,0x0};*/
	// u8 i1[16] = {0x0,0x0,0,0x0, 0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x01};
	u128 ad_reg = {0x20,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0  ,0x0,0x0,0x0,0x0}; // LOAD(ad_mask);
	u128 tag_fin = {0x40,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0  ,0x0,0x0,0x0,0x0}; // LOAD(tag_mask);
	u128 MSB1 = {0x80,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0  ,0x0,0x0,0x0,0x0}; // LOAD(MSB_mask);
	// u8 prop_a[16] = {0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x08,0x0,0x0,0x0  ,0x0,0x0,0x0,0x0};
	u128 prop = {0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x08,0x0,0x0,0x0  ,0x0,0x0,0x0,0x0}; // LOAD(prop_a);
	// u8 prop_ma[16] =  {8,9,10,11,12,13,14,15,  0,1,2,3,4,5,6,7};
	u128 prop_mask = {8,9,10,11,12,13,14,15,  0,1,2,3,4,5,6,7}; // LOAD(prop_ma); 
	// /*Check RHS first*/u128 zero = keys[15];
	// u8 nonce_a[16] = {0x10,npub[14],npub[13],npub[12],npub[11],npub[10],npub[9],npub[8],npub[7],npub[6],npub[5],npub[4],npub[3],npub[2],npub[1],npub[0]};
	u128 nonce = {0x10,npub[14],npub[13],npub[12],npub[11],npub[10],npub[9],npub[8],npub[7],npub[6],npub[5],npub[4],npub[3],npub[2],npub[1],npub[0]}; // LOAD(nonce_a);
	u128 one = {0x0,0x0,0,0x0, 0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x01}; // LOAD(i1); 
	
	// /*Check RHS first*/u128 h = _mm_set_epi8( 7,0,13,10, 11,4,1,14, 15,8,5,2, 3,12,9,6 );
	u128 idx,tmp,ctr;
	u8 A_star[CRYPTO_KEYBYTES];
	u8 M_star[CRYPTO_KEYBYTES];
	
	// Additional data
	
	/*Those that remain 8 are to be permuted*/
	u128 eight[8],tweaks[8],xx[PARA-1],z_s[8][PARA-1],mes[PARA],tweaks_sin[8];
	
	// tmp = one;
	tweaks[0] = ad_reg; 
	// u8 eight_arr[16] =  {0x0,0x0,0,0x0, 0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x0,0x0,0x0,PARA};
	u128 eight1 = {0x0,0x0,0,0x0, 0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x0,0x0,0x0,PARA};
	eight[0] = eight1; // LOAD(eight_arr); 
	
	for(i=0;i<8;++i)
	{
		z_s[i][0] = ADD(one,keys[15]);
		for(j=1;j<PARA-1;++j){
			
			z_s[i][j] = ADD(one,z_s[i][j-1]);
		}
		one = PERMUTE(one,h);
		
	} // */
	
	for(i=1;i<8;++i){
		tweaks[i] = PERMUTE(tweaks[i-1],h);
		eight[i] = PERMUTE(eight[i-1],h);
	}
	
	
	
	z = 0;
	
	int t_off=0;
	int fin_encr = numblocks_ad%4;
	int sin = 1;
	if(!fin_encr){
		sin = 0;
	}
	// printf("%d\n",numblocks_ad-(4*sin));
	for(i=0;i<numblocks_ad-(4*sin);i+=4)
	{
		for(j=0;j<PARA;++j){
			mes[j] = LOAD(ad+(i+j)*CRYPTO_KEYBYTES);
		}
		
		tmp = keys[0]^tweaks[0];

		mes[0] = mes[0]^tmp; //  _mm_xor_si128(mes[0],tmp);
		for(j=1;j<PARA;++j){
			mes[j] = mes[j]^tmp^z_s[0][j-1]; //  _mm_xor_si128(mes[j], _mm_xor_si128(tmp,z_s[0][j-i]) );
		}
		
		for(j=1;j<8;++j){
			tmp = keys[j]^tweaks[j];
			for(y=0;y<PARA-1;++y){
				xx[y] = tmp^z_s[j][y]; //  _mm_xor_si128(tmp,z_s[j][z]); 
				
			}
			ONEROUND(mes);
		
		}
		
		for(j=8;j<15;++j){
			tmp = keys[j]^tweaks[j-8];
			for(y=0;y<PARA-1;++y){
				xx[y] = tmp^z_s[j-8][y]; //  _mm_xor_si128(tmp,z_s[j][z]); 
			}
			ONEROUND(mes);
		}
		
		if(z==31)
		{
			z=0;
			
			tweaks[0] = PERMUTE(tweaks[0],prop_mask);
			tweaks[0] = ADD(tweaks[0],prop);
			for(j=1;j<8;++j){ 
				tweaks[j] = PERMUTE(tweaks[j],h);
			}
		}
		else
		{
			for(j=0;j<8;++j){
				tweaks[j] = ADD(tweaks[j],eight[j]);
			}
			
			++z;
		} // */
	
		for(j=0;j<PARA;++j){
			auth =auth^mes[j];
			
		}
		// auth = mes[0]^mes[1]^mes[2]^mes[3]^mes[4]^mes[5]^mes[6]^mes[7]^auth;
	} 
	
	ctr = keys[15];
	for(i=0;i<fin_encr;++i){
		
		if(t_off>0){ctr = z_s[0][t_off-1];}
		tmp = keys[0]^(ctr^tweaks[0]);
		mes[0] = LOAD(ad+(i+numblocks_ad-fin_encr)*CRYPTO_KEYBYTES);
		mes[0] = tmp^mes[0];

		tweaks_sin[0] = ctr^tweaks[0];
		tweaks_sin[1] = PERMUTE(tweaks_sin[0],h);
		tweaks_sin[2] = PERMUTE(tweaks_sin[1],h);
		tweaks_sin[3] = PERMUTE(tweaks_sin[2],h);
		tweaks_sin[4] = PERMUTE(tweaks_sin[3],h);
		tweaks_sin[5] = PERMUTE(tweaks_sin[4],h);
		tweaks_sin[6] = PERMUTE(tweaks_sin[5],h);
		tweaks_sin[7] = PERMUTE(tweaks_sin[6],h);
	
		xx[0] = keys[1]^tweaks_sin[1];
		xx[1] = keys[2]^tweaks_sin[2];
		xx[2] = keys[3]^tweaks_sin[3];
		mes[0] = ENC(mes[0],xx[0]);
		mes[0] = ENC(mes[0],xx[1]);
		mes[0] = ENC(mes[0],xx[2]);
	
		xx[0] = keys[4]^tweaks_sin[4];
		xx[1] = keys[5]^tweaks_sin[5];
		xx[2] = keys[6]^tweaks_sin[6];
		mes[0] = ENC(mes[0],xx[0]);
		mes[0] = ENC(mes[0],xx[1]);
		mes[0] = ENC(mes[0],xx[2]);
	
		xx[0] = keys[7]^tweaks_sin[7];
		xx[1] = keys[8]^tweaks_sin[0];
		xx[2] = keys[9]^tweaks_sin[1];
		mes[0] = ENC(mes[0],xx[0]);
		mes[0] = ENC(mes[0],xx[1]);
		mes[0] = ENC(mes[0],xx[2]);
	
		xx[0] = keys[10]^tweaks_sin[2];
		xx[1] = keys[11]^tweaks_sin[3];
		xx[2] = keys[12]^tweaks_sin[4];
		mes[0] = ENC(mes[0],xx[0]);
		mes[0] = ENC(mes[0],xx[1]);
		mes[0] = ENC(mes[0],xx[2]);
	
		xx[1] = keys[13]^tweaks_sin[5];
		xx[2] = keys[14]^tweaks_sin[6];
		mes[0] = ENC(mes[0],xx[0]);
		mes[0] = ENC(mes[0],xx[1]);
		++t_off;
		
		auth = auth^mes[0];
		print128_asint(auth);
	}
	
	if(fin_ad)
	{
		memcpy(A_star,ad+numblocks_ad*CRYPTO_KEYBYTES,fin_ad);
		A_star[fin_ad] = 0x80;
		memset(A_star+fin_ad+1,0,CRYPTO_KEYBYTES-(fin_ad+1));
		mes[0] = LOAD(A_star);
		if(t_off>0){ctr = z_s[0][t_off-1];}
		idx = tag_fin^(ctr^tweaks[0]) ; /* tweaks[0] = current index, since it is incremented at end*/
		
		tweaks[0] = idx; 
		
		tmp = (keys[0]^tweaks[0]); // Round key
		idx = (tmp^mes[0]); 
	
		tweaks[1] = PERMUTE(tweaks[0],h); // Remember to reset tweaks
		tweaks[2] = PERMUTE(tweaks[1],h);
		tweaks[3] = PERMUTE(tweaks[2],h);
		tweaks[4] = PERMUTE(tweaks[3],h);
		tweaks[5] = PERMUTE(tweaks[4],h);
		tweaks[6] = PERMUTE(tweaks[5],h);
		tweaks[7] = PERMUTE(tweaks[6],h);
	
		tmp = keys[1]^tweaks[1]; 
		idx = ENC(idx,tmp);
		tmp = keys[2]^tweaks[2]; 
		idx = ENC(idx,tmp);
		tmp = keys[3]^tweaks[3]; 
		idx = ENC(idx,tmp);
		tmp = keys[4]^tweaks[4]; 
		idx = ENC(idx,tmp);
		tmp = keys[5]^tweaks[5]; 
		idx = ENC(idx,tmp);
		tmp = keys[6]^tweaks[6]; 
		idx = ENC(idx,tmp);
		tmp = keys[7]^tweaks[7]; 
		idx = ENC(idx,tmp);
		tmp = keys[8]^tweaks[0]; 
		idx = ENC(idx,tmp);
		tmp = keys[9]^tweaks[9]; 
		idx = ENC(idx,tmp);
		tmp = keys[10]^tweaks[10]; 
		idx = ENC(idx,tmp);
		tmp = keys[11]^tweaks[11]; 
		idx = ENC(idx,tmp);
		tmp = keys[12]^tweaks[12]; 
		idx = ENC(idx,tmp);
		tmp = keys[13]^tweaks[13]; 
		idx = ENC(idx,tmp);
		tmp = keys[14]^tweaks[14]; 
		idx = ENC(idx,tmp);
	
		/* end of encrypt_block*/
		
		auth = idx^auth;
	}
	
	
	/*if(fin_ad) 
	{
		memcpy(A_star,ad+numblocks_ad*CRYPTO_KEYBYTES,fin_ad);
		A_star[fin_ad] = 0x80;
		memset(A_star+fin_ad+1,0,CRYPTO_KEYBYTES-(fin_ad+1));
		mes[0] = LOAD(A_star);
		idx = tweaks[0]^tag_fin; // tweaks[0] = current index, since it is incremented at end
		// tmp = encrypt_block(mes[0],idx);
		
		
		tweaks[0] = idx; 
		
		tmp = keys[0]^tweaks[0]; //  _mm_xor_si128(keys[0],tweaks[0]); // Round key
		idx = tmp^mes[0]; //   _mm_xor_si128(tmp,mes[0]); 
	
		for(i=1;i<8;++i){
			tweaks[i]=PERMUTE(tweaks[i-1],h);
		}
		
		
		for(i=1;i<8;++i){
			tmp = keys[i]^tweaks[i]; //  _mm_xor_si128(keys[1],tweaks[1]);
			idx = idx^tmp; // _mm_aesenc_si128(idx,tmp);
		}
		for(i=8;i<15;++i){
			tmp = keys[i]^tweaks[i-8]; //  _mm_xor_si128(keys[1],tweaks[1]);
			idx = idx^tmp; // _mm_aesenc_si128(idx,tmp);
		}
	
	
		
		auth = auth^idx; // auth =  _mm_xor_si128(auth,idx);
	}*/

	// Tag generation
	
	/*And I definitely need to so something about this*/
	
	for(i=0;i<8;++i){ /* Shuffling a zero would be a pointless exercise */
		tweaks[i] = keys[15];
	}
	
	
	u128 tag = auth; 

	// idx = zero;
	t_off=0;
	fin_encr = numblocks_mes%4;
	sin = 1;
	if(!fin_encr){
		sin = 0;
	}
	z = 0;
	for(i=0;i<(numblocks_mes-4*sin);i+=4)  
	{
		for(j=0;j<PARA;++j){
			mes[j] = LOAD(m+(i+j)*CRYPTO_KEYBYTES);
		}
		
		
		
		tmp = keys[0]^tweaks[0]; //  _mm_xor_si128(keys[0],tweaks[0]);
		
		for(j=0;j<PARA-1;++j){
			xx[j] = tmp^z_s[0][j];
		}
		mes[0] = mes[0]^tmp; //  _mm_xor_si128(mes[0],tmp);
		for(j=1;j<PARA;++j){
			mes[j] = mes[j]^xx[j-1];
		}
		
			
		for(j=1;j<8;++j){
			tmp = keys[j]^tweaks[j];
			for(y=0;y<PARA-1;++y){
				xx[y] = tmp^z_s[j][y]; //  _mm_xor_si128(tmp,z_s[j][z]); 
			}
			ONEROUND(mes);
		
		}
		for(j=8;j<15;++j){
			tmp = keys[j]^tweaks[j-8];
			for(y=0;y<PARA-1;++y){
				xx[y] = tmp^z_s[j-8][y]; //  _mm_xor_si128(tmp,z_s[j][z]); 
			}
			ONEROUND(mes);
		}
			
		
		if(z==31)
		{
			z=0;
			
			tweaks[0] = PERMUTE(tweaks[0],prop_mask);
			tweaks[0] = ADD(tweaks[0],prop);
			for(j=1;j<8;++j){
				tweaks[j] = PERMUTE(tweaks[j-1],h);
			}

		}
		else
		{
			for(j=0;j<8;++j){
				tweaks[j] = ADD(tweaks[j],eight[j]);
			}
			
			++z;
		} // */
		
		for(j=0;j<PARA;++j){
			tag = tag^mes[j];
		}
	}
	ctr = keys[15];
	for(i=0;i<fin_encr;++i){
		if(t_off>0){ctr = z_s[0][t_off-1];}
		tmp = keys[0]^(ctr^tweaks[0]);
		mes[0] = LOAD(m+(i+numblocks_mes-fin_encr)*CRYPTO_KEYBYTES);
		mes[0] = tmp^mes[0];

		tweaks_sin[0] = ctr^tweaks[0];
		tweaks_sin[1] = PERMUTE(tweaks_sin[0],h);
		tweaks_sin[2] = PERMUTE(tweaks_sin[1],h);
		tweaks_sin[3] = PERMUTE(tweaks_sin[2],h);
		tweaks_sin[4] = PERMUTE(tweaks_sin[3],h);
		tweaks_sin[5] = PERMUTE(tweaks_sin[4],h);
		tweaks_sin[6] = PERMUTE(tweaks_sin[5],h);
		tweaks_sin[7] = PERMUTE(tweaks_sin[6],h);
	
		xx[0] = keys[1]^tweaks_sin[1];
		xx[1] = keys[2]^tweaks_sin[2];
		xx[2] = keys[3]^tweaks_sin[3];
		mes[0] = ENC(mes[0],xx[0]);
		mes[0] = ENC(mes[0],xx[1]);
		mes[0] = ENC(mes[0],xx[2]);
	
		xx[0] = keys[4]^tweaks_sin[4];
		xx[1] = keys[5]^tweaks_sin[5];
		xx[2] = keys[6]^tweaks_sin[6];
		mes[0] = ENC(mes[0],xx[0]);
		mes[0] = ENC(mes[0],xx[1]);
		mes[0] = ENC(mes[0],xx[2]);
	
		xx[0] = keys[7]^tweaks_sin[7];
		xx[1] = keys[8]^tweaks_sin[0];
		xx[2] = keys[9]^tweaks_sin[1];
		mes[0] = ENC(mes[0],xx[0]);
		mes[0] = ENC(mes[0],xx[1]);
		mes[0] = ENC(mes[0],xx[2]);
	
		xx[0] = keys[10]^tweaks_sin[2];
		xx[1] = keys[11]^tweaks_sin[3];
		xx[2] = keys[12]^tweaks_sin[4];
		mes[0] = ENC(mes[0],xx[0]);
		mes[0] = ENC(mes[0],xx[1]);
		mes[0] = ENC(mes[0],xx[2]);
	
		xx[0] = keys[13]^tweaks_sin[5];
		xx[1] = keys[14]^tweaks_sin[6];
		mes[0] = ENC(mes[0],xx[0]);
		mes[0] = ENC(mes[0],xx[1]);
		++t_off;
		
		tag = tag^mes[0];
	}
	
	if(fin_mes) 
	{
		memcpy(M_star,m+numblocks_mes*CRYPTO_KEYBYTES,fin_mes);
		M_star[fin_mes] = 0x80;
		memset(M_star+fin_mes+1,0,CRYPTO_KEYBYTES-(fin_mes+1));
		mes[0] = LOAD(M_star);
		if(t_off>0){ctr = z_s[0][t_off-1];}
		idx = tag_fin^(ctr^tweaks[0]);
		
		tweaks_sin[0] = idx; /*I don't remember the rationale behind this, but I'm afraid to remove it.*/
		
		tmp = keys[0]^tweaks_sin[0]; // Round key
		idx = tmp^mes[0]; // Counting coppers
		
		
		tweaks_sin[1] = PERMUTE(tweaks_sin[0],h); 
		tweaks_sin[2] = PERMUTE(tweaks_sin[1],h);
		tweaks_sin[3] = PERMUTE(tweaks_sin[2],h);
		tweaks_sin[4] = PERMUTE(tweaks_sin[3],h);
		tweaks_sin[5] = PERMUTE(tweaks_sin[4],h);
		tweaks_sin[6] = PERMUTE(tweaks_sin[5],h);
		tweaks_sin[7] = PERMUTE(tweaks_sin[6],h);
		
		xx[0] = keys[1]^tweaks_sin[1];
		xx[1] = keys[2]^tweaks_sin[2];
		xx[2] = keys[3]^tweaks_sin[3];
		idx = ENC(idx,xx[0]);
		idx = ENC(idx,xx[1]);
		idx = ENC(idx,xx[2]);
	
		xx[0] = keys[4]^tweaks_sin[4];
		xx[1] = keys[5]^tweaks_sin[5];
		xx[2] = keys[6]^tweaks_sin[6];
		idx = ENC(idx,xx[0]);
		idx = ENC(idx,xx[1]);
		idx = ENC(idx,xx[2]);
	
		xx[0] = keys[7]^tweaks_sin[7];
		xx[1] = keys[8]^tweaks_sin[0];
		xx[2] = keys[9]^tweaks_sin[1];
		idx = ENC(idx,xx[0]);
		idx = ENC(idx,xx[1]);
		idx = ENC(idx,xx[2]);
	
		xx[0] = keys[10]^tweaks_sin[2];
		xx[1] = keys[11]^tweaks_sin[3];
		xx[2] = keys[12]^tweaks_sin[4];
		idx = ENC(idx,xx[0]);
		idx = ENC(idx,xx[1]);
		idx = ENC(idx,xx[2]);
	
		xx[0] = keys[13]^tweaks_sin[5];
		xx[1] = keys[14]^tweaks_sin[6];
		idx = ENC(idx,xx[0]);
		idx = ENC(idx,xx[1]);

		tag = tag^idx;
		
	}
	/*if(fin_mes) 
	{
		memcpy(M_star,m+numblocks_mes*CRYPTO_KEYBYTES,fin_mes);
		M_star[fin_mes] = 0x80;
		memset(M_star+fin_mes+1,0,CRYPTO_KEYBYTES-(fin_mes+1));
		mes[0] = LOAD(M_star);
		idx = tag_fin^tweaks[0]; //  _mm_xor_si128(tag_fin,tweaks[0]);

		
				
		tweaks[0] = idx; 
		
		tmp = keys[0]^tweaks[0]; //  _mm_xor_si128(keys[0],tweaks[0]); // Round key
		idx = tmp^mes[0]; //  _mm_xor_si128(tmp,mes[0]); // Counting coppers
	
		for(i=1;i<8;++i){
			tweaks[i] = PERMUTE(tweaks[0],h); 
		}
		
		for(i=1;i<8;++i){
			tmp = keys[i]^tweaks[i]; //  _mm_xor_si128(keys[i],tweaks[i]); 
			idx = ENC(idx, tmp); // _mm_aesenc_si128(idx,tmp);
			idx = MC(idx);
		}
		for(i=8;i<15;++i){
			// tmp =  _mm_xor_si128(keys[i],tweaks[i-8]); 
			// idx = _mm_aesenc_si128(idx,tmp);
			tmp = keys[i]^tweaks[i-8]; //  _mm_xor_si128(keys[i],tweaks[i]); 
			idx = ENC(idx, tmp); // _mm_aesenc_si128(idx,tmp);
			idx = MC(idx);
		}
		
		tag = tag^idx; //  _mm_xor_si128(tag,idx);
		
	}*/

	/* end of encrypt_block*/
	tag = encr_one_block(tag,nonce);
	STORE(c+(numblocks_mes*CRYPTO_KEYBYTES+fin_mes),tag ); //  (u128 *)&c[numblocks_mes*CRYPTO_KEYBYTES+fin_mes]
	
	// nonce_a[0] = 0x00;
	nonce[0] = 0x00;
	// nonce = LOAD(nonce_a); //  _mm_set_epi8(0x00,npub[14],npub[13],npub[12],npub[11],npub[10],npub[9],npub[8],npub[7],npub[6],npub[5],npub[4],npub[3],npub[2],npub[1],npub[0]);
	// print128_asint(nonce);
	u128 one_tag = tag | MSB1; //  _mm_or_si128(tag,MSB1);
	for(i=0;i<8;++i){
		tweaks[i] = keys[15]; // zero; 
	}

	for(i=0;i<7;++i)
	{
		keys[i] = (keys[i]^one_tag);
		keys[i+8] = (keys[i+8]^one_tag);
		one_tag = PERMUTE(one_tag,h);
	} // */ 
	
	keys[7] = (keys[7]^one_tag); /*Getting rid of a shuffle and pipelining some xor's*/
	one_tag = PERMUTE(one_tag,h);
	
	// Encryption
	
	unsigned char C_star[CRYPTO_KEYBYTES];
	u128 N[PARA];
	z = 0;
	// idx = zero; // keys[15];
	// printf("Nonce at enc loop ");print128_asint(nonce);
	t_off = 0;
	for(i=0;i<(numblocks_mes-sin*4);i+=PARA)
	{
		
		tmp = tweaks[0]^keys[0]; 
		
		N[0] = nonce^tmp; //  _mm_xor_si128(nonce,tmp );
		for(j=1;j<PARA;++j){
			N[j] = N[0]^z_s[0][j-1]; //  _mm_xor_si128(N[0],z_s[0][j-1] );
		}
				
			for(j=1;j<8;++j){
				tmp = keys[j]^tweaks[j];
				for(y=0;y<PARA-1;++y){
					xx[y] = tmp^z_s[j][y]; //  _mm_xor_si128(tmp,z_s[j][y]);
				}
				ONEROUND(N);
			}
			for(j=8;j<15;++j){
				tmp = keys[j]^tweaks[j-8];
				for(y=0;y<PARA-1;++y){
					xx[y] = tmp^z_s[j-8][y]; // _mm_xor_si128(tmp,z_s[j][y]);
				}
				ONEROUND(N);
			}
		
		for(j=0;j<PARA;++j){
			mes[j] = LOAD(m+(i+j)*CRYPTO_KEYBYTES); 
		}
		
		for(j=0;j<PARA;++j){
			mes[j] = N[j]^mes[j]; 
		}
		
		for(j=0;j<PARA;++j){
			STORE( c+((i+j)*CRYPTO_KEYBYTES), mes[j] );
		}
		/* End of sticking blocks */
		
		if(z==31)
		{
			z=0;
			tweaks[0] = PERMUTE(tweaks[0],prop_mask);
			tweaks[0] = ADD(tweaks[0],prop);
			for(j=1;j<8;++j){
				tweaks[j] = PERMUTE(tweaks[j],h);
			}
		}
		else
		{
			for(j=0;j<8;++j){
				tweaks[j] = ADD(tweaks[j],eight[j]);
			}
			++z;
		} // */		
	}
	
	ctr = keys[15];
	for(i=0;i<fin_encr;++i){
		
		if(t_off>0){ctr = z_s[0][t_off-1];}
		tmp = keys[0]^(ctr^tweaks[0]);
		
		N[0] = tmp^nonce;
		mes[0] = LOAD(m+(i+numblocks_mes-fin_encr)*CRYPTO_KEYBYTES);

		tweaks_sin[0] = (ctr^tweaks[0]);
		tweaks_sin[1] = PERMUTE(tweaks_sin[0],h);
		tweaks_sin[2] = PERMUTE(tweaks_sin[1],h);
		tweaks_sin[3] = PERMUTE(tweaks_sin[2],h);
		tweaks_sin[4] = PERMUTE(tweaks_sin[3],h);
		tweaks_sin[5] = PERMUTE(tweaks_sin[4],h);
		tweaks_sin[6] = PERMUTE(tweaks_sin[5],h);
		tweaks_sin[7] = PERMUTE(tweaks_sin[6],h);
	
		xx[0] = keys[1]^tweaks_sin[1];
		xx[1] = keys[2]^tweaks_sin[2];
		xx[2] = keys[3]^tweaks_sin[3];
		N[0] = ENC(N[0],xx[0]);
		N[0] = ENC(N[0],xx[1]);
		N[0] = ENC(N[0],xx[2]);
	
		xx[0] = keys[4]^tweaks_sin[4];
		xx[1] = keys[5]^tweaks_sin[5];
		xx[2] = keys[6]^tweaks_sin[6];
		N[0] = ENC(N[0],xx[0]);
		N[0] = ENC(N[0],xx[1]);
		N[0] = ENC(N[0],xx[2]);
	
		xx[0] = keys[7]^tweaks_sin[7];
		xx[1] = keys[8]^tweaks_sin[0];
		xx[2] = keys[9]^tweaks_sin[1];
		N[0] = ENC(N[0],xx[0]);
		N[0] = ENC(N[0],xx[1]);
		N[0] = ENC(N[0],xx[2]);
	
		xx[0] = keys[10]^tweaks_sin[2];
		xx[1] = keys[11]^tweaks_sin[3];
		xx[2] = keys[12]^tweaks_sin[4];
		N[0] = ENC(N[0],xx[0]);
		N[0] = ENC(N[0],xx[1]);
		N[0] = ENC(N[0],xx[2]);
	
		xx[0] = keys[13]^tweaks_sin[5];
		xx[1] = keys[14]^tweaks_sin[6];
		N[0] = ENC(N[0],xx[0]);
		N[0] = ENC(N[0],xx[1]);
		++t_off;
		
		mes[0] = N[0]^mes[0];
		STORE( c+((i+numblocks_mes-fin_encr)*CRYPTO_KEYBYTES), mes[0] );
	}
	
	if(fin_mes) 
	{
		memcpy(M_star,m+numblocks_mes*CRYPTO_KEYBYTES,fin_mes);
		M_star[fin_mes] = 0x80;
		memset(M_star+fin_mes+1,0,CRYPTO_KEYBYTES-(fin_mes+1));
		mes[0] = LOAD(M_star);
		
		if(t_off>0){ctr = z_s[0][t_off-1];}
		tweaks[0] = (ctr^tweaks[0]); 
		
		tmp = (keys[0]^tweaks[0]); // Round key
		idx = (tmp^nonce); // Counting coppers
	
		tweaks[1] = PERMUTE(tweaks[0],h); 
		tweaks[2] = PERMUTE(tweaks[1],h);
		tweaks[3] = PERMUTE(tweaks[2],h);
		tweaks[4] = PERMUTE(tweaks[3],h);
		tweaks[5] = PERMUTE(tweaks[4],h);
		tweaks[6] = PERMUTE(tweaks[5],h);
		tweaks[7] = PERMUTE(tweaks[6],h);
	
		xx[0] = keys[1]^tweaks_sin[1];
		xx[1] = keys[2]^tweaks_sin[2];
		xx[2] = keys[3]^tweaks_sin[3];
		idx = ENC(idx,xx[0]);
		idx = ENC(idx,xx[1]);
		idx = ENC(idx,xx[2]);
	
		xx[0] = keys[4]^tweaks_sin[4];
		xx[1] = keys[5]^tweaks_sin[5];
		xx[2] = keys[6]^tweaks_sin[6];
		idx = ENC(idx,xx[0]);
		idx = ENC(idx,xx[1]);
		idx = ENC(idx,xx[2]);
	
		xx[0] = keys[7]^tweaks_sin[7];
		xx[1] = keys[8]^tweaks_sin[0];
		xx[2] = keys[9]^tweaks_sin[1];
		idx = ENC(idx,xx[0]);
		idx = ENC(idx,xx[1]);
		idx = ENC(idx,xx[2]);
	
		xx[0] = keys[10]^tweaks_sin[2];
		xx[1] = keys[11]^tweaks_sin[3];
		xx[2] = keys[12]^tweaks_sin[4];
		idx = ENC(idx,xx[0]);
		idx = ENC(idx,xx[1]);
		idx = ENC(idx,xx[2]);
	
		xx[0] = keys[13]^tweaks_sin[5];
		xx[1] = keys[14]^tweaks_sin[6];
		idx = ENC(idx,xx[0]);
		idx = ENC(idx,xx[1]);
			
		mes[0] = mes[0]^idx;

		STORE( C_star, mes[0] ); 
		memcpy(c+numblocks_mes*CRYPTO_KEYBYTES,C_star,fin_mes);
	}
	/*if(fin_mes) // Not sure what to do in this case. Until further notice, I'll just do 10* padding.
	{
		memcpy(M_star,m+numblocks_mes*CRYPTO_KEYBYTES,fin_mes);
		M_star[fin_mes] = 0x80;
		memset(M_star+fin_mes+1,0,CRYPTO_KEYBYTES-(fin_mes+1));
		mes[0] = LOAD(M_star);
		
		tweaks[0] = one_tag^tweaks[0]; // _mm_xor_si128(one_tag,tweaks[0]); 
		
		tmp = keys[0]^tweaks[0]; //  _mm_xor_si128(keys[0],tweaks[0]); // Round key
		idx = tmp^mes[0]; // _mm_xor_si128(tmp,mes[0]); // Counting coppers
	
		for(j=1;j<8;++j){
			tweaks[j] = PERMUTE(tweaks[j-1],h); 
		}
		
	
		for(j=1;j<8;++j){
			tmp = keys[j]^tweaks[j]; // mm_xor_si128(keys[j],tweaks[j]); // Test reorganizing this stuff
			idx = ENC(idx,tmp); // _mm_aesenc_si128(idx,tmp);
			idx = MC(idx);
		}
		for(j=8;j<15;++j){
			tmp = keys[j]^tweaks[j-8]; // mm_xor_si128(keys[j],tweaks[j]); // Test reorganizing this stuff
			idx = ENC(idx,tmp); // _mm_aesenc_si128(idx,tmp);
			idx = MC(idx);
		}

		mes[0] = mes[0]^idx; 
		STORE( C_star, mes[0] ); 
		memcpy(c+numblocks_mes*CRYPTO_KEYBYTES,C_star,fin_mes);
	}*/
	*clen = mlen+CRYPTO_ABYTES;
	return 0;
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
	// printf("Hello from decrypt\n");
	// Needs to be reinstated for the actual thing
	/*u8 h_mask[16] = {0x07, 0x00, 0x0d, 0x0a,  0x0b, 0x04, 0x01, 0x0e,  0x0f, 0x08, 0x05, 0x02, 0x03, 0x0c, 0x09, 0x06};
	h = LOAD(h_mask);*/
	unsigned char tweak[CRYPTO_KEYBYTES] = "What is a tweak?";
	u128 key = LOAD(k);
	generate_keys_new(key);
	
	
	unsigned long long numblocks_ad = adlen/CRYPTO_KEYBYTES;
	unsigned long long numblocks_cip = clen/CRYPTO_KEYBYTES;
	int fin_ad = adlen%CRYPTO_KEYBYTES;
	int fin_cip = clen%CRYPTO_KEYBYTES;
	u64 i,j,y;
	
	u8 ad_mask[16] = {0x20,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0  ,0x0,0x0,0x0,0x0};
	u128 ad_reg = LOAD(ad_mask);
	u8 MSB_mask[16] = {0x80,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0  ,0x0,0x0,0x0,0x0};
	u128 MSB1    = LOAD(MSB_mask); //  _mm_set_epi8(0x80,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0  ,0x0,0x0,0x0,0x0);
	u8 tag_mask[CRYPTO_KEYBYTES] = {0x40,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0  ,0x0,0x0,0x0,0x0};
	u128 tag_fin = LOAD(tag_mask); // _mm_set_epi8(0x40,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0  ,0x0,0x0,0x0,0x0);
	

	u8 nonce_arr[16] = {0x00,npub[14],npub[13],npub[12],npub[11],npub[10],npub[9],npub[8],npub[7],npub[6],npub[5],npub[4],npub[3],npub[2],npub[1],npub[0]};
	u128 nonce = LOAD(nonce_arr);
	
	u8 one_arr[16] = {0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x01};
	u128 one = LOAD(one_arr);
	// u128 one = _mm_set_epi8(0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1);
	u8 prop_a[16] = {0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x80,0x0,0x0,0x0  ,0x0,0x0,0x0,0x0};
	u128 prop    = LOAD(prop_a); //  _mm_set_epi8(0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x80,0x0,0x0,0x0  ,0x0,0x0,0x0,0x0);
	u8 prop_ma[16] = {0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
	u128 prop_mask = LOAD(prop_ma); //  _mm_set_epi8(8,9,10,11,12,13,14,15,  0,1,2,3,4,5,6,7  );
	u128 A,idx,M,C,tmp,ctr;
	unsigned char A_star[CRYPTO_KEYBYTES];
	unsigned char M_star[CRYPTO_KEYBYTES];
	unsigned char tmp_ar[CRYPTO_KEYBYTES];
	unsigned long long nbm = numblocks_cip-1;
	int z = 0;
	// printf("Declaring u128 arrays\n");
	u128 tweaks[8],z_s[8][PARA-1],eight[8],xx[PARA-1],mes[PARA],N[PARA],tweaks_sin[8];
	
	u128 auth = keys[15];
	
	// Initialization
	
	tmp = one; // Can be removed later. Kristian@later: Yeah, right...
	 /*Good */
	//  printf("Simple things done\n");
	for(i=0;i<8;++i)
	{
		z_s[i][0] = tmp; // ADD(tmp, keys[15]  ); // Why the fuck did I ever do this?
		for(j=1;j<PARA-1;++j){
			z_s[i][j] = ADD(tmp, z_s[i][j-1] );
		}
		tmp = PERMUTE(tmp,h);
	} // */

	for(i=0;i<8;++i){
		tweaks[i] = keys[15]; 
	}
	 // printf("tweaks up\n");

	
	u8 eight_arr[16] = {0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,PARA}; // The name "eight" is retained for legacy purposes
	eight[0] = LOAD(eight_arr); // _mm_set_epi8(0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,8); 
	for(i=1;i<8;++i){
		eight[i] = PERMUTE(eight[i-1],h); 
	}
	
	// Decryption
	u128 tag = LOAD(c+nbm*CRYPTO_KEYBYTES+fin_cip);
	u128 tag1 = tag | MSB1; // _mm_or_si128(tag,MSB1); // This truncating is silly.
	// printf("tag1: ");print128_asint(tag1);
	for(i=0;i<15;++i) 
	{
		keys[i] =  keys[i]^tag1; // _mm_xor_si128(keys[i],tag1);
		tag1 = PERMUTE(tag1,h);
	} 
	 // printf("Keys tagged\n");
	*mlen = clen-CRYPTO_KEYBYTES;
	
	// Decryption
	
	// /*Remember to double check*/u128 keys[15] = keys[15];
	idx = keys[15]; // keys[15];
	
	z = 0;
	
	int t_off=0;
	int fin_encr = nbm%4;
	int sin = 1;
	if(!fin_encr){
		sin = 0;
	}
	
	for(i=0;i<(nbm-PARA*sin);i+=PARA)
	{
		tmp = tweaks[0]^keys[0];  // _mm_xor_si128(tweaks[0] ,keys[0]);
		
		N[0] = nonce^tmp; //  _mm_xor_si128(nonce,tmp );
		for(j=1;j<PARA;++j){
			N[j] = N[0]^z_s[0][j-1];
		}
			
			for(j=1;j<8;++j){
				tmp = keys[j]^tweaks[j];
				for(y=0;y<PARA-1;++y){
					xx[y] = tmp^z_s[j][y];
				}
				ONEROUND(N);
			}
			for(j=8;j<15;++j){
				tmp = keys[j]^tweaks[j-8];
				for(y=0;y<PARA-1;++y){
					xx[y] = tmp^z_s[j-8][y];
				}
				ONEROUND(N);
			}	
		
		for(j=0;j<PARA;++j){
			mes[j] = LOAD(c+(i+j )*CRYPTO_KEYBYTES);
		}
			
		for(j=0;j<PARA;++j){
			mes[j] = N[j]^mes[j]; //  _mm_xor_si128(N[0],mes[0]); 
		}

		for(j=0;j<PARA;++j){
			STORE( m+((i+j)*CRYPTO_KEYBYTES), mes[j] ); // (u128 *)&m[(i  )*CRYPTO_KEYBYTES]
		}

		/* End of sticking blocks */
		
		if(z==31)
		{
			z=0;
			tweaks[0] = PERMUTE(tweaks[0],prop_mask);
			tweaks[0] = ADD(tweaks[0],prop);
			for(j=1;j<8;++j){
				tweaks[j] = PERMUTE(tweaks[j],h);
			}
		}
		else
		{	
			for(j=0;j<8;++j){
				tweaks[j] = ADD(tweaks[j],eight[j]);
			}
			++z;
		} // */		
	}
	
	ctr = keys[15];
	for(i=0;i<fin_encr;++i){
		if(t_off>0){ctr = z_s[0][t_off-1];}
		tmp = (keys[0]^(ctr^tweaks[0]) );
		
		N[0] = (tmp^nonce);
		mes[0] = LOAD(c+(i+nbm-fin_encr)*CRYPTO_KEYBYTES);
				
		tweaks_sin[0] = (ctr^tweaks[0]);
		tweaks_sin[1] = PERMUTE(tweaks_sin[0],h);
		tweaks_sin[2] = PERMUTE(tweaks_sin[1],h);
		tweaks_sin[3] = PERMUTE(tweaks_sin[2],h);
		tweaks_sin[4] = PERMUTE(tweaks_sin[3],h);
		tweaks_sin[5] = PERMUTE(tweaks_sin[4],h);
		tweaks_sin[6] = PERMUTE(tweaks_sin[5],h);
		tweaks_sin[7] = PERMUTE(tweaks_sin[6],h);
	
		xx[0] = (keys[1]^tweaks_sin[1]);
		xx[1] = (keys[2]^tweaks_sin[2]);
		xx[2] = (keys[3]^tweaks_sin[3]);
		N[0] = ENC(N[0],xx[0]);
		N[0] = ENC(N[0],xx[1]);
		N[0] = ENC(N[0],xx[2]);
	
		xx[0] = (keys[4]^tweaks_sin[4]);
		xx[1] = (keys[5]^tweaks_sin[5]);
		xx[2] = (keys[6]^tweaks_sin[6]);
		N[0] = ENC(N[0],xx[0]);
		N[0] = ENC(N[0],xx[1]);
		N[0] = ENC(N[0],xx[2]);
	
		xx[0] = (keys[7]^tweaks_sin[7]);
		xx[1] = (keys[8]^tweaks_sin[0]);
		xx[2] = (keys[9]^tweaks_sin[1]);
		N[0] = ENC(N[0],xx[0]);
		N[0] = ENC(N[0],xx[1]);
		N[0] = ENC(N[0],xx[2]);
	
		xx[0] = (keys[10]^tweaks_sin[2]);
		xx[1] = (keys[11]^tweaks_sin[3]);
		xx[2] = (keys[12]^tweaks_sin[4]);
		N[0] = ENC(N[0],xx[0]);
		N[0] = ENC(N[0],xx[1]);
		N[0] = ENC(N[0],xx[2]);
	
		xx[0] = (keys[13]^tweaks_sin[5]);
		xx[1] = (keys[14]^tweaks_sin[6]);
		N[0] = ENC(N[0],xx[0]);
		N[0] = ENC(N[0],xx[1]);
		++t_off;
		
		mes[0] = (N[0]^mes[0]);
		STORE( m+((i+nbm-fin_encr)*CRYPTO_KEYBYTES), mes[0] );
		
	}
	
	if(fin_cip) 
	{
		memcpy(M_star,c+nbm*CRYPTO_KEYBYTES,fin_cip); 
		
		M = LOAD(M_star);
		
		if(t_off>0){ctr = z_s[0][t_off-1];}
		idx = (ctr^tweaks[0]);
		
		C = M^(encr_one_block(nonce,(tag1^idx)));
		STORE( tmp_ar, C ); 
		memcpy(m+nbm*CRYPTO_KEYBYTES,tmp_ar,fin_cip);  
	}
		
	
	// Associated data
	
	tag1 = tag | MSB1; // _mm_or_si128(tag,MSB1); /* Untagging the nonce */
	// printf("tag1, all the way: ");print128_asint(tag1);
	
	for(i=0;i<7;++i)
	{
		keys[i] = (keys[i]^tag1);
		keys[i+8] = (keys[i+8]^tag1);
		tag1 = PERMUTE(tag1,h);
	} // */ 
	
	keys[7] = (keys[7]^tag1); /*Getting rid of a shuffle and pipelining some xor's*/
	tag1 = PERMUTE(tag1,h);
	
	tweaks[0] = ad_reg; /*Tweak reset*/
	for(i=1;i<8;++i){
		tweaks[i] = PERMUTE(tweaks[i-1],h);
	}
	
		
	fin_encr = numblocks_ad%4;
	sin = 1;
	if(!fin_encr){
		sin = 0;
	}
	z = 0;
	// printf("%d\n",numblocks_ad);
	for(i=0;i<numblocks_ad-(4*sin);i+=4)
	{
		for(j=0;j<PARA;++j){
			mes[j] = LOAD(ad+(i+j)*CRYPTO_KEYBYTES);
		}
		
		
		tmp = keys[0]^tweaks[0]; // _mm_xor_si128(keys[0],tweaks[0]);  
		
		mes[0] = mes[0]^tmp; // _mm_xor_si128(mes[0],tmp);
		for(j=1;j<PARA;++j){
			mes[j] =mes[j]^(tmp^z_s[0][j-1]);
		}
		
		for(j=1;j<8;++j){
			tmp = keys[j]^tweaks[j]; 
			for(y=0;y<PARA-1;++y){
				xx[y] = tmp^z_s[j][y];
			}
			ONEROUND(mes);
		}
		
		for(j=8;j<15;++j){
			tmp = keys[j]^tweaks[j-8]; 
			for(y=0;y<PARA-1;++y){
				xx[y] = tmp^z_s[j-8][y];
			}
			ONEROUND(mes);
		}
		
		
		if(z==31)
		{
			z=0;
			tweaks[0] = PERMUTE(tweaks[0],prop_mask);
			tweaks[0] = ADD(tweaks[0],prop);
			for(j=1;j<8;++j){ 
				tweaks[j] = PERMUTE(tweaks[j],h);
			}
			
		}
		else
		{
			for(j=0;j<8;++j){
				tweaks[j] = ADD(tweaks[j],eight[j]);
			}
			
			++z;
		} // */
	
		for(j=0;j<PARA;++j){
			auth = auth^mes[j]; 
			
		}
		
	}
	
	ctr = keys[15];
	for(i=0;i<fin_encr;++i){
	
		if(t_off>0){
			ctr = z_s[0][t_off-1];
		}
		
		tmp = (keys[0]^(ctr^tweaks[0]) );
		mes[0] = LOAD(ad+(i+numblocks_ad-fin_encr)*CRYPTO_KEYBYTES);
		mes[0] = (tmp^mes[0]);

		tweaks_sin[0] = (ctr^tweaks[0]);
		tweaks_sin[1] = PERMUTE(tweaks_sin[0],h);
		tweaks_sin[2] = PERMUTE(tweaks_sin[1],h);
		tweaks_sin[3] = PERMUTE(tweaks_sin[2],h);
		tweaks_sin[4] = PERMUTE(tweaks_sin[3],h);
		tweaks_sin[5] = PERMUTE(tweaks_sin[4],h);
		tweaks_sin[6] = PERMUTE(tweaks_sin[5],h);
		tweaks_sin[7] = PERMUTE(tweaks_sin[6],h);
	
		xx[0] = (keys[1]^tweaks_sin[1]);
		xx[1] = (keys[2]^tweaks_sin[2]);
		xx[2] = (keys[3]^tweaks_sin[3]);
		mes[0] = ENC(mes[0],xx[0]);
		mes[0] = ENC(mes[0],xx[1]);
		mes[0] = ENC(mes[0],xx[2]);
	
		xx[0] = (keys[4]^tweaks_sin[4]);
		xx[1] = (keys[5]^tweaks_sin[5]);
		xx[2] = (keys[6]^tweaks_sin[6]);
		mes[0] = ENC(mes[0],xx[0]);
		mes[0] = ENC(mes[0],xx[1]);
		mes[0] = ENC(mes[0],xx[2]);
	
		xx[0] = (keys[7]^tweaks_sin[7]);
		xx[1] = (keys[8]^tweaks_sin[0]);
		xx[2] = (keys[9]^tweaks_sin[1]);
		mes[0] = ENC(mes[0],xx[0]);
		mes[0] = ENC(mes[0],xx[1]);
		mes[0] = ENC(mes[0],xx[2]);
	
		xx[0] = (keys[10]^tweaks_sin[2]);
		xx[1] = (keys[11]^tweaks_sin[3]);
		xx[2] = (keys[12]^tweaks_sin[4]);
		mes[0] = ENC(mes[0],xx[0]);
		mes[0] = ENC(mes[0],xx[1]);
		mes[0] = ENC(mes[0],xx[2]);
	
		xx[0] = (keys[13]^tweaks_sin[5]);
		xx[1] = (keys[14]^tweaks_sin[6]);
		mes[0] = ENC(mes[0],xx[0]);
		mes[0] = ENC(mes[0],xx[1]);
		++t_off;
		
		auth = (auth^mes[0]);
		print128_asint(auth);
	}
	
	if(fin_ad)
	{
		memcpy(A_star,ad+numblocks_ad*CRYPTO_KEYBYTES,fin_ad);
		A_star[fin_ad] = 0x80;
		memset(A_star+fin_ad+1,0,CRYPTO_KEYBYTES-(fin_ad+1));
		A = LOAD(A_star);
		if(t_off>0){ctr = z_s[0][t_off-1];}
		idx = (tag_fin^(ctr^tweaks[0]));
		tmp = encr_one_block(A,idx);
		auth = (auth^tmp);
	}
	
	/*if(fin_ad) 
	{
		memcpy(A_star,ad+numblocks_ad*CRYPTO_KEYBYTES,fin_ad);
		A_star[fin_ad] = 0x80;
		memset(A_star+fin_ad+1,0,CRYPTO_KEYBYTES-(fin_ad+1));
		A = LOAD(A_star);
		
		idx = tweaks[0]^tag_fin; // _mm_set_epi64x(ad_fin,numblocks_ad);
		// idx =  _mm_xor_si128(ad_fin,tweaks[0]);
		// print128_asint(idx);
		tmp = encr_one_block(A,idx); // encrypt_block(A,idx,keys);
		auth = auth^tmp; // _mm_xor_si128(auth,tmp);
	}*/
	// printf("Printing auth, decr\n");
	// print128_asint(auth);
	
	///* Tag for decr nicked from here */
	
	
	
	// Verification
	
	u128 tagp = auth; 
	for(i=0;i<8;++i){
		tweaks[i] = keys[15]; 
	}
	
	
	
	idx = keys[15];
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
		for(j=0;j<PARA;++j){
			mes[j] = LOAD(m+(i+j)*CRYPTO_KEYBYTES);
		}
		
		tmp = keys[0]^tweaks[0]; // _mm_xor_si128(keys[0],tweaks[0]);
		
		mes[0] = mes[0]^tmp;
		// mes[0] = _mm_xor_si128(mes[0],tmp);
		for(j=1;j<PARA;++j){
			mes[j] = mes[j]^tmp^z_s[0][j-1];
		}
		
	
			for(j=1;j<8;++j){
				tmp = keys[j]^tweaks[j];
				for(y=0;y<PARA-1;++y){
					xx[y] = tmp^z_s[j][y];
				}
				ONEROUND(mes);
			}
			for(j=8;j<15;++j){
				tmp = keys[j]^tweaks[j-8];
				for(y=0;y<PARA-1;++y){
					xx[y] = tmp^z_s[j-8][y];
				}
				ONEROUND(mes);
			}
		
		if(z==31)
		{
			// printf("Hello!!\n");
			z=0;
			tweaks[0] = PERMUTE(tweaks[0],prop_mask);
			tweaks[0] = ADD(tweaks[0],prop);
			for(j=1;j<8;++j){
				tweaks[j] = PERMUTE(tweaks[j],h);
			}
		}
		else
		{
			for(j=0;j<8;++j){
				tweaks[j] = ADD(tweaks[j],eight[j]);
			}
			
			++z;
		} // */
		
		for(j=0;j<PARA;++j){
			tagp = tagp^mes[j];
		}
		

	}
	
	ctr = keys[15];
	for(i=0;i<fin_encr;++i){
		
		if(t_off>0){ctr = z_s[0][t_off-1];}
		
		tmp = (keys[0]^(ctr^tweaks[0]) );
		mes[0] = LOAD(m+(i+nbm-fin_encr)*CRYPTO_KEYBYTES);
		mes[0] = (tmp^mes[0]);
		
		

		tweaks_sin[0] = (ctr^tweaks[0]);
		tweaks_sin[1] = PERMUTE(tweaks_sin[0],h);
		tweaks_sin[2] = PERMUTE(tweaks_sin[1],h);
		tweaks_sin[3] = PERMUTE(tweaks_sin[2],h);
		tweaks_sin[4] = PERMUTE(tweaks_sin[3],h);
		tweaks_sin[5] = PERMUTE(tweaks_sin[4],h);
		tweaks_sin[6] = PERMUTE(tweaks_sin[5],h);
		tweaks_sin[7] = PERMUTE(tweaks_sin[6],h);
	
		xx[0] = (keys[1]^tweaks_sin[1]);
		xx[1] = (keys[2]^tweaks_sin[2]);
		xx[2] = (keys[3]^tweaks_sin[3]);
		mes[0] = ENC(mes[0],xx[0]);
		mes[0] = ENC(mes[0],xx[1]);
		mes[0] = ENC(mes[0],xx[2]);
	
		xx[0] = (keys[4]^tweaks_sin[4]);
		xx[1] = (keys[5]^tweaks_sin[5]);
		xx[2] = (keys[6]^tweaks_sin[6]);
		mes[0] = ENC(mes[0],xx[0]);
		mes[0] = ENC(mes[0],xx[1]);
		mes[0] = ENC(mes[0],xx[2]);
	
		xx[0] = (keys[7]^tweaks_sin[7]);
		xx[1] = (keys[8]^tweaks_sin[0]);
		xx[2] = (keys[9]^tweaks_sin[1]);
		mes[0] = ENC(mes[0],xx[0]);
		mes[0] = ENC(mes[0],xx[1]);
		mes[0] = ENC(mes[0],xx[2]);
	
		xx[0] = (keys[10]^tweaks_sin[2]);
		xx[1] = (keys[11]^tweaks_sin[3]);
		xx[2] = (keys[12]^tweaks_sin[4]);
		mes[0] = ENC(mes[0],xx[0]);
		mes[0] = ENC(mes[0],xx[1]);
		mes[0] = ENC(mes[0],xx[2]);
	
		xx[0] = (keys[13]^tweaks_sin[5]);
		xx[1] = (keys[14]^tweaks_sin[6]);
		mes[0] = ENC(mes[0],xx[0]);
		mes[0] = ENC(mes[0],xx[1]);
		++t_off;
		
		tagp = (tagp^mes[0]);
	}
	if(fin_cip)
	{
		memcpy(M_star,m+nbm*CRYPTO_KEYBYTES,fin_cip);
		M_star[fin_cip] = 0x80;
		memset(M_star+fin_cip+1,0,CRYPTO_KEYBYTES-(fin_cip+1));
		M = LOAD(M_star); 
		if(t_off>0){ctr = z_s[0][t_off-1];}
		idx = (tag_fin^(ctr^tweaks[0]) );
		
		tmp = encr_one_block(M,idx); 
		
		tagp = (tagp^tmp);
		
	}
	// tagp = tagp^auth; // _mm_xor_si128(tagp,auth);
	// printf("After general round\n");
	// print128_asint(tagp);
	/*if(fin_cip)
	{
		memcpy(M_star,m+nbm*CRYPTO_KEYBYTES,fin_cip);
		M_star[fin_cip] = 0x80;
		memset(M_star+fin_cip+1,0,CRYPTO_KEYBYTES-(fin_cip+1));
		M = LOAD(M_star); // Identical
		// printf("Verification (tmp):\n");
		

		idx = tag_fin^idx; // _mm_xor_si128(tag_fin,idx); // Identical
		

		tmp = encr_one_block(M,idx); // encrypt_block(M,idx,keys); //  _ver

		tagp = tagp^tmp; // _mm_xor_si128(tagp,tmp);
		
	}// */
	nonce_arr[0] = 0x10;
	nonce = LOAD(nonce_arr); // _mm_set_epi8(0x10,npub[14],npub[13],npub[12],npub[11],npub[10],npub[9],npub[8],npub[7],npub[6],npub[5],npub[4],npub[3],npub[2],npub[1],npub[0]);
	
	// print128_asint(tagp);
	// printf("Entering final one_block loop\n");
	tagp = encr_one_block(tagp,nonce); // encrypt_block(tagp,nonce,keys); // 
	
	u128 ver = tag^tagp; // _mm_xor_si128(tag,tagp);
	unsigned char v[CRYPTO_KEYBYTES];
	STORE( v, ver );
	// print128_asint(ver);
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


#define LENGTH 165

int main(){

	
	int i;
	
	u64 mlen = LENGTH;
	u8 pt[LENGTH] = "nwlrbbmqbhcdarzowkkyhiddqscdxrjmowfrxsjybldbefsarcbynecdyggxxpklorellnmpapqfwkhopkmcoqhnwnkuewhsqmgbbuqcljjivswmdkqtbxixmvtrrbljptnsnfwzqfjmafadrrwsofsbcnuvqhffbsaqx";
	//////////////////////////////////////////////////
	//u8 *pt = malloc(sz);
	// u8 pt[80] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
	u8 ch;
	u64 j=0;
	
	
	u8 ct[LENGTH + CRYPTO_ABYTES]; //  = malloc(sz + CRYPTO_ABYTES);
	u8 key[CRYPTO_KEYBYTES] = "keykeykeykeykey!";
	u8 ad[146] = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210!!";
	u8 nonce[15] = "noncenoncenonce";
	// u64 mlen = 80;
	u64 clen,olen;
	u8 out[LENGTH]; // = malloc(sz);
	
	/*FILE *resdump;
	resdump = fopen("Deoxys_ARM_16384","w");
	for(j=0;j<200;++j){
		TIME_IT("COLM_ARM",crypto_aead_encrypt(&ct,&clen,&pt,mlen,&ad,146,0x00,&nonce,&key),mlen,1);
	}
	fclose(resdump);*/
	// printf("sz is %lu\n",sz);
	
	crypto_aead_encrypt(&ct,&clen,&pt,mlen,&ad,146,0x00,&nonce,&key);
	// printf("Entering decrypt\n");
	int ver = crypto_aead_decrypt(&out,&olen,0x00,&ct,clen,&ad,146,&nonce,&key);
       

	// printf("Lenght of the cipher is %d, length of the output is %d\n",clen,olen);
	if(!ver){
		printf("Verification succeeds\n");
		/* for(j=0;j<olen/16;++j){for(i=0;i<16;++i){
			printf("%d ",out[16*j+i]); }printf("\n");
		}// */
	}
	else{
		printf("Verification fails\n");
		for(i=0;i<160;++i){
			printf("%c",ct[i]); 
		} // */
	} 
	printf("\n"); 
	
	return 0;
}
