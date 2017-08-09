#include <stdio.h>
#include "api.h"
#include "emmintrin.h"
#include "wmmintrin.h"
#include "tmmintrin.h"
#include "crypto_aead.h"
// #include "debugfuncs.h" /*Alright compiler? Shut the fuck up*/

/*void print128_asint(__m128i p) // Print 128-bit block as integer
{
	unsigned char *val = (unsigned char*) &p;
	printf("%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d \n", val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7], val[8], val[9], val[10], val[11], val[12], val[13], val[14], val[15], val[16]);
}*/

const unsigned char rcon[17] = {0x2f,0x5e,0xbc,0x63,0xc6,0x97,0x35,0x6a,0xd4,0xb3,0x7d,0xfa,0xef,0xc5,0x91,0x39,0x72};

__m128i keys[15];

__m128i LFSR2(__m128i k)
{
	__m128i mask_high = _mm_set1_epi8(0xfe);
	__m128i mask_low  = _mm_set1_epi8(0x01);
	__m128i tmp = _mm_xor_si128( _mm_and_si128( mask_high  , _mm_slli_epi32( k, 1 ) ) ,
				    _mm_and_si128( mask_low, _mm_srli_epi32( k, 7 ) ) );
	return _mm_xor_si128(_mm_and_si128( mask_low, _mm_srli_epi32( k, 5 ) ),tmp);
}

void generate_keys_new(__m128i key)
{
	__m128i h = _mm_set_epi8( 7,0,13,10, 11,4,1,14, 15,8,5,2, 3,12,9,6 );
	__m128i RC = _mm_set_epi8(0x01,0x02,0x04,0x08,rcon[0],rcon[0],rcon[0],rcon[0],0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);
	keys[0] = _mm_xor_si128(RC,key);
	int i;
	for(i=1;i<=14;++i)
	{
		key = _mm_shuffle_epi8(key,h);
		key = LFSR2(key);
		RC = _mm_set_epi8(0x01,0x02,0x04,0x08,rcon[i],rcon[i],rcon[i],rcon[i],0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);
		keys[i] = _mm_xor_si128(RC,key);
	}
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
	unsigned char tweak[CRYPTO_KEYBYTES] = "What is a tweak?";
	__m128i key = _mm_loadu_si128(k);
	generate_keys_new(key);

	__m128i auth = _mm_setzero_si128();

	unsigned long long numblocks_ad = adlen/CRYPTO_KEYBYTES;
	unsigned long long numblocks_mes = mlen/CRYPTO_KEYBYTES;
	int fin_ad = adlen%CRYPTO_KEYBYTES;
	int fin_mes = mlen%CRYPTO_KEYBYTES;
	unsigned long long i,j;
	int z;

	__m128i ad_reg  = _mm_set_epi8(0x20,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0  ,0x0,0x0,0x0,0x0);
	__m128i tag_fin = _mm_set_epi8(0x40,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0  ,0x0,0x0,0x0,0x0);
	__m128i MSB1    = _mm_set_epi8(0x80,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0  ,0x0,0x0,0x0,0x0);
	__m128i prop    = _mm_set_epi8(0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0, 0x08,0x0,0x0,0x0  ,0x0,0x0,0x0,0x0);
	__m128i prop_mask = _mm_set_epi8(8,9,10,11,12,13,14,15,  0,1,2,3,4,5,6,7  );
	__m128i zero = _mm_setzero_si128();
	__m128i nonce = _mm_set_epi8(0x10,npub[14],npub[13],npub[12],npub[11],npub[10],npub[9],npub[8],npub[7],npub[6],npub[5],npub[4],npub[3],npub[2],npub[1],npub[0]);
	__m128i one = _mm_set_epi8(0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1);
	__m128i h = _mm_set_epi8( 7,0,13,10, 11,4,1,14, 15,8,5,2, 3,12,9,6 );
	__m128i idx,tmp;
	unsigned char A_star[CRYPTO_KEYBYTES];
	unsigned char M_star[CRYPTO_KEYBYTES];

	// Additional data

	__m128i eight[8],tweaks[8],xx[3],z_s[8][3],mes[4];

	// tmp = one;
	for(i=0;i<8;++i)
	{
		z_s[i][0] = _mm_add_epi8(one,zero);
		z_s[i][1] = _mm_add_epi8(one,z_s[i][0]);
		z_s[i][2] = _mm_add_epi8(one,z_s[i][1]);
		/*z_s[i][3] = _mm_add_epi8(one,z_s[i][2]);
		z_s[i][4] = _mm_add_epi8(one,z_s[i][3]);
		z_s[i][5] = _mm_add_epi8(one,z_s[i][4]);
		z_s[i][6] = _mm_add_epi8(one,z_s[i][5]);*/
		one = _mm_shuffle_epi8(one,h);
	} // */
	tweaks[0] = ad_reg;
	tweaks[1] = _mm_shuffle_epi8(tweaks[0],h);
	tweaks[2] = _mm_shuffle_epi8(tweaks[1],h);
	tweaks[3] = _mm_shuffle_epi8(tweaks[2],h);
	tweaks[4] = _mm_shuffle_epi8(tweaks[3],h);
	tweaks[5] = _mm_shuffle_epi8(tweaks[4],h);
	tweaks[6] = _mm_shuffle_epi8(tweaks[5],h);
	tweaks[7] = _mm_shuffle_epi8(tweaks[6],h); // */

	eight[0] = _mm_set_epi8(0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,4); /*Legacy name*/
	eight[1] = _mm_shuffle_epi8(eight[0],h);
	eight[2] = _mm_shuffle_epi8(eight[1],h);
	eight[3] = _mm_shuffle_epi8(eight[2],h);
	eight[4] = _mm_shuffle_epi8(eight[3],h);
	eight[5] = _mm_shuffle_epi8(eight[4],h);
	eight[6] = _mm_shuffle_epi8(eight[5],h);
	eight[7] = _mm_shuffle_epi8(eight[6],h); // */

	for(i=0;i<numblocks_ad;i+=4)
	{
		mes[0] = _mm_loadu_si128(ad+(i  )*CRYPTO_KEYBYTES);
		mes[1] = _mm_loadu_si128(ad+(i+1)*CRYPTO_KEYBYTES);
		mes[2] = _mm_loadu_si128(ad+(i+2)*CRYPTO_KEYBYTES);
		mes[3] = _mm_loadu_si128(ad+(i+3)*CRYPTO_KEYBYTES);
		/*mes[4] = _mm_loadu_si128(ad+(i+4)*CRYPTO_KEYBYTES);
		mes[5] = _mm_loadu_si128(ad+(i+5)*CRYPTO_KEYBYTES);
		mes[6] = _mm_loadu_si128(ad+(i+6)*CRYPTO_KEYBYTES);
		mes[7] = _mm_loadu_si128(ad+(i+7)*CRYPTO_KEYBYTES);*/
        // ENCR_8_BLOCKS(mes);

		tmp = _mm_xor_si128(keys[0],tweaks[0]);

		xx[0] = _mm_xor_si128(tmp,z_s[0][0]);
		xx[1] = _mm_xor_si128(tmp,z_s[0][1]);
		xx[2] = _mm_xor_si128(tmp,z_s[0][2]);

		mes[0] = _mm_xor_si128(mes[0],tmp);
		mes[1] = _mm_xor_si128(mes[1],xx[0] );
		mes[2] = _mm_xor_si128(mes[2],xx[1] );
		mes[3] = _mm_xor_si128(mes[3],xx[2] );
		/*mes[4] = _mm_xor_si128(mes[4],_mm_xor_si128(tmp,z_s[0][3]) );
		mes[5] = _mm_xor_si128(mes[5],_mm_xor_si128(tmp,z_s[0][4]) );
		mes[6] = _mm_xor_si128(mes[6],_mm_xor_si128(tmp,z_s[0][5]) );
		mes[7] = _mm_xor_si128(mes[7],_mm_xor_si128(tmp,z_s[0][6]) );*/


			tmp = _mm_xor_si128(keys[1],tweaks[1]);

			xx[0] = _mm_xor_si128(tmp,z_s[1][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[1][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[1][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[1][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[1][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[1][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[1][6]);*/


			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[2],tweaks[2]);

			xx[0] = _mm_xor_si128(tmp,z_s[2][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[2][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[2][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[2][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[2][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[2][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[2][6]);*/

			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[3],tweaks[3]);

			xx[0] = _mm_xor_si128(tmp,z_s[3][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[3][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[3][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[3][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[3][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[3][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[3][6]);*/

			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[4],tweaks[4]);

			xx[0] = _mm_xor_si128(tmp,z_s[4][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[4][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[4][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[4][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[4][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[4][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[4][6]);*/



			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[5],tweaks[5]);

			xx[0] = _mm_xor_si128(tmp,z_s[5][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[5][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[5][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[5][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[5][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[5][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[5][6]);*/



			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[6],tweaks[6]);

			xx[0] = _mm_xor_si128(tmp,z_s[6][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[6][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[6][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[6][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[6][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[6][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[6][6]);*/



			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[7],tweaks[7]);

			xx[0] = _mm_xor_si128(tmp,z_s[7][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[7][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[7][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[7][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[7][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[7][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[7][6]);*/



			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[8],tweaks[0]);

			xx[0] = _mm_xor_si128(tmp,z_s[0][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[0][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[0][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[0][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[0][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[0][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[0][6]);*/

			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[9],tweaks[1]);

			xx[0] = _mm_xor_si128(tmp,z_s[1][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[1][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[1][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[1][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[1][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[1][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[1][6]);*/

			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[10],tweaks[2]);

			xx[0] = _mm_xor_si128(tmp,z_s[2][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[2][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[2][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[2][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[2][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[2][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[2][6]);*/

			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[11],tweaks[3]);

			xx[0] = _mm_xor_si128(tmp,z_s[3][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[3][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[3][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[3][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[3][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[3][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[3][6]);*/

			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[12],tweaks[4]);

			xx[0] = _mm_xor_si128(tmp,z_s[4][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[4][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[4][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[4][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[4][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[4][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[4][6]);*/

			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[13],tweaks[5]);

			xx[0] = _mm_xor_si128(tmp,z_s[5][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[5][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[5][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[5][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[5][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[5][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[5][6]);*/

			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[14],tweaks[6]);

			xx[0] = _mm_xor_si128(tmp,z_s[6][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[6][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[6][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[6][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[6][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[6][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[6][6]);*/

			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] ); // */

			tweaks[0] = _mm_add_epi64(tweaks[0],eight[0]);
			tweaks[1] = _mm_add_epi64(tweaks[1],eight[1]);
			tweaks[2] = _mm_add_epi64(tweaks[2],eight[2]);
			tweaks[3] = _mm_add_epi64(tweaks[3],eight[3]);
			tweaks[4] = _mm_add_epi64(tweaks[4],eight[4]);
			tweaks[5] = _mm_add_epi64(tweaks[5],eight[5]);
			tweaks[6] = _mm_add_epi64(tweaks[6],eight[6]);
			tweaks[7] = _mm_add_epi64(tweaks[7],eight[7]);



		auth = mes[0]^mes[1]^mes[2]^mes[3]^auth;


		// // print128_asint(auth);
	}
	if(fin_ad)
	{
		memcpy(A_star,ad+numblocks_ad*CRYPTO_KEYBYTES,fin_ad);
		A_star[fin_ad] = 0x80;
		memset(A_star+fin_ad+1,0,CRYPTO_KEYBYTES-(fin_ad+1));
		mes[0] = _mm_loadu_si128(A_star);
		idx = _mm_xor_si128(tag_fin,tweaks[0]); /* tweaks[0] = current index, since it is incremented at end*/
		// tmp = encrypt_block(mes[0],idx);

		/* Start of encrypt_block. To encrypt: mes[0] with tweak idx. This will be a slow f*cker. */

		tweaks[0] = idx;

		tmp = _mm_xor_si128(keys[0],tweaks[0]); // Round key
		idx = _mm_xor_si128(tmp,mes[0]);

		tweaks[1] = _mm_shuffle_epi8(tweaks[0],h); // Remember to reset tweaks
		tweaks[2] = _mm_shuffle_epi8(tweaks[1],h);
		tweaks[3] = _mm_shuffle_epi8(tweaks[2],h);
		tweaks[4] = _mm_shuffle_epi8(tweaks[3],h);
		tweaks[5] = _mm_shuffle_epi8(tweaks[4],h);
		tweaks[6] = _mm_shuffle_epi8(tweaks[5],h);
		tweaks[7] = _mm_shuffle_epi8(tweaks[6],h);

		tmp = _mm_xor_si128(keys[1],tweaks[1]); /* Use "tweaks" for tmp??*/
		idx = _mm_aesenc_si128(idx,tmp);
		tmp = _mm_xor_si128(keys[2],tweaks[2]);
		idx = _mm_aesenc_si128(idx,tmp);
		tmp = _mm_xor_si128(keys[3],tweaks[3]);
		idx = _mm_aesenc_si128(idx,tmp);
		tmp = _mm_xor_si128(keys[4],tweaks[4]);
		idx = _mm_aesenc_si128(idx,tmp);
		tmp = _mm_xor_si128(keys[5],tweaks[5]);
		idx = _mm_aesenc_si128(idx,tmp);
		tmp = _mm_xor_si128(keys[6],tweaks[6]);
		idx = _mm_aesenc_si128(idx,tmp);
		tmp = _mm_xor_si128(keys[7],tweaks[7]);
		idx = _mm_aesenc_si128(idx,tmp);
		tmp = _mm_xor_si128(keys[8],tweaks[0]);
		idx = _mm_aesenc_si128(idx,tmp);
		tmp = _mm_xor_si128(keys[9],tweaks[1]);
		idx = _mm_aesenc_si128(idx,tmp);
		tmp = _mm_xor_si128(keys[10],tweaks[2]);
		idx = _mm_aesenc_si128(idx,tmp);
		tmp = _mm_xor_si128(keys[11],tweaks[3]);
		idx = _mm_aesenc_si128(idx,tmp);
		tmp = _mm_xor_si128(keys[12],tweaks[4]);
		idx = _mm_aesenc_si128(idx,tmp);
		tmp = _mm_xor_si128(keys[13],tweaks[5]);
		idx = _mm_aesenc_si128(idx,tmp);
		tmp = _mm_xor_si128(keys[14],tweaks[6]);
		idx = _mm_aesenc_si128(idx,tmp);

		/* end of encrypt_block*/

		auth = _mm_xor_si128(auth,idx);
	}
    // // print128_asint(auth);
	// Tag generation

	/*And I definitely need to so something about this*/

	tweaks[0] = zero; /* Shuffling a zero would be a pointless exercise */
	tweaks[1] = zero;
	tweaks[2] = zero;
	tweaks[3] = zero;
	tweaks[4] = zero;
	tweaks[5] = zero;
	tweaks[6] = zero;
	tweaks[7] = zero;

	__m128i tag = auth;
	// print128_asint(tag);
	z = 0;
	for(i=0;i<numblocks_mes;i+=4)
	{
		mes[0] = _mm_loadu_si128(m+(i  )*CRYPTO_KEYBYTES);
		mes[1] = _mm_loadu_si128(m+(i+1)*CRYPTO_KEYBYTES);
		mes[2] = _mm_loadu_si128(m+(i+2)*CRYPTO_KEYBYTES);
		mes[3] = _mm_loadu_si128(m+(i+3)*CRYPTO_KEYBYTES);
		/*mes[4] = _mm_loadu_si128(m+(i+4)*CRYPTO_KEYBYTES);
		mes[5] = _mm_loadu_si128(m+(i+5)*CRYPTO_KEYBYTES);
		mes[6] = _mm_loadu_si128(m+(i+6)*CRYPTO_KEYBYTES);
		mes[7] = _mm_loadu_si128(m+(i+7)*CRYPTO_KEYBYTES);*/

		// ENCR_8_BLOCKS(mes);

		tmp = _mm_xor_si128(keys[0],tweaks[0]);

		xx[0] = _mm_xor_si128(tmp,z_s[0][0]);
		xx[1] = _mm_xor_si128(tmp,z_s[0][1]);
		xx[2] = _mm_xor_si128(tmp,z_s[0][2]);
		/*xx[3] = _mm_xor_si128(tmp,z_s[0][3]);
		xx[4] = _mm_xor_si128(tmp,z_s[0][4]);
		xx[5] = _mm_xor_si128(tmp,z_s[0][5]);
		xx[6] = _mm_xor_si128(tmp,z_s[0][6]);*/

		mes[0] = _mm_xor_si128(mes[0],tmp);
		mes[1] = _mm_xor_si128(mes[1],xx[0] ); // index 1..7
		mes[2] = _mm_xor_si128(mes[2],xx[1] );
		mes[3] = _mm_xor_si128(mes[3],xx[2] );
		/*mes[4] = _mm_xor_si128(mes[4],xx[3] );
		mes[5] = _mm_xor_si128(mes[5],xx[4] );
		mes[6] = _mm_xor_si128(mes[6],xx[5] );
		mes[7] = _mm_xor_si128(mes[7],xx[6] );*/


			tmp = _mm_xor_si128(keys[1],tweaks[1]);

			xx[0] = _mm_xor_si128(tmp,z_s[1][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[1][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[1][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[1][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[1][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[1][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[1][6]);*/

			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[2],tweaks[2]);

			xx[0] = _mm_xor_si128(tmp,z_s[2][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[2][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[2][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[2][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[2][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[2][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[2][6]);*/

			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[3],tweaks[3]);

			xx[0] = _mm_xor_si128(tmp,z_s[3][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[3][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[3][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[3][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[3][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[3][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[3][6]);*/

			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[4],tweaks[4]);

			xx[0] = _mm_xor_si128(tmp,z_s[4][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[4][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[4][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[4][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[4][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[4][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[4][6]);*/

			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[5],tweaks[5]);

			xx[0] = _mm_xor_si128(tmp,z_s[5][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[5][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[5][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[5][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[5][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[5][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[5][6]);*/

			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[6],tweaks[6]);

			xx[0] = _mm_xor_si128(tmp,z_s[6][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[6][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[6][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[6][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[6][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[6][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[6][6]);*/

			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[7],tweaks[7]);

			xx[0] = _mm_xor_si128(tmp,z_s[7][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[7][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[7][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[7][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[7][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[7][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[7][6]);*/

			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[8],tweaks[0]);

			xx[0] = _mm_xor_si128(tmp,z_s[0][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[0][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[0][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[0][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[0][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[0][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[0][6]);*/

			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[9],tweaks[1]);

			xx[0] = _mm_xor_si128(tmp,z_s[1][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[1][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[1][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[1][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[1][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[1][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[1][6]);*/

			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[10],tweaks[2]);

			xx[0] = _mm_xor_si128(tmp,z_s[2][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[2][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[2][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[2][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[2][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[2][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[2][6]);*/

			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[11],tweaks[3]);

			xx[0] = _mm_xor_si128(tmp,z_s[3][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[3][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[3][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[3][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[3][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[3][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[3][6]);*/

			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[12],tweaks[4]);

			xx[0] = _mm_xor_si128(tmp,z_s[4][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[4][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[4][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[4][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[4][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[4][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[4][6]);*/

			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[13],tweaks[5]);

			xx[0] = _mm_xor_si128(tmp,z_s[5][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[5][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[5][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[5][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[5][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[5][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[5][6]);*/

			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[14],tweaks[6]);

			xx[0] = _mm_xor_si128(tmp,z_s[6][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[6][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[6][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[6][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[6][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[6][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[6][6]);*/

			mes[0] = _mm_aesenc_si128(mes[0],tmp);
			mes[1] = _mm_aesenc_si128(mes[1],xx[0] );
			mes[2] = _mm_aesenc_si128(mes[2],xx[1] );
			mes[3] = _mm_aesenc_si128(mes[3],xx[2] );
			/*mes[4] = _mm_aesenc_si128(mes[4],xx[3] );
			mes[5] = _mm_aesenc_si128(mes[5],xx[4] );
			mes[6] = _mm_aesenc_si128(mes[6],xx[5] );
			mes[7] = _mm_aesenc_si128(mes[7],xx[6] ); // */


			tweaks[0] = _mm_add_epi64(tweaks[0],eight[0]);
			tweaks[1] = _mm_add_epi64(tweaks[1],eight[1]);
			tweaks[2] = _mm_add_epi64(tweaks[2],eight[2]);
			tweaks[3] = _mm_add_epi64(tweaks[3],eight[3]);
			tweaks[4] = _mm_add_epi64(tweaks[4],eight[4]);
			tweaks[5] = _mm_add_epi64(tweaks[5],eight[5]);
			tweaks[6] = _mm_add_epi64(tweaks[6],eight[6]);
			tweaks[7] = _mm_add_epi64(tweaks[7],eight[7]);



		tag = tag^mes[0]^mes[1]^mes[2]^mes[3]; // ^mes[4]^mes[5]^mes[6]^mes[7];
	}

	if(fin_mes)
	{
		memcpy(M_star,m+numblocks_mes*CRYPTO_KEYBYTES,fin_mes);
		M_star[fin_mes] = 0x80;
		memset(M_star+fin_mes+1,0,CRYPTO_KEYBYTES-(fin_mes+1));
		mes[0] = _mm_loadu_si128(M_star);
		idx = _mm_xor_si128(tag_fin,tweaks[0]);


		tweaks[0] = idx;

		tmp = _mm_xor_si128(keys[0],tweaks[0]); // Round key
		idx = _mm_xor_si128(tmp,mes[0]); // Counting coppers

		tweaks[1] = _mm_shuffle_epi8(tweaks[0],h);
		tweaks[2] = _mm_shuffle_epi8(tweaks[1],h);
		tweaks[3] = _mm_shuffle_epi8(tweaks[2],h);
		tweaks[4] = _mm_shuffle_epi8(tweaks[3],h);
		tweaks[5] = _mm_shuffle_epi8(tweaks[4],h);
		tweaks[6] = _mm_shuffle_epi8(tweaks[5],h);
		tweaks[7] = _mm_shuffle_epi8(tweaks[6],h);

		xx[0] = _mm_xor_si128(keys[1],tweaks[1]);
		xx[1] = _mm_xor_si128(keys[2],tweaks[2]);
		xx[2] = _mm_xor_si128(keys[3],tweaks[3]);

		idx = _mm_aesenc_si128(idx,xx[0]);
		idx = _mm_aesenc_si128(idx,xx[1]);
		idx = _mm_aesenc_si128(idx,xx[2]);

		xx[0] = _mm_xor_si128(keys[4],tweaks[4]);
		xx[1] = _mm_xor_si128(keys[5],tweaks[5]);
		xx[2] = _mm_xor_si128(keys[6],tweaks[6]);

		idx = _mm_aesenc_si128(idx,xx[0]);
		idx = _mm_aesenc_si128(idx,xx[1]);
		idx = _mm_aesenc_si128(idx,xx[2]);


		xx[0] = _mm_xor_si128(keys[7],tweaks[7]);
		xx[1] = _mm_xor_si128(keys[8],tweaks[0]);
		xx[2] = _mm_xor_si128(keys[9],tweaks[1]);

		idx = _mm_aesenc_si128(idx,xx[0]);
		idx = _mm_aesenc_si128(idx,xx[1]);
		idx = _mm_aesenc_si128(idx,xx[2]);

		xx[0] = _mm_xor_si128(keys[10],tweaks[2]);
		xx[1] = _mm_xor_si128(keys[11],tweaks[3]);
		xx[2] = _mm_xor_si128(keys[12],tweaks[4]);

		idx = _mm_aesenc_si128(idx,xx[0]);
		idx = _mm_aesenc_si128(idx,xx[1]);
		idx = _mm_aesenc_si128(idx,xx[2]);

		xx[0] = _mm_xor_si128(keys[13],tweaks[5]);
		xx[1] = _mm_xor_si128(keys[14],tweaks[6]);

		idx = _mm_aesenc_si128(idx,xx[0]);
		idx = _mm_aesenc_si128(idx,xx[1]);

		tag = _mm_xor_si128(tag,idx);

	}
	/* Start of encrypt_block. To encrypt: Tag with tweak nonce. This will be a slow f*cker. */

	tweaks[0] = nonce;

	tmp = _mm_xor_si128(keys[0],tweaks[0]); // Round key
	tag = _mm_xor_si128(tmp,tag); // Counting coppers

	tweaks[1] = _mm_shuffle_epi8(tweaks[0],h);
	tweaks[2] = _mm_shuffle_epi8(tweaks[1],h);
	tweaks[3] = _mm_shuffle_epi8(tweaks[2],h);
	tweaks[4] = _mm_shuffle_epi8(tweaks[3],h);
	tweaks[5] = _mm_shuffle_epi8(tweaks[4],h);
	tweaks[6] = _mm_shuffle_epi8(tweaks[5],h);
	tweaks[7] = _mm_shuffle_epi8(tweaks[6],h);

	/* Let's see*/

		xx[0] = _mm_xor_si128(keys[1],tweaks[1]);
		xx[1] = _mm_xor_si128(keys[2],tweaks[2]);
		xx[2] = _mm_xor_si128(keys[3],tweaks[3]);

		tag = _mm_aesenc_si128(tag,xx[0]);
		tag = _mm_aesenc_si128(tag,xx[1]);
		tag = _mm_aesenc_si128(tag,xx[2]);

		xx[0] = _mm_xor_si128(keys[4],tweaks[4]);
		xx[1] = _mm_xor_si128(keys[5],tweaks[5]);
		xx[2] = _mm_xor_si128(keys[6],tweaks[6]);

		tag = _mm_aesenc_si128(tag,xx[0]);
		tag = _mm_aesenc_si128(tag,xx[1]);
		tag = _mm_aesenc_si128(tag,xx[2]);


		xx[0] = _mm_xor_si128(keys[7],tweaks[7]);
		xx[1] = _mm_xor_si128(keys[8],tweaks[0]);	
		xx[2] = _mm_xor_si128(keys[9],tweaks[1]);

		tag = _mm_aesenc_si128(tag,xx[0]);
		tag = _mm_aesenc_si128(tag,xx[1]);
		tag = _mm_aesenc_si128(tag,xx[2]);

		xx[0] = _mm_xor_si128(keys[10],tweaks[2]);
		xx[1] = _mm_xor_si128(keys[11],tweaks[3]);
		xx[2] = _mm_xor_si128(keys[12],tweaks[4]);

		tag = _mm_aesenc_si128(tag,xx[0]);
		tag = _mm_aesenc_si128(tag,xx[1]);
		tag = _mm_aesenc_si128(tag,xx[2]);

		xx[0] = _mm_xor_si128(keys[13],tweaks[5]);
		xx[1] = _mm_xor_si128(keys[14],tweaks[6]);

		tag = _mm_aesenc_si128(tag,xx[0]);
		tag = _mm_aesenc_si128(tag,xx[1]);


	/* end of encrypt_block*/

	// print128_asint(tag);

	_mm_storeu_si128( (__m128i *)&c[numblocks_mes*CRYPTO_KEYBYTES+fin_mes], tag );

	nonce = _mm_set_epi8(0x00,npub[14],npub[13],npub[12],npub[11],npub[10],npub[9],npub[8],npub[7],npub[6],npub[5],npub[4],npub[3],npub[2],npub[1],npub[0]);

	__m128i one_tag = _mm_or_si128(tag,MSB1); // And what good does truncating the tag do?

	tweaks[0] = zero;
	tweaks[1] = zero;
	tweaks[2] = zero;
	tweaks[3] = zero;
	tweaks[4] = zero;
	tweaks[5] = zero;
	tweaks[6] = zero;
	tweaks[7] = zero; // */

	// tmp = one_tag;
	for(i=0;i<7;++i)
	{
		keys[i] = _mm_xor_si128(keys[i],one_tag);
		keys[i+8] = _mm_xor_si128(keys[i+8],one_tag);
		one_tag = _mm_shuffle_epi8(one_tag,h);
	} // */

	keys[7] = _mm_xor_si128(keys[7],one_tag); /*Getting rid of a shuffle and pipelining some xor's*/
	one_tag = _mm_shuffle_epi8(one_tag,h);
	// Encryption
	unsigned char C_star[CRYPTO_KEYBYTES];
	__m128i N[4];
	z = 0;
	// idx = zero; // _mm_setzero_si128();

	for(i=0;i<numblocks_mes;i+=4)
	{


		tmp = _mm_xor_si128(tweaks[0] ,keys[0]);

		N[0] = _mm_xor_si128(nonce,tmp );
		N[1] = _mm_xor_si128(N[0],z_s[0][0] );
		N[2] = _mm_xor_si128(N[0],z_s[0][1] );
		N[3] = _mm_xor_si128(N[0],z_s[0][2] );
		/*N[4] = _mm_xor_si128(N[0],z_s[0][3] );
		N[5] = _mm_xor_si128(N[0],z_s[0][4] );
		N[6] = _mm_xor_si128(N[0],z_s[0][5] );
		N[7] = _mm_xor_si128(N[0],z_s[0][6] );*/

			tmp = _mm_xor_si128(keys[1],tweaks[1]);

			xx[0] = _mm_xor_si128(tmp,z_s[1][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[1][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[1][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[1][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[1][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[1][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[1][6]);*/

			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			/*N[4] = _mm_aesenc_si128(N[4],xx[3] );
			N[5] = _mm_aesenc_si128(N[5],xx[4] );
			N[6] = _mm_aesenc_si128(N[6],xx[5] );
			N[7] = _mm_aesenc_si128(N[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[2],tweaks[2]);

			xx[0] = _mm_xor_si128(tmp,z_s[2][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[2][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[2][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[2][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[2][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[2][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[2][6]);*/

			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			/*N[4] = _mm_aesenc_si128(N[4],xx[3] );
			N[5] = _mm_aesenc_si128(N[5],xx[4] );
			N[6] = _mm_aesenc_si128(N[6],xx[5] );
			N[7] = _mm_aesenc_si128(N[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[3],tweaks[3]);

			xx[0] = _mm_xor_si128(tmp,z_s[3][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[3][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[3][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[3][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[3][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[3][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[3][6]);*/

			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			/*N[4] = _mm_aesenc_si128(N[4],xx[3] );
			N[5] = _mm_aesenc_si128(N[5],xx[4] );
			N[6] = _mm_aesenc_si128(N[6],xx[5] );
			N[7] = _mm_aesenc_si128(N[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[4],tweaks[4]);

			xx[0] = _mm_xor_si128(tmp,z_s[4][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[4][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[4][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[4][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[4][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[4][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[4][6]);*/

			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			/*N[4] = _mm_aesenc_si128(N[4],xx[3] );
			N[5] = _mm_aesenc_si128(N[5],xx[4] );
			N[6] = _mm_aesenc_si128(N[6],xx[5] );
			N[7] = _mm_aesenc_si128(N[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[5],tweaks[5]);

			xx[0] = _mm_xor_si128(tmp,z_s[5][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[5][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[5][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[5][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[5][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[5][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[5][6]);*/

			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			/*N[4] = _mm_aesenc_si128(N[4],xx[3] );
			N[5] = _mm_aesenc_si128(N[5],xx[4] );
			N[6] = _mm_aesenc_si128(N[6],xx[5] );
			N[7] = _mm_aesenc_si128(N[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[6],tweaks[6]);

			xx[0] = _mm_xor_si128(tmp,z_s[6][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[6][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[6][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[6][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[6][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[6][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[6][6]);*/

			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			/*N[4] = _mm_aesenc_si128(N[4],xx[3] );
			N[5] = _mm_aesenc_si128(N[5],xx[4] );
			N[6] = _mm_aesenc_si128(N[6],xx[5] );
			N[7] = _mm_aesenc_si128(N[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[7],tweaks[7]);

			xx[0] = _mm_xor_si128(tmp,z_s[7][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[7][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[7][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[7][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[7][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[7][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[7][6]);*/

			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			/*N[4] = _mm_aesenc_si128(N[4],xx[3] );
			N[5] = _mm_aesenc_si128(N[5],xx[4] );
			N[6] = _mm_aesenc_si128(N[6],xx[5] );
			N[7] = _mm_aesenc_si128(N[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[8],tweaks[0]);

			xx[0] = _mm_xor_si128(tmp,z_s[0][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[0][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[0][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[0][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[0][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[0][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[0][6]);*/

			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			/*N[4] = _mm_aesenc_si128(N[4],xx[3] );
			N[5] = _mm_aesenc_si128(N[5],xx[4] );
			N[6] = _mm_aesenc_si128(N[6],xx[5] );
			N[7] = _mm_aesenc_si128(N[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[9],tweaks[1]);

			xx[0] = _mm_xor_si128(tmp,z_s[1][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[1][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[1][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[1][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[1][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[1][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[1][6]);*/

			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			/*N[4] = _mm_aesenc_si128(N[4],xx[3] );
			N[5] = _mm_aesenc_si128(N[5],xx[4] );
			N[6] = _mm_aesenc_si128(N[6],xx[5] );
			N[7] = _mm_aesenc_si128(N[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[10],tweaks[2]);

			xx[0] = _mm_xor_si128(tmp,z_s[2][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[2][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[2][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[2][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[2][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[2][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[2][6]);*/

			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			/*N[4] = _mm_aesenc_si128(N[4],xx[3] );
			N[5] = _mm_aesenc_si128(N[5],xx[4] );
			N[6] = _mm_aesenc_si128(N[6],xx[5] );
			N[7] = _mm_aesenc_si128(N[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[11],tweaks[3]);

			xx[0] = _mm_xor_si128(tmp,z_s[3][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[3][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[3][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[3][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[3][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[3][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[3][6]);*/

			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			/*N[4] = _mm_aesenc_si128(N[4],xx[3] );
			N[5] = _mm_aesenc_si128(N[5],xx[4] );
			N[6] = _mm_aesenc_si128(N[6],xx[5] );
			N[7] = _mm_aesenc_si128(N[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[12],tweaks[4]);

			xx[0] = _mm_xor_si128(tmp,z_s[4][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[4][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[4][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[4][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[4][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[4][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[4][6]);*/

			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			/*N[4] = _mm_aesenc_si128(N[4],xx[3] );
			N[5] = _mm_aesenc_si128(N[5],xx[4] );
			N[6] = _mm_aesenc_si128(N[6],xx[5] );
			N[7] = _mm_aesenc_si128(N[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[13],tweaks[5]);

			xx[0] = _mm_xor_si128(tmp,z_s[5][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[5][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[5][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[5][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[5][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[5][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[5][6]);*/

			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			/*N[4] = _mm_aesenc_si128(N[4],xx[3] );
			N[5] = _mm_aesenc_si128(N[5],xx[4] );
			N[6] = _mm_aesenc_si128(N[6],xx[5] );
			N[7] = _mm_aesenc_si128(N[7],xx[6] );*/

			tmp = _mm_xor_si128(keys[14],tweaks[6]);

			xx[0] = _mm_xor_si128(tmp,z_s[6][0]);
			xx[1] = _mm_xor_si128(tmp,z_s[6][1]);
			xx[2] = _mm_xor_si128(tmp,z_s[6][2]);
			/*xx[3] = _mm_xor_si128(tmp,z_s[6][3]);
			xx[4] = _mm_xor_si128(tmp,z_s[6][4]);
			xx[5] = _mm_xor_si128(tmp,z_s[6][5]);
			xx[6] = _mm_xor_si128(tmp,z_s[6][6]);*/

			N[0] = _mm_aesenc_si128(N[0],tmp);
			N[1] = _mm_aesenc_si128(N[1],xx[0] );
			N[2] = _mm_aesenc_si128(N[2],xx[1] );
			N[3] = _mm_aesenc_si128(N[3],xx[2] );
			/*N[4] = _mm_aesenc_si128(N[4],xx[3] );
			N[5] = _mm_aesenc_si128(N[5],xx[4] );
			N[6] = _mm_aesenc_si128(N[6],xx[5] );
			N[7] = _mm_aesenc_si128(N[7],xx[6] );*/



		/* Can't do shit about the next three blocks */

		mes[0] = _mm_loadu_si128(m+(i  )*CRYPTO_KEYBYTES);
		mes[1] = _mm_loadu_si128(m+(i+1)*CRYPTO_KEYBYTES);
		mes[2] = _mm_loadu_si128(m+(i+2)*CRYPTO_KEYBYTES);
		mes[3] = _mm_loadu_si128(m+(i+3)*CRYPTO_KEYBYTES);
		/*mes[4] = _mm_loadu_si128(m+(i+4)*CRYPTO_KEYBYTES);
		mes[5] = _mm_loadu_si128(m+(i+5)*CRYPTO_KEYBYTES);
		mes[6] = _mm_loadu_si128(m+(i+6)*CRYPTO_KEYBYTES);
		mes[7] = _mm_loadu_si128(m+(i+7)*CRYPTO_KEYBYTES);*/

		mes[0] = _mm_xor_si128(N[0],mes[0]);
		mes[1] = _mm_xor_si128(N[1],mes[1]);
		mes[2] = _mm_xor_si128(N[2],mes[2]);
		mes[3] = _mm_xor_si128(N[3],mes[3]);
		/*mes[4] = _mm_xor_si128(N[4],mes[4]);
		mes[5] = _mm_xor_si128(N[5],mes[5]);
		mes[6] = _mm_xor_si128(N[6],mes[6]);
		mes[7] = _mm_xor_si128(N[7],mes[7]);*/

		_mm_storeu_si128( (__m128i *)&c[(i  )*CRYPTO_KEYBYTES], mes[0] );
		_mm_storeu_si128( (__m128i *)&c[(i+1)*CRYPTO_KEYBYTES], mes[1] );
		_mm_storeu_si128( (__m128i *)&c[(i+2)*CRYPTO_KEYBYTES], mes[2] );
		_mm_storeu_si128( (__m128i *)&c[(i+3)*CRYPTO_KEYBYTES], mes[3] );
		/*_mm_storeu_si128( (__m128i *)&c[(i+4)*CRYPTO_KEYBYTES], mes[4] );
		_mm_storeu_si128( (__m128i *)&c[(i+5)*CRYPTO_KEYBYTES], mes[5] );
		_mm_storeu_si128( (__m128i *)&c[(i+6)*CRYPTO_KEYBYTES], mes[6] );
		_mm_storeu_si128( (__m128i *)&c[(i+7)*CRYPTO_KEYBYTES], mes[7] );*/

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
	if(fin_mes) // Not sure what to do in this case. Until further notice, I'll just do 10* padding.
	{
		memcpy(M_star,m+numblocks_mes*CRYPTO_KEYBYTES,fin_mes);
		M_star[fin_mes] = 0x80;
		memset(M_star+fin_mes+1,0,CRYPTO_KEYBYTES-(fin_mes+1));
		mes[0] = _mm_loadu_si128(M_star);

		// mes[0] = _mm_xor_si128(mes[0],encrypt_block(nonce,_mm_xor_si128(one_tag,tweaks[0]) ) );

		/* Start of encrypt_block. To encrypt: mes[0] with tweak one_tag xor tweaks[0]. This will be a slow f*cker. */

		tweaks[0] = _mm_xor_si128(one_tag,tweaks[0]);

		tmp = _mm_xor_si128(keys[0],tweaks[0]); // Round key
		idx = _mm_xor_si128(tmp,mes[0]); // Counting coppers

		tweaks[1] = _mm_shuffle_epi8(tweaks[0],h);
		tweaks[2] = _mm_shuffle_epi8(tweaks[1],h);
		tweaks[3] = _mm_shuffle_epi8(tweaks[2],h);
		tweaks[4] = _mm_shuffle_epi8(tweaks[3],h);
		tweaks[5] = _mm_shuffle_epi8(tweaks[4],h);
		tweaks[6] = _mm_shuffle_epi8(tweaks[5],h);
		tweaks[7] = _mm_shuffle_epi8(tweaks[6],h);

		xx[0] = _mm_xor_si128(keys[1],tweaks[1]);
		xx[1] = _mm_xor_si128(keys[2],tweaks[2]);
		xx[2] = _mm_xor_si128(keys[3],tweaks[3]);

		idx = _mm_aesenc_si128(idx,xx[0]);
		idx = _mm_aesenc_si128(idx,xx[1]);
		idx = _mm_aesenc_si128(idx,xx[2]);

		xx[0] = _mm_xor_si128(keys[4],tweaks[4]);
		xx[1] = _mm_xor_si128(keys[5],tweaks[5]);
		xx[2] = _mm_xor_si128(keys[6],tweaks[6]);

		idx = _mm_aesenc_si128(idx,xx[0]);
		idx = _mm_aesenc_si128(idx,xx[1]);
		idx = _mm_aesenc_si128(idx,xx[2]);

		xx[0] = _mm_xor_si128(keys[7],tweaks[7]);
		xx[1] = _mm_xor_si128(keys[8],tweaks[0]);
		xx[2] = _mm_xor_si128(keys[9],tweaks[1]);

		idx = _mm_aesenc_si128(idx,xx[0]);
		idx = _mm_aesenc_si128(idx,xx[1]);
		idx = _mm_aesenc_si128(idx,xx[2]);

		xx[0] = _mm_xor_si128(keys[10],tweaks[2]);
		xx[1] = _mm_xor_si128(keys[11],tweaks[3]);
		xx[2] = _mm_xor_si128(keys[12],tweaks[4]);

		idx = _mm_aesenc_si128(idx,xx[0]);
		idx = _mm_aesenc_si128(idx,xx[1]);
		idx = _mm_aesenc_si128(idx,xx[2]);

		xx[0] = _mm_xor_si128(keys[13],tweaks[5]);
		xx[1] = _mm_xor_si128(keys[14],tweaks[6]);

		idx = _mm_aesenc_si128(idx,tmp);


		mes[0] = _mm_xor_si128(mes[0],idx );
		_mm_storeu_si128( (__m128i *)&C_star[0], mes[0] );
		memcpy(c+numblocks_mes*CRYPTO_KEYBYTES,C_star,fin_mes);
	}
	*clen = mlen+CRYPTO_ABYTES;
	return 0;
}
