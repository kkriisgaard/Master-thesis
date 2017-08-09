#include "Skinny128128AVX2.h"
#include <string.h>

/* Code based on https://github.com/kste/skinny_avx */

u256 the_key[32];

extern void pack_key(u256 x[32], const unsigned char *in);
extern void pack_message(u256 x[32], const unsigned char *in);
#if DEBUG
extern void print256_asint(const u256 in);
#endif

#if IDX_PROP
extern unsigned char the_tweak[1024];
#endif

#if (IDX_PROP || PRECOMPUTE)
u256 add_tweak[48][16];
#endif



const unsigned char RC[62] = {
    0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
    0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
    0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
    0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A,
    0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04, 0x09, 0x13,
    0x26, 0x0c, 0x19, 0x32, 0x25, 0x0a, 0x15, 0x2a, 0x14, 0x28,
    0x10, 0x20};
	
#if IDX_PROP
void increment_tweak(){ // This is absolutely disgusting, but it works.
	
	unsigned char ch = 64;
	int i,j;
	u256 tk3[32],tmp[32];
	pack_message(tk3,the_tweak); // Packing the tweak
	
	for(j = 0; j < 48; j++) { // Updating the tweak

		for(i = 0; i < 16; i++){ 
			add_tweak[j][i] = tk3[i];
		  
		}
		
		//Add constant into key
		u256 rc = _mm256_set_epi64x(0x000000FF000000FFull,
									0x000000FF000000FFull,
									0x000000FF000000FFull,
									0x000000FF000000FFull);

		if(RC[j]>>5 & 1) 
		  add_tweak[j][14] = XOR(add_tweak[j][14], rc);
		if(RC[j]>>4 & 1)
		  add_tweak[j][15] = XOR(add_tweak[j][15], rc);
		if(RC[j]>>3 & 1)
		  add_tweak[j][4] = XOR(add_tweak[j][4], rc);
		if(RC[j]>>2 & 1)
		  add_tweak[j][5] = XOR(add_tweak[j][5], rc);
		if(RC[j]>>1 & 1)
		  add_tweak[j][6] = XOR(add_tweak[j][6], rc);
		if(RC[j]>>0 & 1) /* What? */
		  add_tweak[j][7] = XOR(add_tweak[j][7], rc);

		//Update TK1
		for(i = 0; i < 16; i++){
		  tmp[16 + i] = tk3[0 + i];
		}

		//Apply bit permutation /*PT !*/
		for(i = 0; i < 8; i++){
		  tmp[0 + i] = XOR(_mm256_shuffle_epi8(tk3[16  + i], _mm256_set_epi8(0xff,28,0xff,29,0xff,24,0xff,25,0xff,20,0xff,21,0xff,16,0xff,17,0xff,12,0xff,13,0xff,8,0xff,9,0xff,4,0xff,5,0xff,0,0xff,1)),
						   _mm256_shuffle_epi8(tk3[24  + i], _mm256_set_epi8(29,0xff,31,0xff,25,0xff,27,0xff,21,0xff,23,0xff,17,0xff,19,0xff,13,0xff,15,0xff,9,0xff,11,0xff,5,0xff,7,0xff,1,0xff,3,0xff)));
		  tmp[8 + i] = XOR(_mm256_shuffle_epi8(tk3[16  + i], _mm256_set_epi8(31,0xff,0xff,30,27,0xff,0xff,26,23,0xff,0xff,22,19,0xff,0xff,18,15,0xff,0xff,14,11,0xff,0xff,10,7,0xff,0xff,6,3,0xff,0xff,2)),
						   _mm256_shuffle_epi8(tk3[24  + i], _mm256_set_epi8(0xff,28,30,0xff,0xff,24,26,0xff,0xff,20,22,0xff,0xff,16,18,0xff,0xff,12,14,0xff,0xff,8,10,0xff,0xff,4,6,0xff,0xff,0,2,0xff)));
		}

		for(i = 0; i < 32; i++){
		  tk3[i] = tmp[i];
		}
	}
	
  unsigned long long *ptr;
	 for(j=0;j<64;++j){
	 	  ptr = &the_tweak[16*j+8]; // Pointer abuse for simple increments
		  
		(*ptr) += ch;
		
  }
  
				  
}

#elif PRECOMPUTE

void expand_tweak(unsigned long long offset, u256 *tw){ // This is absolutely disgusting, but it works.
	
	int i,j;
	u256 tmp[32],tk3[32];
	
	
		for(i=0;i<32;++i){
			tk3[i] = tw[i+offset];
		}
	
	
	for(j = 0; j < 48; j++) { // Updating the tweak
		for(i = 0; i < 16; i++){ 
			add_tweak[j][i] ^= add_tweak[j][i];
			add_tweak[j][i] = tk3[i];
		}
		
		//Add constant into key
		u256 rc = _mm256_set_epi64x(0x000000FF000000FFull,
									0x000000FF000000FFull,
									0x000000FF000000FFull,
									0x000000FF000000FFull);

		if(RC[j]>>5 & 1) 
		  add_tweak[j][14] = XOR(add_tweak[j][14], rc);
		if(RC[j]>>4 & 1)
		  add_tweak[j][15] = XOR(add_tweak[j][15], rc);
		if(RC[j]>>3 & 1)
		  add_tweak[j][4] = XOR(add_tweak[j][4], rc);
		if(RC[j]>>2 & 1)
		  add_tweak[j][5] = XOR(add_tweak[j][5], rc);
		if(RC[j]>>1 & 1)
		  add_tweak[j][6] = XOR(add_tweak[j][6], rc);
		if(RC[j]>>0 & 1) /* What? */
		  add_tweak[j][7] = XOR(add_tweak[j][7], rc);

		//Update TK3
		for(i = 0; i < 16; i++){
		  tmp[16 + i] = tk3[0 + i];
		}

		//Apply bit permutation /*PT !*/
		for(i = 0; i < 8; i++){
		  tmp[0 + i] = XOR(_mm256_shuffle_epi8(tk3[16  + i], _mm256_set_epi8(0xff,28,0xff,29,0xff,24,0xff,25,0xff,20,0xff,21,0xff,16,0xff,17,0xff,12,0xff,13,0xff,8,0xff,9,0xff,4,0xff,5,0xff,0,0xff,1)),
						   _mm256_shuffle_epi8(tk3[24  + i], _mm256_set_epi8(29,0xff,31,0xff,25,0xff,27,0xff,21,0xff,23,0xff,17,0xff,19,0xff,13,0xff,15,0xff,9,0xff,11,0xff,5,0xff,7,0xff,1,0xff,3,0xff)));
		  tmp[8 + i] = XOR(_mm256_shuffle_epi8(tk3[16  + i], _mm256_set_epi8(31,0xff,0xff,30,27,0xff,0xff,26,23,0xff,0xff,22,19,0xff,0xff,18,15,0xff,0xff,14,11,0xff,0xff,10,7,0xff,0xff,6,3,0xff,0xff,2)),
						   _mm256_shuffle_epi8(tk3[24  + i], _mm256_set_epi8(0xff,28,30,0xff,0xff,24,26,0xff,0xff,20,22,0xff,0xff,16,18,0xff,0xff,12,14,0xff,0xff,8,10,0xff,0xff,4,6,0xff,0xff,0,2,0xff)));
		}

		for(i = 0; i < 32; i++){
		  tk3[i] = tmp[i];
		}
	} 
				  
}
#endif


void encrypt_64blocks(u256 x[32], u256 rk[48][16]) {

  int i, j;
  #if DEBUG
  int z;
  #endif
  u256 rc, tmp[8], t[4];
  rc = _mm256_set_epi64x(0x000000FF000000FFull,
                         0x000000FF000000FFull,
                         0x000000FF000000FFull,
                         0x000000FF000000FFull);
						 
  #if IDX_PROP
	increment_tweak();
	#endif

  
  for(i = 0; i < 48; i++){
  
    //SubBytes
    for(j = 0; j < 4; j++) {
      
      
      t[0] = XOR(x[7 + 8*j],NOR(x[4 + 8*j],x[5 + 8*j]) );
      t[1] = XOR(x[1 + 8*j],NOR(x[5 + 8*j],x[6 + 8*j]) );
      x[1 + 8*j] = XOR(x[3 + 8*j],NOR(x[0 + 8*j],x[1 + 8*j]) );
      
      t[2] = XOR(x[2 + 8*j],NOR(x[1 + 8*j],t[0]) );
      t[3] = XOR(x[6 + 8*j],NOR(t[0],x[4 + 8*j]) );
      x[6 + 8*j] = XOR(x[0 + 8*j],NOR(t[1],t[2]) );
      
      x[0 + 8*j] = t[2];
      x[2 + 8*j] = t[0];
      x[3 + 8*j] = XOR(x[4 + 8*j],NOR(t[2],x[1 + 8*j]) );
      
      x[4 + 8*j] = t[3];
      x[7 + 8*j] = XOR(x[5 + 8*j],NOR(t[3],x[6 + 8*j]) );
      x[5 + 8*j] = t[1];
    }

    //AddConstant
    //This only adds c2. The other constants are added with the key
    x[22] = XOR(x[22], rc);
	  
    //AddKey
    x[0] = XOR(x[0], rk[i][0]);
    x[1] = XOR(x[1], rk[i][1]);
    x[2] = XOR(x[2], rk[i][2]);
    x[3] = XOR(x[3], rk[i][3]);
    x[4] = XOR(x[4], rk[i][4]);
    x[5] = XOR(x[5], rk[i][5]);
    x[6] = XOR(x[6], rk[i][6]);
    x[7] = XOR(x[7], rk[i][7]);
    x[8] = XOR(x[8], rk[i][8]);
    x[9] = XOR(x[9], rk[i][9]);
    x[10] = XOR(x[10], rk[i][10]);
    x[11] = XOR(x[11], rk[i][11]);
    x[12] = XOR(x[12], rk[i][12]);
    x[13] = XOR(x[13], rk[i][13]);
    x[14] = XOR(x[14], rk[i][14]);
    x[15] = XOR(x[15], rk[i][15]);
	

	//Increment tweak
	#if (IDX_PROP || PRECOMPUTE)
	x[0] = XOR(x[0], add_tweak[i][0]);
    x[1] = XOR(x[1], add_tweak[i][1]);
    x[2] = XOR(x[2], add_tweak[i][2]);
    x[3] = XOR(x[3], add_tweak[i][3]);
    x[4] = XOR(x[4], add_tweak[i][4]);
    x[5] = XOR(x[5], add_tweak[i][5]);
    x[6] = XOR(x[6], add_tweak[i][6]);
    x[7] = XOR(x[7], add_tweak[i][7]);
    x[8] = XOR(x[8], add_tweak[i][8]);
    x[9] = XOR(x[9], add_tweak[i][9]);
    x[10] = XOR(x[10], add_tweak[i][10]);
    x[11] = XOR(x[11], add_tweak[i][11]);
    x[12] = XOR(x[12], add_tweak[i][12]);
    x[13] = XOR(x[13], add_tweak[i][13]);
    x[14] = XOR(x[14], add_tweak[i][14]);
    x[15] = XOR(x[15], add_tweak[i][15]);
	#endif
	
	
    //ShiftRows
    x[8]  = SR1(x[8]);  x[16] = SR2(x[16]); x[24] = SR3(x[24]);
    x[9]  = SR1(x[9]);  x[17] = SR2(x[17]); x[25] = SR3(x[25]);
    x[10] = SR1(x[10]); x[18] = SR2(x[18]); x[26] = SR3(x[26]);
    x[11] = SR1(x[11]); x[19] = SR2(x[19]); x[27] = SR3(x[27]);
    x[12] = SR1(x[12]); x[20] = SR2(x[20]); x[28] = SR3(x[28]);
    x[13] = SR1(x[13]); x[21] = SR2(x[21]); x[29] = SR3(x[29]);
    x[14] = SR1(x[14]); x[22] = SR2(x[22]); x[30] = SR3(x[30]);
    x[15] = SR1(x[15]); x[23] = SR2(x[23]); x[31] = SR3(x[31]);

    //MixColumns
    tmp[0] = x[24]; tmp[1] = x[25]; tmp[2] = x[26]; tmp[3] = x[27];
    tmp[4] = x[28]; tmp[5] = x[29]; tmp[6] = x[30]; tmp[7] = x[31];

    x[24] = XOR(x[16], x[0]); x[28] = XOR(x[20], x[4]);
    x[25] = XOR(x[17], x[1]); x[29] = XOR(x[21], x[5]);
    x[26] = XOR(x[18], x[2]); x[30] = XOR(x[22], x[6]);
    x[27] = XOR(x[19], x[3]); x[31] = XOR(x[23], x[7]);

    x[16] = XOR(x[8],  x[16]); x[20] = XOR(x[12], x[20]);
    x[17] = XOR(x[9],  x[17]); x[21] = XOR(x[13], x[21]);
    x[18] = XOR(x[10], x[18]); x[22] = XOR(x[14], x[22]);
    x[19] = XOR(x[11], x[19]); x[23] = XOR(x[15], x[23]);

    x[8]  = x[0]; x[12] = x[4];
    x[9]  = x[1]; x[13] = x[5];
    x[10] = x[2]; x[14] = x[6];
    x[11] = x[3]; x[15] = x[7];


    x[0] = XOR(tmp[0], x[24]); x[4] = XOR(tmp[4], x[28]);
    x[1] = XOR(tmp[1], x[25]); x[5] = XOR(tmp[5], x[29]);
    x[2] = XOR(tmp[2], x[26]); x[6] = XOR(tmp[6], x[30]);
    x[3] = XOR(tmp[3], x[27]); x[7] = XOR(tmp[7], x[31]); 
  }
}	


void key_schedule(const unsigned char *k, u256 rk[48][16]) {

  int i, j;
  u256 tk1[32], tmp[32],tk2[32];
  #if (IDX_PROP)
  u256 tk3[32];
  #endif

  unsigned char *tmp_key = malloc(32);
  
  #if IDX_PROP
  unsigned char ch = 0;
  unsigned long long *ptr;
  
  for(j=0;j<64;++j){
	  for(i=0;i<16;++i){
		  the_tweak[16*j+i] = 0;
	  }
	  ptr = &the_tweak[16*j+8]; // Pointer abuse for simple increments
	  (*ptr) += ch;
	  
	  ++ch;
	  
  }
    
  #elif !PRECOMPUTE
  for(i = 0; i < 2; i++){ /* Tweak*/
	memcpy(tmp_key + 16*i, k, 16); 
  }
  pack_key(tk1, tmp_key);
  #endif
  
  
  
  #if TEST_DEOXYS
  for(i = 0; i < 2; i++){ /*Key*/
    memcpy(tmp_key + 16*i, k, 16); 
  }
  #else
  for(i = 0; i < 2; i++){ /*Key*/
    memcpy(tmp_key + 16*i, k+16, 16); 
  }
	#endif
  pack_key(tk2, tmp_key);

  

for(j = 0; j < 48; j++) {

	#if (IDX_PROP || PRECOMPUTE)
	for(i = 0; i < 16; i++){ 
		rk[j][i] = tk2[i];
    }
	
	/* #if !IDX_PROP
	//Add constant into key
    u256 rc = _mm256_set_epi64x(0x000000FF000000FFull,
                                0x000000FF000000FFull,
                                0x000000FF000000FFull,
                                0x000000FF000000FFull);

    if(RC[j]>>5 & 1) 
      rk[j][14] = XOR(rk[j][14], rc);
    if(RC[j]>>4 & 1)
      rk[j][15] = XOR(rk[j][15], rc);
    if(RC[j]>>3 & 1)
      rk[j][4] = XOR(rk[j][4], rc);
    if(RC[j]>>2 & 1)
      rk[j][5] = XOR(rk[j][5], rc);
    if(RC[j]>>1 & 1)
      rk[j][6] = XOR(rk[j][6], rc);
    if(RC[j]>>0 & 1) 
      rk[j][7] = XOR(rk[j][7], rc);

    //Update TK1
    for(i = 0; i < 16; i++){
      tmp[16 + i] = tk3[0 + i];
    }

    //Apply bit permutation
    for(i = 0; i < 8; i++){
      tmp[0 + i] = XOR(_mm256_shuffle_epi8(tk3[16  + i], _mm256_set_epi8(0xff,28,0xff,29,0xff,24,0xff,25,0xff,20,0xff,21,0xff,16,0xff,17,0xff,12,0xff,13,0xff,8,0xff,9,0xff,4,0xff,5,0xff,0,0xff,1)),
                       _mm256_shuffle_epi8(tk3[24  + i], _mm256_set_epi8(29,0xff,31,0xff,25,0xff,27,0xff,21,0xff,23,0xff,17,0xff,19,0xff,13,0xff,15,0xff,9,0xff,11,0xff,5,0xff,7,0xff,1,0xff,3,0xff)));
      tmp[8 + i] = XOR(_mm256_shuffle_epi8(tk3[16  + i], _mm256_set_epi8(31,0xff,0xff,30,27,0xff,0xff,26,23,0xff,0xff,22,19,0xff,0xff,18,15,0xff,0xff,14,11,0xff,0xff,10,7,0xff,0xff,6,3,0xff,0xff,2)),
                       _mm256_shuffle_epi8(tk3[24  + i], _mm256_set_epi8(0xff,28,30,0xff,0xff,24,26,0xff,0xff,20,22,0xff,0xff,16,18,0xff,0xff,12,14,0xff,0xff,8,10,0xff,0xff,4,6,0xff,0xff,0,2,0xff)));
    }

    for(i = 0; i < 32; i++){
      tk3[i] = tmp[i];
    }
	#endif // !IDX_PROP */ 
	
	#else
    //Extract round key
    for(i = 0; i < 16; i++){ 
	  rk[j][i] = XOR(tk1[i], tk2[i]);
	  
    }
	#endif

	
    //Add constant into key
    u256 rc = _mm256_set_epi64x(0x000000FF000000FFull,
                                0x000000FF000000FFull,
                                0x000000FF000000FFull,
                                0x000000FF000000FFull);

    if(RC[j]>>5 & 1) /* This is confusing.*/
      rk[j][14] = XOR(rk[j][14], rc);
    if(RC[j]>>4 & 1)
      rk[j][15] = XOR(rk[j][15], rc);
    if(RC[j]>>3 & 1)
      rk[j][4] = XOR(rk[j][4], rc);
    if(RC[j]>>2 & 1)
      rk[j][5] = XOR(rk[j][5], rc);
    if(RC[j]>>1 & 1)
      rk[j][6] = XOR(rk[j][6], rc);
    if(RC[j]>>0 & 1) /* What? */
      rk[j][7] = XOR(rk[j][7], rc);

	  #if !(IDX_PROP || PRECOMPUTE)
    //Update TK1
    for(i = 0; i < 16; i++){
      tmp[16 + i] = tk1[0 + i];
    }

    //Apply bit permutation /*PT !*/
    for(i = 0; i < 8; i++){
      tmp[0 + i] = XOR(_mm256_shuffle_epi8(tk1[16  + i], _mm256_set_epi8(0xff,28,0xff,29,0xff,24,0xff,25,0xff,20,0xff,21,0xff,16,0xff,17,0xff,12,0xff,13,0xff,8,0xff,9,0xff,4,0xff,5,0xff,0,0xff,1)),
                       _mm256_shuffle_epi8(tk1[24  + i], _mm256_set_epi8(29,0xff,31,0xff,25,0xff,27,0xff,21,0xff,23,0xff,17,0xff,19,0xff,13,0xff,15,0xff,9,0xff,11,0xff,5,0xff,7,0xff,1,0xff,3,0xff)));
      tmp[8 + i] = XOR(_mm256_shuffle_epi8(tk1[16  + i], _mm256_set_epi8(31,0xff,0xff,30,27,0xff,0xff,26,23,0xff,0xff,22,19,0xff,0xff,18,15,0xff,0xff,14,11,0xff,0xff,10,7,0xff,0xff,6,3,0xff,0xff,2)),
                       _mm256_shuffle_epi8(tk1[24  + i], _mm256_set_epi8(0xff,28,30,0xff,0xff,24,26,0xff,0xff,20,22,0xff,0xff,16,18,0xff,0xff,12,14,0xff,0xff,8,10,0xff,0xff,4,6,0xff,0xff,0,2,0xff)));
    }

    for(i = 0; i < 32; i++){
      tk1[i] = tmp[i];
    }
    
	#endif
	
	//Update TK2
    for(i = 0; i < 16; i++){
      tmp[16 + i] = tk2[0 + i];
    }

    //Apply bit permutation /*PT !*/
    for(i = 0; i < 8; i++){ 
      tmp[0 + i] = XOR(_mm256_shuffle_epi8(tk2[16  + i], _mm256_set_epi8(0xff,28,0xff,29,0xff,24,0xff,25,0xff,20,0xff,21,0xff,16,0xff,17,0xff,12,0xff,13,0xff,8,0xff,9,0xff,4,0xff,5,0xff,0,0xff,1)),
                       _mm256_shuffle_epi8(tk2[24  + i], _mm256_set_epi8(29,0xff,31,0xff,25,0xff,27,0xff,21,0xff,23,0xff,17,0xff,19,0xff,13,0xff,15,0xff,9,0xff,11,0xff,5,0xff,7,0xff,1,0xff,3,0xff)));
      tmp[8 + i] = XOR(_mm256_shuffle_epi8(tk2[16  + i], _mm256_set_epi8(31,0xff,0xff,30,27,0xff,0xff,26,23,0xff,0xff,22,19,0xff,0xff,18,15,0xff,0xff,14,11,0xff,0xff,10,7,0xff,0xff,6,3,0xff,0xff,2)),
                       _mm256_shuffle_epi8(tk2[24  + i], _mm256_set_epi8(0xff,28,30,0xff,0xff,24,26,0xff,0xff,20,22,0xff,0xff,16,18,0xff,0xff,12,14,0xff,0xff,8,10,0xff,0xff,4,6,0xff,0xff,0,2,0xff)));
    }

	
	tk2[7] = XOR(tmp[0],tmp[2]);  // Reverse order
	tk2[6] = tmp[7];
	tk2[5] = tmp[6];
	tk2[4] = tmp[5];
	tk2[3] = tmp[4];
	tk2[2] = tmp[3];
	tk2[1] = tmp[2];
	tk2[0] = tmp[1];
	
	tk2[7+8] = XOR(tmp[0+8],tmp[2+8]); 
	tk2[6+8] = tmp[7+8];
	tk2[5+8] = tmp[6+8];
	tk2[4+8] = tmp[5+8];
	tk2[3+8] = tmp[4+8];
	tk2[2+8] = tmp[3+8];
	tk2[1+8] = tmp[2+8];
	tk2[0+8] = tmp[1+8]; // */
	   
	
	for(i = 16; i < 32; i++){ /*This damn loop cost me 2 days of work*/
      tk2[i] = tmp[i];
    }
	

  }

  
}


