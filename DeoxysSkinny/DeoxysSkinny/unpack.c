#include "Skinny128128AVX2.h"
#include <stdio.h>

#if DEBUG
extern void print256_asint(const u256 in);
#endif


void pack_tweak(u256 *x, const unsigned char *in, unsigned long long offset) {
  int i;
  for(i = 0; i < 32; i++) { /*Fixed length*/
    x[i+ offset] = LOAD(in + i*32);
	
  }
  //Seperate bits for S-box
  for(i = 0; i < 4; i++) {
    SWAPMOVE(x[8*i + 0+ offset], x[8*i + 1+ offset], MASK1, 1);
    SWAPMOVE(x[8*i + 2+ offset], x[8*i + 3+ offset], MASK1, 1);
    SWAPMOVE(x[8*i + 4+ offset], x[8*i + 5+ offset], MASK1, 1);
    SWAPMOVE(x[8*i + 6+ offset], x[8*i + 7+ offset], MASK1, 1);

    SWAPMOVE(x[8*i + 0+ offset], x[8*i + 2+ offset], MASK2, 2);
    SWAPMOVE(x[8*i + 1+ offset], x[8*i + 3+ offset], MASK2, 2);
    SWAPMOVE(x[8*i + 4+ offset], x[8*i + 6+ offset], MASK2, 2);
    SWAPMOVE(x[8*i + 5+ offset], x[8*i + 7+ offset], MASK2, 2);

    SWAPMOVE(x[8*i + 0+ offset], x[8*i + 4+ offset], MASK4, 4);
    SWAPMOVE(x[8*i + 1+ offset], x[8*i + 5+ offset], MASK4, 4);
    SWAPMOVE(x[8*i + 2+ offset], x[8*i + 6+ offset], MASK4, 4);
    SWAPMOVE(x[8*i + 3+ offset], x[8*i + 7+ offset], MASK4, 4);    
	
  }
	
  //Group the rows for efficient MixColumns implementation
  for(i = 0; i < 8; i++) {
    SWAPMOVE(x[i + 8+ offset], x[i + 0+ offset], MASK32, 32);
    SWAPMOVE(x[i + 24+ offset], x[i + 16+ offset], MASK32, 32);
    
    SWAPMOVEBY64(x[i + 16+ offset], x[i + 0+ offset], MASK64);
    SWAPMOVEBY64(x[i + 24+ offset], x[i + 8+ offset], MASK64);    
  }
}

void pack_message(u256 x[32], const unsigned char *in) {
  int i;

	
  for(i = 0; i < 32; i++) { /*Fixed length*/
    x[i] = LOAD(in + i*32);
  }

  //Seperate bits for S-box
  for(i = 0; i < 4; i++) {
    SWAPMOVE(x[8*i + 0], x[8*i + 1], MASK1, 1);
    SWAPMOVE(x[8*i + 2], x[8*i + 3], MASK1, 1);
    SWAPMOVE(x[8*i + 4], x[8*i + 5], MASK1, 1);
    SWAPMOVE(x[8*i + 6], x[8*i + 7], MASK1, 1);

    SWAPMOVE(x[8*i + 0], x[8*i + 2], MASK2, 2);
    SWAPMOVE(x[8*i + 1], x[8*i + 3], MASK2, 2);
    SWAPMOVE(x[8*i + 4], x[8*i + 6], MASK2, 2);
    SWAPMOVE(x[8*i + 5], x[8*i + 7], MASK2, 2);

    SWAPMOVE(x[8*i + 0], x[8*i + 4], MASK4, 4);
    SWAPMOVE(x[8*i + 1], x[8*i + 5], MASK4, 4);
    SWAPMOVE(x[8*i + 2], x[8*i + 6], MASK4, 4);
    SWAPMOVE(x[8*i + 3], x[8*i + 7], MASK4, 4);    
  }

  //Group the rows for efficient MixColumns implementation
  for(i = 0; i < 8; i++) {
    SWAPMOVE(x[i + 8], x[i + 0], MASK32, 32);
    SWAPMOVE(x[i + 24], x[i + 16], MASK32, 32);
    
    SWAPMOVEBY64(x[i + 16], x[i + 0], MASK64);
    SWAPMOVEBY64(x[i + 24], x[i + 8], MASK64);    
  }
}

void pack_key(u256 x[32], const unsigned char *in) {
  int i;
	// printf("Printing load results:\n");
  //Load same key for all blocks
  for(i = 0; i < 32; i++) {
    x[i] = LOAD(in);
	// print256_asint(x[i]);
  }

  //Seperate bits for S-box
  for(i = 0; i < 4; i++) {
    SWAPMOVE(x[8*i + 0], x[8*i + 1], MASK1, 1);
    SWAPMOVE(x[8*i + 2], x[8*i + 3], MASK1, 1);
    SWAPMOVE(x[8*i + 4], x[8*i + 5], MASK1, 1);
    SWAPMOVE(x[8*i + 6], x[8*i + 7], MASK1, 1);

    SWAPMOVE(x[8*i + 0], x[8*i + 2], MASK2, 2);
    SWAPMOVE(x[8*i + 1], x[8*i + 3], MASK2, 2);
    SWAPMOVE(x[8*i + 4], x[8*i + 6], MASK2, 2);
    SWAPMOVE(x[8*i + 5], x[8*i + 7], MASK2, 2);

    SWAPMOVE(x[8*i + 0], x[8*i + 4], MASK4, 4);
    SWAPMOVE(x[8*i + 1], x[8*i + 5], MASK4, 4);
    SWAPMOVE(x[8*i + 2], x[8*i + 6], MASK4, 4);
    SWAPMOVE(x[8*i + 3], x[8*i + 7], MASK4, 4);    
  }

  //Group the rows for efficient MixColumns implementation 
  for(i = 0; i < 8; i++) {
    SWAPMOVE(x[i + 8], x[i + 0], MASK32, 32);
    SWAPMOVE(x[i + 24], x[i + 16], MASK32, 32);
    
    SWAPMOVEBY64(x[i + 16], x[i + 0], MASK64);
    SWAPMOVEBY64(x[i + 24], x[i + 8], MASK64);    
  }
}

//Unpacking
void unpack_and_store_message(unsigned char *out, u256 x[32]) {
  int i;

  //Group the rows for efficient MixColumns implementation
  for(i = 0; i < 8; i++) {
    SWAPMOVE(x[i + 8], x[i + 0], MASK32, 32);
    SWAPMOVE(x[i + 24], x[i + 16], MASK32, 32);
    
    SWAPMOVEBY64(x[i + 16], x[i + 0], MASK64);
    SWAPMOVEBY64(x[i + 24], x[i + 8], MASK64);    
  }

  //Seperate bits for S-box
  for(i = 0; i < 4; i++) {
    SWAPMOVE(x[8*i + 0], x[8*i + 1], MASK1, 1);
    SWAPMOVE(x[8*i + 2], x[8*i + 3], MASK1, 1);
    SWAPMOVE(x[8*i + 4], x[8*i + 5], MASK1, 1);
    SWAPMOVE(x[8*i + 6], x[8*i + 7], MASK1, 1);

    SWAPMOVE(x[8*i + 0], x[8*i + 2], MASK2, 2);
    SWAPMOVE(x[8*i + 1], x[8*i + 3], MASK2, 2);
    SWAPMOVE(x[8*i + 4], x[8*i + 6], MASK2, 2);
    SWAPMOVE(x[8*i + 5], x[8*i + 7], MASK2, 2);

    SWAPMOVE(x[8*i + 0], x[8*i + 4], MASK4, 4);
    SWAPMOVE(x[8*i + 1], x[8*i + 5], MASK4, 4);
    SWAPMOVE(x[8*i + 2], x[8*i + 6], MASK4, 4);
    SWAPMOVE(x[8*i + 3], x[8*i + 7], MASK4, 4);    
  }  

  for(i = 0; i < 32; i++) {
    STORE(out + 32*i, x[i]);
  }
}
