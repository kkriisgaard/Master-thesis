#include <stdio.h>
#include "emmintrin.h"
#include "wmmintrin.h"
#include "tmmintrin.h"
#include "debugfuncs.h"
 
void print128_aschar(__m128i p) // Print 128-bit block as characters
{
	const unsigned char val[16];
	_mm_storeu_si128( (__m128i *)&val[0], p ); 
	printf("%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c \n", val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7], val[8], val[9], val[10], val[11], val[12], val[13], val[14], val[15]); 
} 

void print128_asint(const __m128i p) // Print 128-bit block as integer
{
	const unsigned char val[16];
	_mm_storeu_si128( (__m128i *)&val[0], p ); 
	printf("%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d \n", val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7], val[8], val[9], val[10], val[11], val[12], val[13], val[14], val[15]); 
} 
