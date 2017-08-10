/*
Constants, parameters and intrinsics used for the implementation of 
Skinny128/128.
*/

#ifndef SKINNY128128AVX2_H
#define SKINNY128128AVX2_H
#include "immintrin.h"

//Types
#define u16 unsigned short
#define u32 unsigned
#define u64 unsigned long long
#define u256 __m256i

//Intrinsics
#define XOR _mm256_xor_si256
#define AND _mm256_and_si256
#define ANDNOT _mm256_andnot_si256
#define OR _mm256_or_si256
#define NOT(x) _mm256_xor_si256(x, _mm256_set_epi32(-1, -1, -1, -1, -1, -1, -1, -1))
#define NOR(x, y) _mm256_xor_si256(_mm256_or_si256(x, y), _mm256_set_epi32(-1, -1, -1, -1, -1, -1, -1, -1))
#define SHIFTR64(x, y) _mm256_srli_epi64(x, y)
#define SHIFTL64(x, y) _mm256_slli_epi64(x, y)

#define SR1(x) _mm256_shuffle_epi8(x, _mm256_set_epi8(30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0,31))
#define SR2(x) _mm256_shuffle_epi8(x, _mm256_set_epi8(29,28,27,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0,31,30))
#define SR3(x) _mm256_shuffle_epi8(x, _mm256_set_epi8(28,27,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0,31,30,29))

#define LOAD(src) _mm256_loadu_si256((__m256i *)(src))
#define STORE(dest,src) _mm256_storeu_si256((__m256i *)(dest),src)

#define MASK1 _mm256_set_epi32(0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa)
#define MASK2 _mm256_set_epi32(0xcccccccc, 0xcccccccc, 0xcccccccc, 0xcccccccc, 0xcccccccc, 0xcccccccc, 0xcccccccc, 0xcccccccc)
#define MASK4 _mm256_set_epi32(0xf0f0f0f0, 0xf0f0f0f0, 0xf0f0f0f0, 0xf0f0f0f0, 0xf0f0f0f0, 0xf0f0f0f0, 0xf0f0f0f0, 0xf0f0f0f0)
#define MASK32 _mm256_set_epi32(0xffffffff, 0x00000000, 0xffffffff, 0x00000000, 0xffffffff, 0x00000000, 0xffffffff, 0x00000000)
#define MASK64 _mm256_set_epi32(0xffffffff, 0xffffffff, 0x00000000, 0x00000000, 0xffffffff, 0xffffffff, 0x00000000, 0x00000000)

#define SWAPMOVE(a, b, mask, shift) \
{ \
	u256 T = AND(XOR(SHIFTL64(a, shift), b), mask); \
	b = XOR(b, T); \
    a = XOR(a, SHIFTR64(T, shift)); \
}

//Swap move for shifting by 64
#define SWAPMOVEBY64(a, b, mask) \
{ \
	u256 T = AND(XOR(_mm256_shuffle_epi8(a, _mm256_set_epi8(23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0,31,30,29,28,27,26,25,24)), b), mask); \
	b = XOR(b, T); \
    a = XOR(a, _mm256_shuffle_epi8(T, _mm256_set_epi8(7,6,5,4,3,2,1,0,31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8))); \
}

/*Kristian's defines. To run with Deoxys-like tweaks, do not modify*/
#define TWEAK 1
#define TEST_FUNCTIONALITY 0
#define DEBUG 0
#define TIMED_RUN (1 && (!TEST_FUNCTIONALITY && !DEBUG) )
#define IDX_PROP (TWEAK && 0) 
#define PRECOMPUTE (TWEAK && 1)
#define TEST_DEOXYS ( (IDX_PROP||PRECOMPUTE) && 1)
#define VERIFY_OUTPUT (TEST_DEOXYS && 0)
#endif
