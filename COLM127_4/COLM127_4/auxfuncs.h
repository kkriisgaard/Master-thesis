#ifndef AUX_FUNC
#define AUX_FUNC

/*#define CRYPTO_KEYBYTES 16
#define CRYPTO_NPUBBYTES 8
*/
// Print functions may be removable. Thery were really useful throughout debugging.
/*
void print128_aschar(__m128i p);

void print128_asint(__m128i p); // */

// Constants - I'd really prefer that I could just leave these in.

__m128i mul2(__m128i x); // Small scale, deserves testing

//keys

__m128i keys[20];

__m128i key_exp_assist(__m128i t1, __m128i t2);

void generate_aes_key(__m128i key);

__m128i encrypt_block(__m128i pt); 

__m128i decrypt_block(__m128i ct); 

// void encrypt_8block(__m128i* in, __m128i* out);

void encrypt_8block2(__m128i* in);

// void decrypt_8block(__m128i* in, __m128i* out);

void decrypt_8block2(__m128i* in);


#endif //AUX_FUNC
