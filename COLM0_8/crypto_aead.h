#ifndef CRYPTO_AEAD
#define CRYPTO_AEAD

// Do NOT include in benchmarking, except local!!

int crypto_aead_encrypt(
       unsigned char *c,unsigned long long *clen, // c = cipher, clen = cipher length - not const, as they may change in size.
       const unsigned char *m,unsigned long long mlen,
       const unsigned char *ad,unsigned long long adlen, // 
       const unsigned char *nsec, // = param??
       const unsigned char *npub, // = nonce
       const unsigned char *k
     );

int crypto_aead_decrypt(
       unsigned char *m,unsigned long long *mlen, 
       unsigned char *nsec,
       const unsigned char *c,unsigned long long clen,
       const unsigned char *ad,unsigned long long adlen,
       const unsigned char *npub,
       const unsigned char *k
     );


#endif // CRYPTO_AEAD
