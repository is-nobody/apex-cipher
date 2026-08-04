#ifndef CIPHER_OPS_H
#define CIPHER_OPS_H

#include <stdint.h>
#include <stddef.h>
#include "sbox.h"
#include "keygen.h"
#include "kdf.h"
#include "hmac.h"
#include "hash.h"

typedef struct {
    uint8_t enc_key[KDF_DERIVED_KEY_SIZE];
    uint8_t mac_key[KDF_DERIVED_KEY_SIZE];
    uint8_t round_keys[ROUNDS + 1][BLOCK_SIZE];
    uint8_t hmac_key[HMAC_BLOCK_SIZE];
} CipherContext;

int cipher_ctx_init_encrypt(CipherContext *ctx, 
                            const uint8_t *master_key, size_t key_len,
                            const uint8_t *salt);

int cipher_ctx_init_decrypt(CipherContext *ctx,
                            const uint8_t *master_key, size_t key_len,
                            const uint8_t *salt);

void cipher_cbc_encrypt_block(uint8_t *block,
                              uint8_t *prev,
                              CipherContext *ctx,
                              HASH_CTX *hmac_ctx);

void cipher_cbc_decrypt_block(const uint8_t *encrypted_block,
                              uint8_t *decrypted_block,
                              uint8_t *prev,
                              CipherContext *ctx);

void cipher_add_pkcs7_padding(uint8_t *block, size_t data_len, size_t block_size);
int cipher_remove_pkcs7_padding(uint8_t *block, size_t block_size, size_t *data_len);

void cipher_hmac_init(HASH_CTX *ctx, CipherContext *cipher_ctx);
void cipher_hmac_update_header(HASH_CTX *ctx, 
                               const uint8_t *size_bytes,
                               const uint8_t *salt,
                               const uint8_t *iv);
void cipher_hmac_update_data(HASH_CTX *ctx, const uint8_t *data, size_t len);
void cipher_hmac_final(HASH_CTX *ctx, CipherContext *cipher_ctx, uint8_t *mac);

int cipher_ct_memcmp(const uint8_t *a, const uint8_t *b, size_t len);

void cipher_secure_zero(void *ptr, size_t len);

void cipher_ctx_cleanup(CipherContext *ctx);

#endif