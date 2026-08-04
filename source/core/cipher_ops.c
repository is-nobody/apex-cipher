#include "cipher_ops.h"
#include "encrypt_decrypt.h"
#include <string.h>
#include <stdlib.h>

void cipher_secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

int cipher_ct_memcmp(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff;
}

int cipher_ctx_init_encrypt(CipherContext *ctx,
                            const uint8_t *master_key, size_t key_len,
                            const uint8_t *salt) {
    uint8_t enc_salt[KDF_SALT_SIZE + 3];
    uint8_t mac_salt[KDF_SALT_SIZE + 3];
    
    memcpy(enc_salt, salt, KDF_SALT_SIZE);
    enc_salt[KDF_SALT_SIZE] = 'E';
    enc_salt[KDF_SALT_SIZE + 1] = 'N';
    enc_salt[KDF_SALT_SIZE + 2] = 'C';
    
    memcpy(mac_salt, salt, KDF_SALT_SIZE);
    mac_salt[KDF_SALT_SIZE] = 'M';
    mac_salt[KDF_SALT_SIZE + 1] = 'A';
    mac_salt[KDF_SALT_SIZE + 2] = 'C';
    
    if (kdf_derive(master_key, key_len, enc_salt, KDF_SALT_SIZE + 3, 
                   KDF_ITERATIONS, ctx->enc_key, KDF_DERIVED_KEY_SIZE) != 0) {
        return -1;
    }
    
    if (kdf_derive(master_key, key_len, mac_salt, KDF_SALT_SIZE + 3,
                   KDF_ITERATIONS, ctx->mac_key, KDF_DERIVED_KEY_SIZE) != 0) {
        cipher_secure_zero(ctx->enc_key, sizeof(ctx->enc_key));
        return -1;
    }
    
    keygen_expand(ctx->enc_key, KDF_DERIVED_KEY_SIZE, ctx->round_keys);
    
    memset(ctx->hmac_key, 0, HMAC_BLOCK_SIZE);
    memcpy(ctx->hmac_key, ctx->mac_key, KDF_DERIVED_KEY_SIZE);
    
    return 0;
}

int cipher_ctx_init_decrypt(CipherContext *ctx,
                            const uint8_t *master_key, size_t key_len,
                            const uint8_t *salt) {
    return cipher_ctx_init_encrypt(ctx, master_key, key_len, salt);
}

void cipher_cbc_encrypt_block(uint8_t *block,
                              uint8_t *prev,
                              CipherContext *ctx,
                              HASH_CTX *hmac_ctx) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        block[i] ^= prev[i];
    }
    
    encrypt_block(block, ctx->round_keys);
    
    if (hmac_ctx) {
        hash_update(hmac_ctx, block, BLOCK_SIZE);
    }
    
    memcpy(prev, block, BLOCK_SIZE);
}

void cipher_cbc_decrypt_block(const uint8_t *encrypted_block,
                              uint8_t *decrypted_block,
                              uint8_t *prev,
                              CipherContext *ctx) {
    uint8_t temp[BLOCK_SIZE];
    memcpy(temp, encrypted_block, BLOCK_SIZE);
    
    decrypt_block(temp, ctx->round_keys);
    
    for (int j = 0; j < BLOCK_SIZE; j++) {
        decrypted_block[j] = temp[j] ^ prev[j];
    }
    
    memcpy(prev, encrypted_block, BLOCK_SIZE);
}

void cipher_add_pkcs7_padding(uint8_t *block, size_t data_len, size_t block_size) {
    uint8_t padding_value = (uint8_t)(block_size - data_len);
    for (size_t i = data_len; i < block_size; i++) {
        block[i] = padding_value;
    }
}

int cipher_remove_pkcs7_padding(uint8_t *block, size_t block_size, size_t *data_len) {
    uint8_t padding_value = block[block_size - 1];
    
    if (padding_value == 0 || padding_value > block_size) {
        return -1;
    }
    
    for (size_t i = block_size - padding_value; i < block_size; i++) {
        if (block[i] != padding_value) {
            return -1;
        }
    }
    
    *data_len = block_size - padding_value;
    return 0;
}

void cipher_hmac_init(HASH_CTX *ctx, CipherContext *cipher_ctx) {
    hash_init(ctx);
    
    uint8_t ipad[HMAC_BLOCK_SIZE];
    for (int i = 0; i < HMAC_BLOCK_SIZE; i++) {
        ipad[i] = cipher_ctx->hmac_key[i] ^ 0x36;
    }
    hash_update(ctx, ipad, HMAC_BLOCK_SIZE);
}

void cipher_hmac_update_header(HASH_CTX *ctx,
                               const uint8_t *size_bytes,
                               const uint8_t *salt,
                               const uint8_t *iv) {
    hash_update(ctx, size_bytes, 8);
    hash_update(ctx, salt, KDF_SALT_SIZE);
    hash_update(ctx, iv, BLOCK_SIZE);
}

void cipher_hmac_update_data(HASH_CTX *ctx, const uint8_t *data, size_t len) {
    hash_update(ctx, data, len);
}

void cipher_hmac_final(HASH_CTX *ctx, CipherContext *cipher_ctx, uint8_t *mac) {
    uint8_t inner_hash[HASH_DIGEST_SIZE];
    hash_final(ctx, inner_hash);
    
    HASH_CTX opad_ctx;
    hash_init(&opad_ctx);
    
    uint8_t opad[HMAC_BLOCK_SIZE];
    for (int i = 0; i < HMAC_BLOCK_SIZE; i++) {
        opad[i] = cipher_ctx->hmac_key[i] ^ 0x5c;
    }
    
    hash_update(&opad_ctx, opad, HMAC_BLOCK_SIZE);
    hash_update(&opad_ctx, inner_hash, HASH_DIGEST_SIZE);
    hash_final(&opad_ctx, mac);
    
    cipher_secure_zero(inner_hash, sizeof(inner_hash));
}

void cipher_ctx_cleanup(CipherContext *ctx) {
    cipher_secure_zero(ctx->enc_key, sizeof(ctx->enc_key));
    cipher_secure_zero(ctx->mac_key, sizeof(ctx->mac_key));
    cipher_secure_zero(ctx->round_keys, sizeof(ctx->round_keys));
    cipher_secure_zero(ctx->hmac_key, sizeof(ctx->hmac_key));
}