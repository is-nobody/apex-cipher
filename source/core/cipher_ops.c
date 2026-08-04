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
    
    return 0;
}

int cipher_ctx_init_decrypt(CipherContext *ctx,
                            const uint8_t *master_key, size_t key_len,
                            const uint8_t *salt) {
    return cipher_ctx_init_encrypt(ctx, master_key, key_len, salt);
}

void cipher_cbc_encrypt_block(uint8_t *block,
                              uint8_t *prev,
                              CipherContext *ctx) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        block[i] ^= prev[i];
    }
    
    encrypt_block(block, ctx->round_keys);
    
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

void cipher_ctx_cleanup(CipherContext *ctx) {
    cipher_secure_zero(ctx->enc_key, sizeof(ctx->enc_key));
    cipher_secure_zero(ctx->mac_key, sizeof(ctx->mac_key));
    cipher_secure_zero(ctx->round_keys, sizeof(ctx->round_keys));
}