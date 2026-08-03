// source/cipher.c
#include <string.h>
#include <stdlib.h>
#include "cipher.h"
#include "sbox.h"
#include "keygen.h"
#include "encrypt_decrypt.h"
#include "hmac.h"
#include "hash.h"
#include "kdf.h"

#define STREAM_CHUNK 65536

static void secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

static int ct_memcmp(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff;
}

int cipher_encrypt_file(const char *input_path,
                        const char *output_path,
                        const uint8_t *key, size_t key_len,
                        void (*progress)(size_t current, size_t total)) {
    
    FILE *input = fopen(input_path, "rb");
    if (!input) return -1;
    
    fseek(input, 0, SEEK_END);
    long file_size = ftell(input);
    fseek(input, 0, SEEK_SET);
    
    if (file_size <= 0) { fclose(input); return -1; }
    
    FILE *output = fopen(output_path, "wb");
    if (!output) { fclose(input); return -1; }
    
    sbox_init();
    
    uint8_t salt[KDF_SALT_SIZE];
    keygen_generate_iv(salt);
    
    uint8_t derived_key[KDF_DERIVED_KEY_SIZE];
    kdf_derive(key, key_len, salt, KDF_SALT_SIZE, KDF_ITERATIONS, 
               derived_key, KDF_DERIVED_KEY_SIZE);
    
    fwrite(salt, 1, KDF_SALT_SIZE, output);
    
    uint8_t round_keys[ROUNDS][BLOCK_SIZE];
    keygen_expand(derived_key, KDF_DERIVED_KEY_SIZE, round_keys);
    
    uint8_t iv[BLOCK_SIZE];
    keygen_generate_iv(iv);
    fwrite(iv, 1, BLOCK_SIZE, output);
    
    uint32_t data_size = (uint32_t)file_size;
    fwrite(&data_size, 1, sizeof(data_size), output);
    
    uint8_t hmac_key[HMAC_BLOCK_SIZE];
    memset(hmac_key, 0, HMAC_BLOCK_SIZE);
    memcpy(hmac_key, derived_key, KDF_DERIVED_KEY_SIZE);
    
    HASH_CTX hmac_ctx;
    hash_init(&hmac_ctx);
    
    uint8_t ipad[HMAC_BLOCK_SIZE];
    for (int i = 0; i < HMAC_BLOCK_SIZE; i++) ipad[i] = hmac_key[i] ^ 0x36;
    hash_update(&hmac_ctx, ipad, HMAC_BLOCK_SIZE);
    hash_update(&hmac_ctx, salt, KDF_SALT_SIZE);
    hash_update(&hmac_ctx, iv, BLOCK_SIZE);
    hash_update(&hmac_ctx, (uint8_t*)&data_size, sizeof(data_size));
    hash_update(&hmac_ctx, derived_key, KDF_DERIVED_KEY_SIZE);
    
    uint8_t prev[BLOCK_SIZE];
    memcpy(prev, iv, BLOCK_SIZE);
    
    uint8_t *buffer = (uint8_t*)malloc(STREAM_CHUNK);
    if (!buffer) { 
        secure_zero(derived_key, sizeof(derived_key));
        secure_zero(round_keys, sizeof(round_keys));
        fclose(input); fclose(output); return -1; 
    }
    
    size_t total_read = 0;
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, STREAM_CHUNK, input)) > 0) {
        size_t processed = 0;
        while (processed < bytes_read) {
            uint8_t block[BLOCK_SIZE] = {0};
            size_t chunk = bytes_read - processed;
            if (chunk > BLOCK_SIZE) chunk = BLOCK_SIZE;
            memcpy(block, buffer + processed, chunk);
            
            for (int i = 0; i < BLOCK_SIZE; i++) block[i] ^= prev[i];
            encrypt_block(block, round_keys);
            hash_update(&hmac_ctx, block, BLOCK_SIZE);
            fwrite(block, 1, BLOCK_SIZE, output);
            memcpy(prev, block, BLOCK_SIZE);
            processed += chunk;
        }
        total_read += bytes_read;
        if (progress) progress(total_read, (size_t)file_size);
    }
    
    uint8_t inner_hash[HASH_DIGEST_SIZE];
    hash_final(&hmac_ctx, inner_hash);
    
    HASH_CTX opad_ctx;
    hash_init(&opad_ctx);
    uint8_t opad[HMAC_BLOCK_SIZE];
    for (int i = 0; i < HMAC_BLOCK_SIZE; i++) opad[i] = hmac_key[i] ^ 0x5c;
    hash_update(&opad_ctx, opad, HMAC_BLOCK_SIZE);
    hash_update(&opad_ctx, inner_hash, HASH_DIGEST_SIZE);
    
    uint8_t mac[HMAC_SIZE];
    hash_final(&opad_ctx, mac);
    fwrite(mac, 1, HMAC_SIZE, output);
    
    secure_zero(derived_key, sizeof(derived_key));
    secure_zero(round_keys, sizeof(round_keys));
    secure_zero(prev, sizeof(prev));
    secure_zero(hmac_key, sizeof(hmac_key));
    free(buffer);
    fclose(input);
    fclose(output);
    return 0;
}

int cipher_decrypt_file(const char *input_path,
                        const char *output_path,
                        const uint8_t *key, size_t key_len,
                        void (*progress)(size_t current, size_t total)) {
    
    FILE *input = fopen(input_path, "rb");
    if (!input) return -1;
    
    uint8_t salt[KDF_SALT_SIZE];
    if (fread(salt, 1, KDF_SALT_SIZE, input) != KDF_SALT_SIZE) {
        fclose(input);
        return -1;
    }
    
    uint8_t derived_key[KDF_DERIVED_KEY_SIZE];
    kdf_derive(key, key_len, salt, KDF_SALT_SIZE, KDF_ITERATIONS,
               derived_key, KDF_DERIVED_KEY_SIZE);
    
    uint8_t iv[BLOCK_SIZE];
    uint32_t original_size;
    
    if (fread(iv, 1, BLOCK_SIZE, input) != BLOCK_SIZE ||
        fread(&original_size, 1, sizeof(original_size), input) != sizeof(original_size)) {
        secure_zero(derived_key, sizeof(derived_key));
        fclose(input);
        return -1;
    }
    
    fseek(input, 0, SEEK_END);
    long total_size = ftell(input);
    long encrypted_size = total_size - KDF_SALT_SIZE - BLOCK_SIZE - sizeof(uint32_t) - HMAC_SIZE;
    
    if (encrypted_size <= 0 || original_size == 0) {
        secure_zero(derived_key, sizeof(derived_key));
        fclose(input); 
        return -1; 
    }
    
    uint8_t stored_mac[HMAC_SIZE];
    fseek(input, -HMAC_SIZE, SEEK_END);
    if (fread(stored_mac, 1, HMAC_SIZE, input) != HMAC_SIZE) {
        secure_zero(derived_key, sizeof(derived_key));
        fclose(input); 
        return -1; 
    }
    
    fseek(input, KDF_SALT_SIZE + BLOCK_SIZE + sizeof(uint32_t), SEEK_SET);
    
    uint8_t hmac_key[HMAC_BLOCK_SIZE];
    memset(hmac_key, 0, HMAC_BLOCK_SIZE);
    memcpy(hmac_key, derived_key, KDF_DERIVED_KEY_SIZE);
    
    HASH_CTX hmac_ctx;
    hash_init(&hmac_ctx);
    
    uint8_t ipad[HMAC_BLOCK_SIZE];
    for (int i = 0; i < HMAC_BLOCK_SIZE; i++) ipad[i] = hmac_key[i] ^ 0x36;
    hash_update(&hmac_ctx, ipad, HMAC_BLOCK_SIZE);
    hash_update(&hmac_ctx, salt, KDF_SALT_SIZE);
    hash_update(&hmac_ctx, iv, BLOCK_SIZE);
    hash_update(&hmac_ctx, (uint8_t*)&original_size, sizeof(original_size));
    hash_update(&hmac_ctx, derived_key, KDF_DERIVED_KEY_SIZE);
    
    uint8_t *chunk_buf = (uint8_t*)malloc(STREAM_CHUNK);
    if (!chunk_buf) { 
        secure_zero(derived_key, sizeof(derived_key));
        fclose(input); return -1; 
    }
    
    long remaining = encrypted_size;
    while (remaining > 0) {
        size_t to_read = (remaining < STREAM_CHUNK) ? (size_t)remaining : STREAM_CHUNK;
        if (fread(chunk_buf, 1, to_read, input) != to_read) {
            secure_zero(derived_key, sizeof(derived_key));
            free(chunk_buf);
            fclose(input);
            return -1;
        }
        hash_update(&hmac_ctx, chunk_buf, to_read);
        remaining -= to_read;
    }
    
    uint8_t inner_hash[HASH_DIGEST_SIZE];
    hash_final(&hmac_ctx, inner_hash);
    
    HASH_CTX opad_ctx;
    hash_init(&opad_ctx);
    uint8_t opad[HMAC_BLOCK_SIZE];
    for (int i = 0; i < HMAC_BLOCK_SIZE; i++) opad[i] = hmac_key[i] ^ 0x5c;
    hash_update(&opad_ctx, opad, HMAC_BLOCK_SIZE);
    hash_update(&opad_ctx, inner_hash, HASH_DIGEST_SIZE);
    
    uint8_t computed_mac[HMAC_SIZE];
    hash_final(&opad_ctx, computed_mac);
    
    if (ct_memcmp(computed_mac, stored_mac, HMAC_SIZE) != 0) {
        secure_zero(derived_key, sizeof(derived_key));
        secure_zero(hmac_key, sizeof(hmac_key));
        free(chunk_buf);
        fclose(input);
        return -2;
    }
    
    FILE *output = fopen(output_path, "wb");
    if (!output) { 
        secure_zero(derived_key, sizeof(derived_key));
        free(chunk_buf); fclose(input); return -1; 
    }
    
    sbox_init();
    uint8_t round_keys[ROUNDS][BLOCK_SIZE];
    keygen_expand(derived_key, KDF_DERIVED_KEY_SIZE, round_keys);
    
    uint8_t prev[BLOCK_SIZE];
    memcpy(prev, iv, BLOCK_SIZE);
    
    fseek(input, KDF_SALT_SIZE + BLOCK_SIZE + sizeof(uint32_t), SEEK_SET);
    
    size_t total_written = 0;
    remaining = encrypted_size;
    
    while (remaining > 0 && total_written < original_size) {
        size_t to_read = (remaining < STREAM_CHUNK) ? (size_t)remaining : STREAM_CHUNK;
        size_t read_bytes = fread(chunk_buf, 1, to_read, input);
        if (read_bytes == 0) break;
        
        for (size_t i = 0; i < read_bytes; i += BLOCK_SIZE) {
            if (i + BLOCK_SIZE > read_bytes) break;
            
            uint8_t block[BLOCK_SIZE];
            memcpy(block, chunk_buf + i, BLOCK_SIZE);
            decrypt_block(block, round_keys);
            for (int j = 0; j < BLOCK_SIZE; j++) block[j] ^= prev[j];
            memcpy(prev, chunk_buf + i, BLOCK_SIZE);
            
            size_t to_write = BLOCK_SIZE;
            if (total_written + BLOCK_SIZE > original_size) to_write = original_size - total_written;
            fwrite(block, 1, to_write, output);
            total_written += to_write;
        }
        remaining -= read_bytes;
        if (progress) progress(total_written, original_size);
    }
    
    secure_zero(derived_key, sizeof(derived_key));
    secure_zero(round_keys, sizeof(round_keys));
    secure_zero(prev, sizeof(prev));
    secure_zero(hmac_key, sizeof(hmac_key));
    free(chunk_buf);
    fclose(input);
    fclose(output);
    
    return (total_written == original_size) ? 0 : -1;
}