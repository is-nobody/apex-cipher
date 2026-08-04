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

static void add_pkcs7_padding(uint8_t *block, size_t data_len, size_t block_size) {
    uint8_t padding_value = (uint8_t)(block_size - data_len);
    for (size_t i = data_len; i < block_size; i++) {
        block[i] = padding_value;
    }
}

static int remove_pkcs7_padding(uint8_t *block, size_t block_size, size_t *data_len) {
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
    
    uint64_t original_size = (uint64_t)file_size;
    uint8_t size_bytes[8];
    size_bytes[0] = (uint8_t)(original_size >> 56);
    size_bytes[1] = (uint8_t)(original_size >> 48);
    size_bytes[2] = (uint8_t)(original_size >> 40);
    size_bytes[3] = (uint8_t)(original_size >> 32);
    size_bytes[4] = (uint8_t)(original_size >> 24);
    size_bytes[5] = (uint8_t)(original_size >> 16);
    size_bytes[6] = (uint8_t)(original_size >> 8);
    size_bytes[7] = (uint8_t)(original_size);
    fwrite(size_bytes, 1, sizeof(size_bytes), output);
    
    uint8_t salt[KDF_SALT_SIZE];
    keygen_generate_iv(salt);
    
    uint8_t enc_salt[KDF_SALT_SIZE + 3];
    memcpy(enc_salt, salt, KDF_SALT_SIZE);
    enc_salt[KDF_SALT_SIZE] = 'E';
    enc_salt[KDF_SALT_SIZE + 1] = 'N';
    enc_salt[KDF_SALT_SIZE + 2] = 'C';
    
    uint8_t mac_salt[KDF_SALT_SIZE + 3];
    memcpy(mac_salt, salt, KDF_SALT_SIZE);
    mac_salt[KDF_SALT_SIZE] = 'M';
    mac_salt[KDF_SALT_SIZE + 1] = 'A';
    mac_salt[KDF_SALT_SIZE + 2] = 'C';
    
    uint8_t enc_key[KDF_DERIVED_KEY_SIZE];
    uint8_t mac_key[KDF_DERIVED_KEY_SIZE];
    
    kdf_derive(key, key_len, enc_salt, KDF_SALT_SIZE + 3, KDF_ITERATIONS, 
               enc_key, KDF_DERIVED_KEY_SIZE);
    kdf_derive(key, key_len, mac_salt, KDF_SALT_SIZE + 3, KDF_ITERATIONS, 
               mac_key, KDF_DERIVED_KEY_SIZE);
    
    fwrite(salt, 1, KDF_SALT_SIZE, output);
    
    uint8_t round_keys[ROUNDS + 1][BLOCK_SIZE];
    keygen_expand(enc_key, KDF_DERIVED_KEY_SIZE, salt, KDF_SALT_SIZE, round_keys);
    
    uint8_t iv[BLOCK_SIZE];
    keygen_generate_iv(iv);
    fwrite(iv, 1, BLOCK_SIZE, output);
    
    uint8_t hmac_key[HMAC_BLOCK_SIZE];
    memset(hmac_key, 0, HMAC_BLOCK_SIZE);
    memcpy(hmac_key, mac_key, KDF_DERIVED_KEY_SIZE);
    
    HASH_CTX hmac_ctx;
    hash_init(&hmac_ctx);
    
    uint8_t ipad[HMAC_BLOCK_SIZE];
    for (int i = 0; i < HMAC_BLOCK_SIZE; i++) ipad[i] = hmac_key[i] ^ 0x36;
    hash_update(&hmac_ctx, ipad, HMAC_BLOCK_SIZE);
    hash_update(&hmac_ctx, size_bytes, sizeof(size_bytes));
    hash_update(&hmac_ctx, salt, KDF_SALT_SIZE);
    hash_update(&hmac_ctx, iv, BLOCK_SIZE);
    hash_update(&hmac_ctx, mac_key, KDF_DERIVED_KEY_SIZE);
    
    uint8_t prev[BLOCK_SIZE];
    memcpy(prev, iv, BLOCK_SIZE);
    
    uint8_t *buffer = (uint8_t*)malloc(STREAM_CHUNK);
    if (!buffer) { 
        secure_zero(enc_key, sizeof(enc_key));
        secure_zero(mac_key, sizeof(mac_key));
        secure_zero(round_keys, sizeof(round_keys));
        fclose(input); fclose(output); return -1; 
    }
    
    size_t total_read = 0;
    size_t bytes_read;
    uint8_t pending_block[BLOCK_SIZE];
    size_t pending_len = 0;
    
    while ((bytes_read = fread(buffer, 1, STREAM_CHUNK, input)) > 0) {
        total_read += bytes_read;
        size_t processed = 0;
        
        if (pending_len > 0) {
            size_t to_copy = BLOCK_SIZE - pending_len;
            if (to_copy > bytes_read) to_copy = bytes_read;
            memcpy(pending_block + pending_len, buffer, to_copy);
            pending_len += to_copy;
            processed += to_copy;
            
            if (pending_len == BLOCK_SIZE) {
                for (int i = 0; i < BLOCK_SIZE; i++) pending_block[i] ^= prev[i];
                encrypt_block(pending_block, round_keys);
                hash_update(&hmac_ctx, pending_block, BLOCK_SIZE);
                fwrite(pending_block, 1, BLOCK_SIZE, output);
                memcpy(prev, pending_block, BLOCK_SIZE);
                pending_len = 0;
            }
        }
        
        while (processed + BLOCK_SIZE <= bytes_read) {
            uint8_t block[BLOCK_SIZE];
            memcpy(block, buffer + processed, BLOCK_SIZE);
            
            for (int i = 0; i < BLOCK_SIZE; i++) block[i] ^= prev[i];
            encrypt_block(block, round_keys);
            hash_update(&hmac_ctx, block, BLOCK_SIZE);
            fwrite(block, 1, BLOCK_SIZE, output);
            memcpy(prev, block, BLOCK_SIZE);
            processed += BLOCK_SIZE;
        }
        
        if (processed < bytes_read) {
            size_t remaining = bytes_read - processed;
            memcpy(pending_block, buffer + processed, remaining);
            pending_len = remaining;
        }
        
        if (progress) progress(total_read, (size_t)file_size);
    }
    
    uint8_t final_block[BLOCK_SIZE];
    memcpy(final_block, pending_block, pending_len);
    add_pkcs7_padding(final_block, pending_len, BLOCK_SIZE);
    
    for (int i = 0; i < BLOCK_SIZE; i++) final_block[i] ^= prev[i];
    encrypt_block(final_block, round_keys);
    hash_update(&hmac_ctx, final_block, BLOCK_SIZE);
    fwrite(final_block, 1, BLOCK_SIZE, output);
    
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
    
    secure_zero(enc_key, sizeof(enc_key));
    secure_zero(mac_key, sizeof(mac_key));
    secure_zero(round_keys, sizeof(round_keys));
    secure_zero(prev, sizeof(prev));
    secure_zero(hmac_key, sizeof(hmac_key));
    secure_zero(pending_block, sizeof(pending_block));
    secure_zero(final_block, sizeof(final_block));
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
    
    uint8_t size_bytes[8];
    if (fread(size_bytes, 1, sizeof(size_bytes), input) != sizeof(size_bytes)) {
        fclose(input);
        return -1;
    }
    uint64_t original_size = ((uint64_t)size_bytes[0] << 56) |
                             ((uint64_t)size_bytes[1] << 48) |
                             ((uint64_t)size_bytes[2] << 40) |
                             ((uint64_t)size_bytes[3] << 32) |
                             ((uint64_t)size_bytes[4] << 24) |
                             ((uint64_t)size_bytes[5] << 16) |
                             ((uint64_t)size_bytes[6] << 8)  |
                             ((uint64_t)size_bytes[7]);
    
    uint8_t salt[KDF_SALT_SIZE];
    if (fread(salt, 1, KDF_SALT_SIZE, input) != KDF_SALT_SIZE) {
        fclose(input);
        return -1;
    }
    
    uint8_t enc_salt[KDF_SALT_SIZE + 3];
    memcpy(enc_salt, salt, KDF_SALT_SIZE);
    enc_salt[KDF_SALT_SIZE] = 'E';
    enc_salt[KDF_SALT_SIZE + 1] = 'N';
    enc_salt[KDF_SALT_SIZE + 2] = 'C';
    
    uint8_t mac_salt[KDF_SALT_SIZE + 3];
    memcpy(mac_salt, salt, KDF_SALT_SIZE);
    mac_salt[KDF_SALT_SIZE] = 'M';
    mac_salt[KDF_SALT_SIZE + 1] = 'A';
    mac_salt[KDF_SALT_SIZE + 2] = 'C';
    
    uint8_t enc_key[KDF_DERIVED_KEY_SIZE];
    uint8_t mac_key[KDF_DERIVED_KEY_SIZE];
    
    kdf_derive(key, key_len, enc_salt, KDF_SALT_SIZE + 3, KDF_ITERATIONS,
               enc_key, KDF_DERIVED_KEY_SIZE);
    kdf_derive(key, key_len, mac_salt, KDF_SALT_SIZE + 3, KDF_ITERATIONS,
               mac_key, KDF_DERIVED_KEY_SIZE);
    
    uint8_t iv[BLOCK_SIZE];
    if (fread(iv, 1, BLOCK_SIZE, input) != BLOCK_SIZE) {
        secure_zero(enc_key, sizeof(enc_key));
        secure_zero(mac_key, sizeof(mac_key));
        fclose(input);
        return -1;
    }
    
    fseek(input, 0, SEEK_END);
    long total_size = ftell(input);
    long encrypted_size = total_size - sizeof(uint64_t) - KDF_SALT_SIZE - BLOCK_SIZE - HMAC_SIZE;
    
    if (encrypted_size <= 0 || encrypted_size % BLOCK_SIZE != 0) {
        secure_zero(enc_key, sizeof(enc_key));
        secure_zero(mac_key, sizeof(mac_key));
        fclose(input); 
        return -1; 
    }
    
    uint8_t stored_mac[HMAC_SIZE];
    fseek(input, -(long)HMAC_SIZE, SEEK_END);
    if (fread(stored_mac, 1, HMAC_SIZE, input) != HMAC_SIZE) {
        secure_zero(enc_key, sizeof(enc_key));
        secure_zero(mac_key, sizeof(mac_key));
        fclose(input); 
        return -1; 
    }
    
    fseek(input, sizeof(uint64_t) + KDF_SALT_SIZE + BLOCK_SIZE, SEEK_SET);
    
    uint8_t hmac_key[HMAC_BLOCK_SIZE];
    memset(hmac_key, 0, HMAC_BLOCK_SIZE);
    memcpy(hmac_key, mac_key, KDF_DERIVED_KEY_SIZE);
    
    HASH_CTX hmac_ctx;
    hash_init(&hmac_ctx);
    
    uint8_t ipad[HMAC_BLOCK_SIZE];
    for (int i = 0; i < HMAC_BLOCK_SIZE; i++) ipad[i] = hmac_key[i] ^ 0x36;
    hash_update(&hmac_ctx, ipad, HMAC_BLOCK_SIZE);
    hash_update(&hmac_ctx, size_bytes, sizeof(size_bytes));
    hash_update(&hmac_ctx, salt, KDF_SALT_SIZE);
    hash_update(&hmac_ctx, iv, BLOCK_SIZE);
    hash_update(&hmac_ctx, mac_key, KDF_DERIVED_KEY_SIZE);
    
    uint8_t *chunk_buf = (uint8_t*)malloc(STREAM_CHUNK);
    if (!chunk_buf) { 
        secure_zero(enc_key, sizeof(enc_key));
        secure_zero(mac_key, sizeof(mac_key));
        fclose(input); return -1; 
    }
    
    long remaining = encrypted_size;
    while (remaining > 0) {
        size_t to_read = (remaining < STREAM_CHUNK) ? (size_t)remaining : STREAM_CHUNK;
        if (fread(chunk_buf, 1, to_read, input) != to_read) {
            secure_zero(enc_key, sizeof(enc_key));
            secure_zero(mac_key, sizeof(mac_key));
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
        secure_zero(enc_key, sizeof(enc_key));
        secure_zero(mac_key, sizeof(mac_key));
        secure_zero(hmac_key, sizeof(hmac_key));
        free(chunk_buf);
        fclose(input);
        return -2;
    }
    
    FILE *output = fopen(output_path, "wb");
    if (!output) { 
        secure_zero(enc_key, sizeof(enc_key));
        secure_zero(mac_key, sizeof(mac_key));
        secure_zero(hmac_key, sizeof(hmac_key));
        free(chunk_buf); 
        fclose(input); 
        return -1; 
    }
    
    sbox_init();
    uint8_t round_keys[ROUNDS + 1][BLOCK_SIZE];
    keygen_expand(enc_key, KDF_DERIVED_KEY_SIZE, salt, KDF_SALT_SIZE, round_keys);
    
    uint8_t prev[BLOCK_SIZE];
    memcpy(prev, iv, BLOCK_SIZE);
    
    fseek(input, sizeof(uint64_t) + KDF_SALT_SIZE + BLOCK_SIZE, SEEK_SET);
    
    size_t total_written = 0;
    remaining = encrypted_size - BLOCK_SIZE;
    
    while (remaining > 0) {
        size_t to_read = (remaining < STREAM_CHUNK) ? (size_t)remaining : STREAM_CHUNK;
        size_t read_bytes = fread(chunk_buf, 1, to_read, input);
        if (read_bytes == 0) break;
        
        for (size_t i = 0; i < read_bytes; i += BLOCK_SIZE) {
            if (i + BLOCK_SIZE > read_bytes) break;
            
            uint8_t block[BLOCK_SIZE];
            uint8_t temp[BLOCK_SIZE];
            memcpy(temp, chunk_buf + i, BLOCK_SIZE);
            decrypt_block(temp, round_keys);
            for (int j = 0; j < BLOCK_SIZE; j++) block[j] = temp[j] ^ prev[j];
            memcpy(prev, chunk_buf + i, BLOCK_SIZE);
            
            fwrite(block, 1, BLOCK_SIZE, output);
            total_written += BLOCK_SIZE;
        }
        remaining -= read_bytes;
        if (progress) progress(total_written, original_size);
    }
    
    uint8_t last_encrypted[BLOCK_SIZE];
    uint8_t last_decrypted[BLOCK_SIZE];
    if (fread(last_encrypted, 1, BLOCK_SIZE, input) == BLOCK_SIZE) {
        decrypt_block(last_encrypted, round_keys);
        for (int j = 0; j < BLOCK_SIZE; j++) last_decrypted[j] = last_encrypted[j] ^ prev[j];
        
        size_t unpadded_len;
        if (remove_pkcs7_padding(last_decrypted, BLOCK_SIZE, &unpadded_len) != 0) {
            secure_zero(enc_key, sizeof(enc_key));
            secure_zero(mac_key, sizeof(mac_key));
            secure_zero(round_keys, sizeof(round_keys));
            secure_zero(hmac_key, sizeof(hmac_key));
            free(chunk_buf);
            fclose(input);
            fclose(output);
            return -2;
        }
        
        if (unpadded_len > 0) {
            size_t remaining_to_write = original_size - total_written;
            if (unpadded_len > remaining_to_write) unpadded_len = remaining_to_write;
            
            fwrite(last_decrypted, 1, unpadded_len, output);
            total_written += unpadded_len;
        }
    }
    
    if (progress) progress(total_written, original_size);
    
    secure_zero(enc_key, sizeof(enc_key));
    secure_zero(mac_key, sizeof(mac_key));
    secure_zero(round_keys, sizeof(round_keys));
    secure_zero(prev, sizeof(prev));
    secure_zero(hmac_key, sizeof(hmac_key));
    secure_zero(last_encrypted, sizeof(last_encrypted));
    secure_zero(last_decrypted, sizeof(last_decrypted));
    free(chunk_buf);
    fclose(input);
    fclose(output);
    
    return 0;
}