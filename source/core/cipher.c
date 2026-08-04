// source/cipher.c
#include <string.h>
#include <stdlib.h>
#include "cipher.h"
#include "sbox.h"
#include "keygen.h"
#include "cipher_ops.h"

#define STREAM_CHUNK 65536

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
    for (int i = 0; i < 8; i++) {
        size_bytes[i] = (uint8_t)(original_size >> (56 - i * 8));
    }

    if (fwrite(size_bytes, 1, sizeof(size_bytes), output) != sizeof(size_bytes)) {
        fclose(input);
        fclose(output);
        return -1;
    }

    uint8_t salt[KDF_SALT_SIZE];
    keygen_generate_iv(salt);
    
    if (fwrite(salt, 1, KDF_SALT_SIZE, output) != KDF_SALT_SIZE) {
        fclose(input);
        fclose(output);
        return -1;
    }
    
    CipherContext ctx;
    if (cipher_ctx_init_encrypt(&ctx, key, key_len, salt) != 0) {
        fclose(input);
        fclose(output);
        return -1;
    }
    
    uint8_t iv[BLOCK_SIZE];
    keygen_generate_iv(iv);

    if (fwrite(iv, 1, BLOCK_SIZE, output) != BLOCK_SIZE) {
        cipher_ctx_cleanup(&ctx);
        fclose(input);
        fclose(output);
        return -1;
    }
    
    size_t encrypted_capacity = (size_t)file_size + BLOCK_SIZE;
    uint8_t *encrypted_data = (uint8_t*)malloc(encrypted_capacity);
    if (!encrypted_data) {
        cipher_ctx_cleanup(&ctx);
        fclose(input);
        fclose(output);
        return -1;
    }
    size_t encrypted_len = 0;
    
    uint8_t prev[BLOCK_SIZE];
    memcpy(prev, iv, BLOCK_SIZE);
    
    uint8_t *buffer = (uint8_t*)malloc(STREAM_CHUNK);
    if (!buffer) { 
        cipher_ctx_cleanup(&ctx);
        free(encrypted_data);
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
                cipher_cbc_encrypt_block(pending_block, prev, &ctx);
                memcpy(encrypted_data + encrypted_len, pending_block, BLOCK_SIZE);
                encrypted_len += BLOCK_SIZE;
                
                if (fwrite(pending_block, 1, BLOCK_SIZE, output) != BLOCK_SIZE) {
                    cipher_ctx_cleanup(&ctx);
                    free(encrypted_data);
                    free(buffer);
                    fclose(input);
                    fclose(output);
                    return -1;
                }
                pending_len = 0;
            }
        }
        
        while (processed + BLOCK_SIZE <= bytes_read) {
            uint8_t block[BLOCK_SIZE];
            memcpy(block, buffer + processed, BLOCK_SIZE);
            
            cipher_cbc_encrypt_block(block, prev, &ctx);
            memcpy(encrypted_data + encrypted_len, block, BLOCK_SIZE);
            encrypted_len += BLOCK_SIZE;
            
            if (fwrite(block, 1, BLOCK_SIZE, output) != BLOCK_SIZE) {
                cipher_ctx_cleanup(&ctx);
                free(encrypted_data);
                free(buffer);
                fclose(input);
                fclose(output);
                return -1;
            }
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
    cipher_add_pkcs7_padding(final_block, pending_len, BLOCK_SIZE);
    
    cipher_cbc_encrypt_block(final_block, prev, &ctx);
    memcpy(encrypted_data + encrypted_len, final_block, BLOCK_SIZE);
    encrypted_len += BLOCK_SIZE;

    if (fwrite(final_block, 1, BLOCK_SIZE, output) != BLOCK_SIZE) {
        cipher_ctx_cleanup(&ctx);
        cipher_secure_zero(prev, sizeof(prev));
        cipher_secure_zero(pending_block, sizeof(pending_block));
        free(encrypted_data);
        free(buffer);
        fclose(input);
        fclose(output);
        return -1;
    }
    
    size_t header_size = 8 + KDF_SALT_SIZE + BLOCK_SIZE;
    size_t hmac_data_size = header_size + encrypted_len;
    uint8_t *hmac_data = (uint8_t*)malloc(hmac_data_size);
    if (hmac_data) {
        memcpy(hmac_data, size_bytes, 8);
        memcpy(hmac_data + 8, salt, KDF_SALT_SIZE);
        memcpy(hmac_data + 8 + KDF_SALT_SIZE, iv, BLOCK_SIZE);
        memcpy(hmac_data + header_size, encrypted_data, encrypted_len);
        
        uint8_t mac[HMAC_SIZE];
        hmac_compute(ctx.mac_key, KDF_DERIVED_KEY_SIZE, hmac_data, hmac_data_size, mac);
        
        fwrite(mac, 1, HMAC_SIZE, output);
        
        cipher_secure_zero(hmac_data, hmac_data_size);
        free(hmac_data);
    }
    
    cipher_ctx_cleanup(&ctx);
    cipher_secure_zero(prev, sizeof(prev));
    cipher_secure_zero(pending_block, sizeof(pending_block));
    cipher_secure_zero(final_block, sizeof(final_block));
    free(encrypted_data);
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
    uint64_t original_size = 0;
    for (int i = 0; i < 8; i++) {
        original_size = (original_size << 8) | size_bytes[i];
    }
    
    uint8_t salt[KDF_SALT_SIZE];
    if (fread(salt, 1, KDF_SALT_SIZE, input) != KDF_SALT_SIZE) {
        fclose(input);
        return -1;
    }
    
    CipherContext ctx;
    if (cipher_ctx_init_decrypt(&ctx, key, key_len, salt) != 0) {
        fclose(input);
        return -1;
    }
    
    uint8_t iv[BLOCK_SIZE];
    if (fread(iv, 1, BLOCK_SIZE, input) != BLOCK_SIZE) {
        cipher_ctx_cleanup(&ctx);
        fclose(input);
        return -1;
    }
    
    fseek(input, 0, SEEK_END);
    long total_size = ftell(input);
    long encrypted_size = total_size - sizeof(uint64_t) - KDF_SALT_SIZE - BLOCK_SIZE - HMAC_SIZE;
    
    if (encrypted_size <= 0 || encrypted_size % BLOCK_SIZE != 0) {
        cipher_ctx_cleanup(&ctx);
        fclose(input); 
        return -1; 
    }
    
    uint8_t stored_mac[HMAC_SIZE];
    fseek(input, -(long)HMAC_SIZE, SEEK_END);
    if (fread(stored_mac, 1, HMAC_SIZE, input) != HMAC_SIZE) {
        cipher_ctx_cleanup(&ctx);
        fclose(input); 
        return -1; 
    }
    
    fseek(input, sizeof(uint64_t) + KDF_SALT_SIZE + BLOCK_SIZE, SEEK_SET);
    
    uint8_t *chunk_buf = (uint8_t*)malloc(STREAM_CHUNK);
    if (!chunk_buf) { 
        cipher_ctx_cleanup(&ctx);
        fclose(input); return -1; 
    }
    
    size_t header_size = 8 + KDF_SALT_SIZE + BLOCK_SIZE;
    size_t hmac_data_size = header_size + (size_t)encrypted_size;
    uint8_t *hmac_data = (uint8_t*)malloc(hmac_data_size);
    if (!hmac_data) {
        cipher_ctx_cleanup(&ctx);
        free(chunk_buf);
        fclose(input);
        return -1;
    }
    
    memcpy(hmac_data, size_bytes, 8);
    memcpy(hmac_data + 8, salt, KDF_SALT_SIZE);
    memcpy(hmac_data + 8 + KDF_SALT_SIZE, iv, BLOCK_SIZE);
    
    size_t offset = header_size;
    long remaining = encrypted_size;
    while (remaining > 0) {
        size_t to_read = (remaining < STREAM_CHUNK) ? (size_t)remaining : STREAM_CHUNK;
        size_t read_now = fread(chunk_buf, 1, to_read, input);
        if (read_now == 0) break;
        memcpy(hmac_data + offset, chunk_buf, read_now);
        offset += read_now;
        remaining -= read_now;
    }
    
    uint8_t computed_mac[HMAC_SIZE];
    hmac_compute(ctx.mac_key, KDF_DERIVED_KEY_SIZE, hmac_data, hmac_data_size, computed_mac);
    
    cipher_secure_zero(hmac_data, hmac_data_size);
    free(hmac_data);
    
    if (cipher_ct_memcmp(computed_mac, stored_mac, HMAC_SIZE) != 0) {
        cipher_ctx_cleanup(&ctx);
        free(chunk_buf);
        fclose(input);
        return -2;
    }
    
    FILE *output = fopen(output_path, "wb");
    if (!output) { 
        cipher_ctx_cleanup(&ctx);
        free(chunk_buf); 
        fclose(input); 
        return -1; 
    }
    
    sbox_init();
    
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
            
            uint8_t decrypted[BLOCK_SIZE];
            cipher_cbc_decrypt_block(chunk_buf + i, decrypted, prev, &ctx);
            
            if (fwrite(decrypted, 1, BLOCK_SIZE, output) != BLOCK_SIZE) {
                cipher_ctx_cleanup(&ctx);
                free(chunk_buf);
                fclose(input);
                fclose(output);
                return -1;
            }
            total_written += BLOCK_SIZE;
        }
        remaining -= read_bytes;
        if (progress) progress(total_written, original_size);
    }
    
    uint8_t last_encrypted[BLOCK_SIZE];
    uint8_t last_decrypted[BLOCK_SIZE];
    if (fread(last_encrypted, 1, BLOCK_SIZE, input) == BLOCK_SIZE) {
        cipher_cbc_decrypt_block(last_encrypted, last_decrypted, prev, &ctx);
        
        size_t unpadded_len;
        if (cipher_remove_pkcs7_padding(last_decrypted, BLOCK_SIZE, &unpadded_len) != 0) {
            cipher_ctx_cleanup(&ctx);
            free(chunk_buf);
            fclose(input);
            fclose(output);
            return -2;
        }
        
        if (unpadded_len > 0) {
            size_t remaining_to_write = original_size - total_written;
            if (unpadded_len > remaining_to_write) unpadded_len = remaining_to_write;
            
            if (fwrite(last_decrypted, 1, unpadded_len, output) != unpadded_len) {
                cipher_ctx_cleanup(&ctx);
                free(chunk_buf);
                fclose(input);
                fclose(output);
                return -1;
            }
            total_written += unpadded_len;
        }
    }
    
    if (progress) progress(total_written, original_size);
    
    cipher_ctx_cleanup(&ctx);
    cipher_secure_zero(prev, sizeof(prev));
    cipher_secure_zero(last_encrypted, sizeof(last_encrypted));
    cipher_secure_zero(last_decrypted, sizeof(last_decrypted));
    free(chunk_buf);
    fclose(input);
    fclose(output);
    
    return 0;
}