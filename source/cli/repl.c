// source/cli/repl.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include "repl.h"
#include "cipher.h"
#include "cipher_ops.h"
#include "utils.h"
#include "keygen.h"
#include "crypto_context.h"
#include "sbox.h"
#include "encrypt_decrypt.h"
#include "hmac.h"
#include "hash.h"
#include "kdf.h"

#define REPL_MAX_CIPHERTEXT 65536

static uint8_t current_key[64];
static size_t current_key_len = DEFAULT_KEY_SIZE;
static int key_initialized = 0;

static void secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

static void add_pkcs7_padding(uint8_t *block, size_t data_len, size_t block_size) {
    uint8_t padding_value = (uint8_t)(block_size - data_len);
    memset(block + data_len, padding_value, block_size - data_len);
}

static int remove_pkcs7_padding(uint8_t *block, size_t block_size, size_t *data_len) {
    uint8_t padding_value = block[block_size - 1];
    if (padding_value == 0 || padding_value > block_size) return -1;
    for (size_t i = block_size - padding_value; i < block_size; i++) {
        if (block[i] != padding_value) return -1;
    }
    *data_len = block_size - padding_value;
    return 0;
}

static int ct_memcmp(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff;
}

static int repl_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                        uint8_t *ciphertext, size_t *ciphertext_len,
                        const uint8_t *key, size_t key_len) {
    
    if (plaintext_len == 0) return -1;
    
    sbox_init();
    
    uint8_t salt[KDF_SALT_SIZE];
    keygen_generate_iv(salt);
    
    uint8_t iv[BLOCK_SIZE];
    keygen_generate_iv(iv);
    
    CipherContext ctx;
    if (cipher_ctx_init_encrypt(&ctx, key, key_len, salt) != 0) {
        return -1;
    }
    
    size_t padded_len = ((plaintext_len + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE;
    if (padded_len == 0) padded_len = BLOCK_SIZE;
    
    size_t total_output = 8 + KDF_SALT_SIZE + BLOCK_SIZE + padded_len + HMAC_SIZE;
    if (total_output > REPL_MAX_CIPHERTEXT) {
        cipher_ctx_cleanup(&ctx);
        return -1;
    }
    
    uint8_t *output = ciphertext;
    size_t offset = 0;
    
    uint64_t orig_size = (uint64_t)plaintext_len;
    for (int i = 0; i < 8; i++) {
        output[offset++] = (uint8_t)(orig_size >> (56 - i * 8));
    }
    
    memcpy(output + offset, salt, KDF_SALT_SIZE);
    offset += KDF_SALT_SIZE;
    
    memcpy(output + offset, iv, BLOCK_SIZE);
    offset += BLOCK_SIZE;
    
    HASH_CTX hmac_ctx;
    cipher_hmac_init(&hmac_ctx, &ctx);
    cipher_hmac_update_header(&hmac_ctx, output, salt, iv);
    
    uint8_t prev[BLOCK_SIZE];
    memcpy(prev, iv, BLOCK_SIZE);
    
    size_t pos = 0;
    while (pos < plaintext_len) {
        size_t chunk = plaintext_len - pos;
        if (chunk > BLOCK_SIZE) chunk = BLOCK_SIZE;
        
        uint8_t block[BLOCK_SIZE];
        if (chunk < BLOCK_SIZE) {
            memcpy(block, plaintext + pos, chunk);
            cipher_add_pkcs7_padding(block, chunk, BLOCK_SIZE);
        } else {
            memcpy(block, plaintext + pos, BLOCK_SIZE);
        }
        
        cipher_cbc_encrypt_block(block, prev, &ctx, &hmac_ctx);
        memcpy(output + offset, block, BLOCK_SIZE);
        offset += BLOCK_SIZE;
        
        if (chunk < BLOCK_SIZE) break;
        pos += BLOCK_SIZE;
    }
    
    if (plaintext_len % BLOCK_SIZE == 0) {
        uint8_t pad_block[BLOCK_SIZE];
        memset(pad_block, BLOCK_SIZE, BLOCK_SIZE);
        cipher_cbc_encrypt_block(pad_block, prev, &ctx, &hmac_ctx);
        memcpy(output + offset, pad_block, BLOCK_SIZE);
        offset += BLOCK_SIZE;
    }
    
    uint8_t mac[HMAC_SIZE];
    cipher_hmac_final(&hmac_ctx, &ctx, mac);
    memcpy(output + offset, mac, HMAC_SIZE);
    offset += HMAC_SIZE;
    
    *ciphertext_len = offset;
    
    cipher_ctx_cleanup(&ctx);
    cipher_secure_zero(prev, sizeof(prev));
    
    return 0;
}

static int repl_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                        uint8_t *plaintext, size_t *plaintext_len,
                        const uint8_t *key, size_t key_len) {
    
    if (ciphertext_len < 8 + KDF_SALT_SIZE + BLOCK_SIZE + BLOCK_SIZE + HMAC_SIZE) {
        return -1;
    }
    
    uint64_t original_size = 0;
    for (int i = 0; i < 8; i++) {
        original_size = (original_size << 8) | ciphertext[i];
    }
    
    if (original_size > MAX_TEXT) return -1;
    
    size_t offset = 8;
    
    uint8_t salt[KDF_SALT_SIZE];
    memcpy(salt, ciphertext + offset, KDF_SALT_SIZE);
    offset += KDF_SALT_SIZE;
    
    uint8_t iv[BLOCK_SIZE];
    memcpy(iv, ciphertext + offset, BLOCK_SIZE);
    offset += BLOCK_SIZE;
    
    size_t encrypted_data_len = ciphertext_len - offset - HMAC_SIZE;
    if (encrypted_data_len % BLOCK_SIZE != 0 || encrypted_data_len < BLOCK_SIZE) {
        return -1;
    }
    
    uint8_t stored_mac[HMAC_SIZE];
    memcpy(stored_mac, ciphertext + ciphertext_len - HMAC_SIZE, HMAC_SIZE);
    
    CipherContext ctx;
    if (cipher_ctx_init_decrypt(&ctx, key, key_len, salt) != 0) {
        return -1;
    }
    
    HASH_CTX hmac_ctx;
    cipher_hmac_init(&hmac_ctx, &ctx);
    cipher_hmac_update_header(&hmac_ctx, ciphertext, salt, iv);
    cipher_hmac_update_data(&hmac_ctx, ciphertext + offset, encrypted_data_len);
    
    uint8_t computed_mac[HMAC_SIZE];
    cipher_hmac_final(&hmac_ctx, &ctx, computed_mac);
    
    if (cipher_ct_memcmp(computed_mac, stored_mac, HMAC_SIZE) != 0) {
        cipher_ctx_cleanup(&ctx);
        return -2;
    }
    
    sbox_init();
    
    uint8_t prev[BLOCK_SIZE];
    memcpy(prev, iv, BLOCK_SIZE);
    
    size_t plain_offset = 0;
    
    for (size_t i = 0; i < encrypted_data_len - BLOCK_SIZE; i += BLOCK_SIZE) {
        uint8_t decrypted[BLOCK_SIZE];
        cipher_cbc_decrypt_block(ciphertext + offset + i, decrypted, prev, &ctx);
        
        memcpy(plaintext + plain_offset, decrypted, BLOCK_SIZE);
        plain_offset += BLOCK_SIZE;
    }
    
    size_t last_block_idx = encrypted_data_len - BLOCK_SIZE;
    uint8_t last_decrypted[BLOCK_SIZE];
    cipher_cbc_decrypt_block(ciphertext + offset + last_block_idx, last_decrypted, prev, &ctx);
    
    size_t unpadded_len;
    if (cipher_remove_pkcs7_padding(last_decrypted, BLOCK_SIZE, &unpadded_len) != 0) {
        cipher_ctx_cleanup(&ctx);
        cipher_secure_zero(prev, sizeof(prev));
        return -2;
    }
    
    if (unpadded_len > 0) {
        memcpy(plaintext + plain_offset, last_decrypted, unpadded_len);
        plain_offset += unpadded_len;
    }
    
    *plaintext_len = plain_offset;
    
    cipher_ctx_cleanup(&ctx);
    cipher_secure_zero(prev, sizeof(prev));
    cipher_secure_zero(last_decrypted, sizeof(last_decrypted));
    cipher_secure_zero(computed_mac, sizeof(computed_mac));
    
    return 0;
}

static void init_key(void) {
    if (!key_initialized) {
        crypto_get_default_key(current_key);
        key_initialized = 1;
    }
}

void repl_run(void) {
    uint8_t input[MAX_TEXT];
    uint8_t output[REPL_MAX_CIPHERTEXT];
    int choice;
    
    init_key();

    printf("Welcome to Apex Cipher 26.08!\n");
    printf("Max text in REPL: %d bytes | Key: up to %d bytes\n", MAX_TEXT, DEFAULT_KEY_SIZE * 2);
    utils_show_key(current_key, current_key_len);
    printf("\n");
    
    while (1) {
        printf("1. Encrypt\n");
        printf("2. Decrypt\n");
        printf("3. Set key\n");
        printf("> ");
        
        if (scanf("%d", &choice) != 1) {
            int c;
            while ((c = getchar()) != '\n' && c != EOF);
            break;
        }
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
        
        if (choice == 1) {
            printf("Enter text: ");
            if (!fgets((char*)input, MAX_TEXT, stdin)) continue;
            size_t len = strlen((char*)input);
            if (len > 0 && input[len - 1] == '\n') { input[len - 1] = 0; len--; }
            if (len == 0) { printf("No data entered.\n\n"); continue; }
            
            size_t enc_len;
            int result = repl_encrypt(input, len, output, &enc_len, current_key, current_key_len);
            
            if (result != 0) {
                printf("Encryption failed!\n\n");
            } else {
                printf("Encrypted (%zu bytes):\n", enc_len);
                for (size_t i = 0; i < enc_len; i++) printf("%02x", output[i]);
                printf("\n\n");
            }
            
            secure_zero(output, sizeof(output));
            
        } else if (choice == 2) {
            printf("Enter hex: ");
            char hex[REPL_MAX_CIPHERTEXT * 2 + 2];
            if (!fgets(hex, sizeof(hex), stdin)) continue;
            size_t hex_len = strlen(hex);
            if (hex_len > 0 && hex[hex_len - 1] == '\n') { hex[hex_len - 1] = 0; hex_len--; }
            if (hex_len == 0) { printf("No data entered.\n\n"); continue; }
            
            for (size_t i = 0; i < hex_len; i++) {
                if (!isxdigit((unsigned char)hex[i])) {
                    printf("Invalid hex. Use 0-9 a-f A-F only.\n\n");
                    hex_len = 0; // mark as invalid
                    break;
                }
            }
            if (hex_len == 0) continue;
            if (hex_len % 2 != 0) {
                printf("Invalid hex. Must be even length.\n\n");
                continue;
            }
            
            size_t ciphertext_len = hex_len / 2;
            if (ciphertext_len > REPL_MAX_CIPHERTEXT) {
                printf("Ciphertext too long (max %d bytes).\n\n", REPL_MAX_CIPHERTEXT);
                continue;
            }
            
            uint8_t *ciphertext = (uint8_t*)malloc(ciphertext_len);
            if (!ciphertext) {
                printf("Memory allocation failed.\n\n");
                continue;
            }
            
            for (size_t i = 0; i < ciphertext_len; i++) {
                unsigned int byte;
                sscanf(hex + i * 2, "%2x", &byte);
                ciphertext[i] = (uint8_t)byte;
            }
            
            uint8_t *decrypted = (uint8_t*)malloc(MAX_TEXT + 1);
            if (!decrypted) {
                printf("Memory allocation failed.\n\n");
                free(ciphertext);
                continue;
            }
            
            size_t dec_len;
            int result = repl_decrypt(ciphertext, ciphertext_len, decrypted, &dec_len,
                                      current_key, current_key_len);
            
            if (result == -2) {
                printf("Wrong key or corrupted data (authentication failed)!\n\n");
            } else if (result != 0) {
                printf("Decryption failed! (code: %d)\n\n", result);
            } else {
                decrypted[dec_len] = 0;
                printf("Decrypted (%zu bytes):\n%s\n\n", dec_len, decrypted);
            }
            
            secure_zero(decrypted, MAX_TEXT + 1);
            secure_zero(ciphertext, ciphertext_len);
            free(decrypted);
            free(ciphertext);
            
        } else if (choice == 3) {
            utils_show_key(current_key, current_key_len);
            printf("New key (empty = keep current): ");
            
            uint8_t new_key[65];
            size_t new_len = 0;
            int c;
            while (new_len < 64 && (c = getchar()) != '\n' && c != EOF) {
                new_key[new_len++] = (uint8_t)c;
            }
            
            if (new_len > 0) {
                memcpy(current_key, new_key, new_len);
                current_key_len = new_len;
                printf("Updated! ");
            } else {
                printf("Unchanged. ");
            }
            utils_show_key(current_key, current_key_len);
            printf("\n");
            
            secure_zero(new_key, sizeof(new_key));
        } else {
            printf("Use 1-3.\n\n");
        }
    }
    
    secure_zero(current_key, sizeof(current_key));
    secure_zero(input, sizeof(input));
    secure_zero(output, sizeof(output));
}