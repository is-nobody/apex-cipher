// source/cli/repl.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include "repl.h"
#include "cipher.h"
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
    
    uint8_t round_keys[ROUNDS + 1][BLOCK_SIZE];
    keygen_expand(enc_key, KDF_DERIVED_KEY_SIZE, round_keys);
    
    uint8_t iv[BLOCK_SIZE];
    keygen_generate_iv(iv);
    
    size_t padded_len = ((plaintext_len + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE;
    if (padded_len == 0) padded_len = BLOCK_SIZE;
    
    size_t total_output = 8 + KDF_SALT_SIZE + BLOCK_SIZE + padded_len + HMAC_SIZE;
    if (total_output > REPL_MAX_CIPHERTEXT) {
        secure_zero(enc_key, sizeof(enc_key));
        secure_zero(mac_key, sizeof(mac_key));
        secure_zero(round_keys, sizeof(round_keys));
        return -1;
    }
    
    uint8_t *output = ciphertext;
    size_t offset = 0;
    
    uint64_t orig_size = (uint64_t)plaintext_len;
    output[0] = (uint8_t)(orig_size >> 56);
    output[1] = (uint8_t)(orig_size >> 48);
    output[2] = (uint8_t)(orig_size >> 40);
    output[3] = (uint8_t)(orig_size >> 32);
    output[4] = (uint8_t)(orig_size >> 24);
    output[5] = (uint8_t)(orig_size >> 16);
    output[6] = (uint8_t)(orig_size >> 8);
    output[7] = (uint8_t)(orig_size);
    offset += 8;
    
    memcpy(output + offset, salt, KDF_SALT_SIZE);
    offset += KDF_SALT_SIZE;
    
    memcpy(output + offset, iv, BLOCK_SIZE);
    offset += BLOCK_SIZE;
    
    uint8_t hmac_key[HMAC_BLOCK_SIZE];
    memset(hmac_key, 0, HMAC_BLOCK_SIZE);
    memcpy(hmac_key, mac_key, KDF_DERIVED_KEY_SIZE);
    
    HASH_CTX hmac_ctx;
    hash_init(&hmac_ctx);
    
    uint8_t ipad[HMAC_BLOCK_SIZE];
    for (int i = 0; i < HMAC_BLOCK_SIZE; i++) ipad[i] = hmac_key[i] ^ 0x36;
    hash_update(&hmac_ctx, ipad, HMAC_BLOCK_SIZE);
    hash_update(&hmac_ctx, output, 8);
    hash_update(&hmac_ctx, salt, KDF_SALT_SIZE);
    hash_update(&hmac_ctx, iv, BLOCK_SIZE);
    
    uint8_t prev[BLOCK_SIZE];
    memcpy(prev, iv, BLOCK_SIZE);
    
    uint8_t padded_plain[BLOCK_SIZE * 2];
    size_t pos = 0;
    
    while (pos < plaintext_len) {
        size_t chunk = plaintext_len - pos;
        if (chunk > BLOCK_SIZE) chunk = BLOCK_SIZE;
        
        uint8_t block[BLOCK_SIZE];
        if (chunk < BLOCK_SIZE) {
            memcpy(block, plaintext + pos, chunk);
            add_pkcs7_padding(block, chunk, BLOCK_SIZE);
        } else {
            memcpy(block, plaintext + pos, BLOCK_SIZE);
        }
        
        for (int i = 0; i < BLOCK_SIZE; i++) block[i] ^= prev[i];
        encrypt_block(block, round_keys);
        hash_update(&hmac_ctx, block, BLOCK_SIZE);
        
        memcpy(output + offset, block, BLOCK_SIZE);
        memcpy(prev, block, BLOCK_SIZE);
        offset += BLOCK_SIZE;
        
        if (chunk < BLOCK_SIZE) break;
        pos += BLOCK_SIZE;
    }
    
    if (plaintext_len % BLOCK_SIZE == 0) {
        uint8_t pad_block[BLOCK_SIZE];
        memset(pad_block, BLOCK_SIZE, BLOCK_SIZE);
        
        for (int i = 0; i < BLOCK_SIZE; i++) pad_block[i] ^= prev[i];
        encrypt_block(pad_block, round_keys);
        hash_update(&hmac_ctx, pad_block, BLOCK_SIZE);
        
        memcpy(output + offset, pad_block, BLOCK_SIZE);
        memcpy(prev, pad_block, BLOCK_SIZE);
        offset += BLOCK_SIZE;
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
    memcpy(output + offset, mac, HMAC_SIZE);
    offset += HMAC_SIZE;
    
    *ciphertext_len = offset;
    
    secure_zero(enc_key, sizeof(enc_key));
    secure_zero(mac_key, sizeof(mac_key));
    secure_zero(round_keys, sizeof(round_keys));
    secure_zero(hmac_key, sizeof(hmac_key));
    secure_zero(prev, sizeof(prev));
    secure_zero(inner_hash, sizeof(inner_hash));
    
    return 0;
}

static int repl_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                        uint8_t *plaintext, size_t *plaintext_len,
                        const uint8_t *key, size_t key_len) {
    
    if (ciphertext_len < 8 + KDF_SALT_SIZE + BLOCK_SIZE + BLOCK_SIZE + HMAC_SIZE) {
        return -1;
    }
    
    uint64_t original_size = ((uint64_t)ciphertext[0] << 56) |
                             ((uint64_t)ciphertext[1] << 48) |
                             ((uint64_t)ciphertext[2] << 40) |
                             ((uint64_t)ciphertext[3] << 32) |
                             ((uint64_t)ciphertext[4] << 24) |
                             ((uint64_t)ciphertext[5] << 16) |
                             ((uint64_t)ciphertext[6] << 8)  |
                             ((uint64_t)ciphertext[7]);
    
    if (original_size > MAX_TEXT) return -1;
    
    size_t offset = 8;
    
    uint8_t salt[KDF_SALT_SIZE];
    memcpy(salt, ciphertext + offset, KDF_SALT_SIZE);
    offset += KDF_SALT_SIZE;
    
    uint8_t iv[BLOCK_SIZE];
    memcpy(iv, ciphertext + offset, BLOCK_SIZE);
    offset += BLOCK_SIZE;
    
    size_t encrypted_data_len = ciphertext_len - offset - HMAC_SIZE;
    if (encrypted_data_len % BLOCK_SIZE != 0) return -1;
    if (encrypted_data_len < BLOCK_SIZE) return -1;
    
    uint8_t stored_mac[HMAC_SIZE];
    memcpy(stored_mac, ciphertext + ciphertext_len - HMAC_SIZE, HMAC_SIZE);
    
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
    
    uint8_t hmac_key[HMAC_BLOCK_SIZE];
    memset(hmac_key, 0, HMAC_BLOCK_SIZE);
    memcpy(hmac_key, mac_key, KDF_DERIVED_KEY_SIZE);
    
    HASH_CTX hmac_ctx;
    hash_init(&hmac_ctx);
    
    uint8_t ipad[HMAC_BLOCK_SIZE];
    for (int i = 0; i < HMAC_BLOCK_SIZE; i++) ipad[i] = hmac_key[i] ^ 0x36;
    hash_update(&hmac_ctx, ipad, HMAC_BLOCK_SIZE);
    hash_update(&hmac_ctx, ciphertext, 8);
    hash_update(&hmac_ctx, salt, KDF_SALT_SIZE);
    hash_update(&hmac_ctx, iv, BLOCK_SIZE);
    hash_update(&hmac_ctx, ciphertext + offset, encrypted_data_len);
    
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
        return -2;
    }
    
    sbox_init();
    uint8_t round_keys[ROUNDS + 1][BLOCK_SIZE];
    keygen_expand(enc_key, KDF_DERIVED_KEY_SIZE, round_keys);
    
    uint8_t prev[BLOCK_SIZE];
    memcpy(prev, iv, BLOCK_SIZE);
    
    size_t plain_offset = 0;
    
    for (size_t i = 0; i < encrypted_data_len - BLOCK_SIZE; i += BLOCK_SIZE) {
        uint8_t temp[BLOCK_SIZE];
        uint8_t decrypted[BLOCK_SIZE];
        
        memcpy(temp, ciphertext + offset + i, BLOCK_SIZE);
        decrypt_block(temp, round_keys);
        for (int j = 0; j < BLOCK_SIZE; j++) decrypted[j] = temp[j] ^ prev[j];
        memcpy(prev, ciphertext + offset + i, BLOCK_SIZE);
        
        memcpy(plaintext + plain_offset, decrypted, BLOCK_SIZE);
        plain_offset += BLOCK_SIZE;
    }
    
    size_t last_block_idx = encrypted_data_len - BLOCK_SIZE;
    uint8_t last_encrypted[BLOCK_SIZE];
    uint8_t last_decrypted[BLOCK_SIZE];
    
    memcpy(last_encrypted, ciphertext + offset + last_block_idx, BLOCK_SIZE);
    decrypt_block(last_encrypted, round_keys);
    for (int j = 0; j < BLOCK_SIZE; j++) last_decrypted[j] = last_encrypted[j] ^ prev[j];
    
    size_t unpadded_len;
    if (remove_pkcs7_padding(last_decrypted, BLOCK_SIZE, &unpadded_len) != 0) {
        secure_zero(enc_key, sizeof(enc_key));
        secure_zero(mac_key, sizeof(mac_key));
        secure_zero(round_keys, sizeof(round_keys));
        secure_zero(hmac_key, sizeof(hmac_key));
        return -2;
    }
    
    if (unpadded_len > 0) {
        memcpy(plaintext + plain_offset, last_decrypted, unpadded_len);
        plain_offset += unpadded_len;
    }
    
    *plaintext_len = plain_offset;
    
    secure_zero(enc_key, sizeof(enc_key));
    secure_zero(mac_key, sizeof(mac_key));
    secure_zero(round_keys, sizeof(round_keys));
    secure_zero(hmac_key, sizeof(hmac_key));
    secure_zero(prev, sizeof(prev));
    secure_zero(last_encrypted, sizeof(last_encrypted));
    secure_zero(last_decrypted, sizeof(last_decrypted));
    secure_zero(inner_hash, sizeof(inner_hash));
    secure_zero(computed_mac, sizeof(computed_mac));
    
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