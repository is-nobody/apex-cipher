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

#define COLOR_RED "\033[1;31m"
#define COLOR_RESET "\033[0m"

#define REPL_MAX_CIPHERTEXT 65536

static uint8_t current_key[64];
static size_t current_key_len = DEFAULT_KEY_SIZE;
static int key_initialized = 0;

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
    
    size_t encrypted_start = offset;
    
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
        
        cipher_cbc_encrypt_block(block, prev, &ctx);
        memcpy(output + offset, block, BLOCK_SIZE);
        offset += BLOCK_SIZE;
        
        if (chunk < BLOCK_SIZE) break;
        pos += BLOCK_SIZE;
    }
    
    if (plaintext_len % BLOCK_SIZE == 0) {
        uint8_t pad_block[BLOCK_SIZE];
        memset(pad_block, BLOCK_SIZE, BLOCK_SIZE);
        cipher_cbc_encrypt_block(pad_block, prev, &ctx);
        memcpy(output + offset, pad_block, BLOCK_SIZE);
        offset += BLOCK_SIZE;
    }
    
    size_t encrypted_len = offset - encrypted_start;
    size_t header_size = 8 + KDF_SALT_SIZE + BLOCK_SIZE;
    size_t hmac_data_size = header_size + encrypted_len;
    uint8_t *hmac_data = (uint8_t*)malloc(hmac_data_size);
    if (hmac_data) {
        memcpy(hmac_data, output, 8);
        memcpy(hmac_data + 8, salt, KDF_SALT_SIZE);
        memcpy(hmac_data + 8 + KDF_SALT_SIZE, iv, BLOCK_SIZE);
        memcpy(hmac_data + header_size, output + encrypted_start, encrypted_len);
        
        uint8_t mac[HMAC_SIZE];
        hmac_compute(ctx.mac_key, KDF_DERIVED_KEY_SIZE, hmac_data, hmac_data_size, mac);
        memcpy(output + offset, mac, HMAC_SIZE);
        offset += HMAC_SIZE;
        
        cipher_secure_zero(hmac_data, hmac_data_size);
        free(hmac_data);
    }
    
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
    
    size_t header_size = 8 + KDF_SALT_SIZE + BLOCK_SIZE;
    size_t hmac_data_size = header_size + encrypted_data_len;
    uint8_t *hmac_data = (uint8_t*)malloc(hmac_data_size);
    if (!hmac_data) {
        cipher_ctx_cleanup(&ctx);
        return -1;
    }
    
    memcpy(hmac_data, ciphertext, 8);
    memcpy(hmac_data + 8, salt, KDF_SALT_SIZE);
    memcpy(hmac_data + 8 + KDF_SALT_SIZE, iv, BLOCK_SIZE);
    memcpy(hmac_data + header_size, ciphertext + offset, encrypted_data_len);
    
    uint8_t computed_mac[HMAC_SIZE];
    hmac_compute(ctx.mac_key, KDF_DERIVED_KEY_SIZE, hmac_data, hmac_data_size, computed_mac);
    
    cipher_secure_zero(hmac_data, hmac_data_size);
    free(hmac_data);
    
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
        current_key_len = DEFAULT_KEY_SIZE;
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
            
            cipher_secure_zero(output, sizeof(output));
            
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
                    hex_len = 0;
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
            
            cipher_secure_zero(decrypted, MAX_TEXT + 1);
            cipher_secure_zero(ciphertext, ciphertext_len);
            free(decrypted);
            free(ciphertext);
            
        } else if (choice == 3) {
            utils_show_key(current_key, current_key_len);
            printf("New key (empty = keep current, min %d bytes recommended): ", MIN_KEY_SIZE);
            
            uint8_t new_key[65];
            size_t new_len = 0;
            int c;
            while (new_len < 64 && (c = getchar()) != '\n' && c != EOF) {
                new_key[new_len++] = (uint8_t)c;
            }
            
            if (new_len > 0) {
                if (new_len < MIN_KEY_SIZE) {
                    printf(COLOR_RED "Warning: Key is only %zu bytes. "
                        "For full security, use at least %d bytes.\n" COLOR_RESET,
                        new_len, MIN_KEY_SIZE);
                }
                memcpy(current_key, new_key, new_len);
                current_key_len = new_len;
                printf("Updated! ");
            } else {
                printf("Unchanged. ");
            }
            utils_show_key(current_key, current_key_len);
            printf("\n");
            
            cipher_secure_zero(new_key, sizeof(new_key));
        } else {
            printf("Use 1-3.\n\n");
        }
    }
    
    cipher_secure_zero(current_key, sizeof(current_key));
    cipher_secure_zero(input, sizeof(input));
    cipher_secure_zero(output, sizeof(output));
}