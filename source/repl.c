#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "repl.h"
#include "cipher.h"
#include "utils.h"

#define MAX_TEXT 4096

static uint8_t current_key[64] = "key";
static size_t current_key_len = 3;

static size_t read_multiline(uint8_t *buffer, size_t max_len) {
    size_t total = 0;
    char line[8192];
    
    printf("Enter text (empty line to finish):\n");
    
    while (total < max_len && fgets(line, sizeof(line), stdin)) {
        int empty = 1;
        for (char *p = line; *p && *p != '\n'; p++) {
            if (*p != ' ' && *p != '\t' && *p != '\r') {
                empty = 0;
                break;
            }
        }
        
        if (empty && total > 0) break;
        if (empty && total == 0) continue;
        
        size_t line_len = strlen(line);
        size_t to_copy = (total + line_len <= max_len) ? line_len : (max_len - total);
        memcpy(buffer + total, line, to_copy);
        total += to_copy;
        
        if (total >= max_len) break;
    }
    
    if (total > 0 && buffer[total - 1] == '\n') {
        total--;
    }
    
    return total;
}

void repl_run(void) {
    uint8_t input[MAX_TEXT];
    uint8_t encrypted[MAX_ENCRYPTED];
    uint8_t decrypted[MAX_TEXT];
    size_t enc_len, dec_len;
    int choice;
    
    printf("Welcome to Apex Cipher!\n");
    printf("Max text: %d bytes | Key: up to 64 bytes\n", MAX_TEXT);
    printf("Cipher: 10-round SPN + CBC + HMAC | Format: Base64\n");
    utils_show_key(current_key, current_key_len);
    printf("\n");
    
    while (1) {
        printf("1. Encrypt\n");
        printf("2. Decrypt\n");
        printf("3. Set key\n");
        printf("4. Exit\n");
        printf("> ");
        
        if (scanf("%d", &choice) != 1) {
            int c;
            while ((c = getchar()) != '\n' && c != EOF);
            break;
        }
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
        
        if (choice == 1) {
            size_t input_len = read_multiline(input, MAX_TEXT);
            
            if (input_len == 0) {
                printf("No data entered.\n\n");
                continue;
            }
            
            printf("\nOriginal (%zu bytes): ", input_len);
            utils_print_safe(input, input_len);
            printf("\n\n");
            
            if (cipher_encrypt(input, input_len, current_key, current_key_len, 
                              encrypted, &enc_len) != 0) {
                printf("Encryption failed!\n\n");
                continue;
            }
            
            printf("Encrypted (%zu bytes):\n", enc_len);
            utils_print_base64(encrypted, enc_len);
            
            int result = cipher_decrypt(encrypted, enc_len, current_key, current_key_len,
                                       decrypted, &dec_len);
            if (result == 0) {
                printf("Verify (%zu bytes): ", dec_len);
                utils_print_safe(decrypted, dec_len);
                printf("\n");
                if (dec_len == input_len && memcmp(input, decrypted, input_len) == 0) {
                    printf("✓ OK\n\n");
                } else {
                    printf("✗ Data mismatch\n\n");
                }
            } else if (result == -2) {
                printf("✗ AUTH FAILED!\n\n");
            } else {
                printf("✗ Decryption failed\n\n");
            }
            
        } else if (choice == 2) {
            uint8_t data_buf[MAX_ENCRYPTED];
            size_t byte_count = utils_read_base64_line(data_buf, MAX_ENCRYPTED);
            
            if (byte_count == 0) {
                printf("No data entered.\n\n");
                continue;
            }
            
            printf("Read %zu bytes\n", byte_count);
            
            int result = cipher_decrypt(data_buf, byte_count, current_key, current_key_len,
                                       decrypted, &dec_len);
            if (result == -2) {
                printf("✗ AUTH FAILED! Wrong key or corrupted data!\n\n");
            } else if (result != 0) {
                printf("Decryption failed! (code: %d)\n\n", result);
            } else {
                printf("Decrypted (%zu bytes): ", dec_len);
                utils_print_safe(decrypted, dec_len);
                printf("\n\n");
            }
            
        } else if (choice == 3) {
            utils_show_key(current_key, current_key_len);
            printf("New key (empty = keep current): ");
            
            uint8_t new_key[65];
            size_t new_len = 0;
            
            while (new_len < 64 && (c = getchar()) != '\n' && c != EOF) {
                new_key[new_len++] = (uint8_t)c;
            }
            
            if (new_len > 0) {
                memcpy(current_key, new_key, new_len);
                current_key_len = new_len;
                printf("Updated! ");
                utils_show_key(current_key, current_key_len);
            } else {
                printf("Unchanged. ");
                utils_show_key(current_key, current_key_len);
            }
            printf("\n");
            
        } else if (choice == 4) {
            printf("Bye!\n");
            break;
        } else {
            printf("Use 1-4.\n\n");
        }
    }
}