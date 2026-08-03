#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "repl.h"
#include "cipher.h"
#include "utils.h"
#include "keygen.h"
#include "crypto_context.h"

static uint8_t current_key[64];
static size_t current_key_len = DEFAULT_KEY_SIZE;
static int key_initialized = 0;

static void init_key(void) {
    if (!key_initialized) {
        crypto_get_default_key(current_key);
        key_initialized = 1;
    }
}

static size_t read_single_line(uint8_t *buffer, size_t max_len) {
    char line[8192];
    
    printf("Enter text: ");
    
    if (!fgets(line, sizeof(line), stdin)) {
        return 0;
    }
    
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n') {
        line[len - 1] = '\0';
        len--;
    }
    
    size_t to_copy = (len < max_len) ? len : max_len;
    memcpy(buffer, line, to_copy);
    
    return to_copy;
}

void repl_run(void) {
    uint8_t input[MAX_TEXT];
    uint8_t encrypted[MAX_ENCRYPTED];
    uint8_t decrypted[MAX_TEXT];
    size_t enc_len, dec_len;
    int choice;
    
    init_key();

    printf("Welcome to Apex Cipher!\n");
    printf("Max text: %d bytes | Key: up to 64 bytes\n", MAX_TEXT);
    printf("Cipher: 10-round SPN + CBC + HMAC | Format: Base64\n");
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
            size_t input_len = read_single_line(input, MAX_TEXT);
            
            if (input_len == 0) {
                printf("No data entered.\n\n");
                continue;
            }
            
            if (cipher_encrypt(input, input_len, current_key, current_key_len, 
                              encrypted, &enc_len) != 0) {
                printf("Encryption failed!\n\n");
                continue;
            }
            
            printf("Encrypted (%zu bytes):\n", enc_len);
            utils_print_base64(encrypted, enc_len);
            printf("\n");
        } else if (choice == 2) {
            uint8_t data_buf[MAX_ENCRYPTED];
            size_t byte_count = utils_read_base64_line(data_buf, MAX_ENCRYPTED);
            
            if (byte_count == 0) {
                printf("No data entered.\n\n");
                continue;
            }
            
            int result = cipher_decrypt(data_buf, byte_count, current_key, current_key_len,
                                       decrypted, &dec_len);
            if (result == -2) {
                printf("Wrong key or corrupted data!\n\n");
            } else if (result != 0) {
                printf("Decryption failed! (code: %d)\n\n", result);
            } else {
                printf("Decrypted (%zu bytes):\n", dec_len);
                utils_print_safe(decrypted, dec_len);
                printf("\n\n");
            }
            
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
                utils_show_key(current_key, current_key_len);
            } else {
                printf("Unchanged. ");
                utils_show_key(current_key, current_key_len);
            }
            printf("\n");
            
        } else {
            printf("Use 1-3.\n\n");
        }
    }
}