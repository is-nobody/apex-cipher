#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
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

void repl_run(void) {
    uint8_t input[MAX_TEXT];
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
            
            char in_name[] = "/tmp/apex_repl_in.XXXXXX";
            char out_name[] = "/tmp/apex_repl_out.XXXXXX";
            int fd_in = mkstemp(in_name);
            int fd_out = mkstemp(out_name);
            if (fd_in < 0 || fd_out < 0) { printf("Error creating temp files.\n\n"); continue; }
            
            FILE *fin = fdopen(fd_in, "wb");
            fwrite(input, 1, len, fin);
            fclose(fin);
            close(fd_out);
            
            if (cipher_encrypt_file(in_name, out_name, current_key, current_key_len, NULL) != 0) {
                printf("Encryption failed!\n\n");
                unlink(in_name);
                unlink(out_name);
                continue;
            }
            
            FILE *fout = fopen(out_name, "rb");
            fseek(fout, 0, SEEK_END);
            long enc_size = ftell(fout);
            fseek(fout, 0, SEEK_SET);
            
            printf("Encrypted (%ld bytes):\n", enc_size);
            uint8_t buf[16];
            size_t n;
            while ((n = fread(buf, 1, 16, fout)) > 0) {
                for (size_t i = 0; i < n; i++) printf("%02x", buf[i]);
            }
            printf("\n\n");
            fclose(fout);
            unlink(in_name);
            unlink(out_name);
            
        } else if (choice == 2) {
            printf("Enter hex: ");
            char hex[65536];
            if (!fgets(hex, sizeof(hex), stdin)) continue;
            size_t hex_len = strlen(hex);
            if (hex_len > 0 && hex[hex_len - 1] == '\n') { hex[hex_len - 1] = 0; hex_len--; }
            if (hex_len == 0) { printf("No data entered.\n\n"); continue; }
            
            char in_name[] = "/tmp/apex_repl_in.XXXXXX";
            char out_name[] = "/tmp/apex_repl_out.XXXXXX";
            int fd_in = mkstemp(in_name);
            int fd_out = mkstemp(out_name);
            if (fd_in < 0 || fd_out < 0) { printf("Error creating temp files.\n\n"); continue; }
            
            FILE *fin = fdopen(fd_in, "wb");
            for (size_t i = 0; i + 1 < hex_len; i += 2) {
                unsigned int byte;
                sscanf(hex + i, "%2x", &byte);
                fputc(byte, fin);
            }
            fclose(fin);
            close(fd_out);
            
            int result = cipher_decrypt_file(in_name, out_name, current_key, current_key_len, NULL);
            
            if (result == -2) {
                printf("Wrong key or corrupted data!\n\n");
            } else if (result != 0) {
                printf("Decryption failed! (code: %d)\n\n", result);
            } else {
                FILE *fout = fopen(out_name, "rb");
                fseek(fout, 0, SEEK_END);
                long dec_size = ftell(fout);
                fseek(fout, 0, SEEK_SET);
                
                uint8_t *dec = (uint8_t*)malloc(dec_size + 1);
                if (fread(dec, 1, dec_size, fout) == (size_t)dec_size) {
                    dec[dec_size] = 0;
                    printf("Decrypted (%ld bytes):\n%s\n\n", dec_size, dec);
                }
                fclose(fout);
                free(dec);
            }
            unlink(in_name);
            unlink(out_name);
            
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
        } else {
            printf("Use 1-3.\n\n");
        }
    }
}