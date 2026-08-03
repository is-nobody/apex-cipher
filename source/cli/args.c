// source/cli/args.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "args.h"
#include "cipher.h"
#include "utils.h"
#include "keygen.h"

#define COLOR_GREEN "\033[1;32m"
#define COLOR_RED "\033[1;31m"
#define COLOR_CYAN "\033[1;36m"
#define COLOR_RESET "\033[0m"

static int is_hex_string(const char *str) {
    if (!str || !*str) return 0;
    for (size_t i = 0; str[i]; i++) {
        if (!isxdigit((unsigned char)str[i])) return 0;
    }
    return 1;
}

static void hex_to_bytes(const char *hex, uint8_t *bytes, size_t *len) {
    size_t hex_len = strlen(hex);
    *len = hex_len / 2;
    for (size_t i = 0; i < *len; i++) {
        unsigned int byte;
        sscanf(hex + i * 2, "%2x", &byte);
        bytes[i] = (uint8_t)byte;
    }
}

void show_progress(size_t current, size_t total) {
    float percent = (total > 0) ? (float)current / total * 100.0f : 0.0f;
    printf("\r" COLOR_CYAN "Progress: %.1f%% (%zu / %zu bytes)" COLOR_RESET, percent, current, total);
    fflush(stdout);
}

static void prepare_key(const char *key_str, uint8_t *key, size_t *key_len) {
    if (key_str) {
        if (strlen(key_str) % 2 == 0 && is_hex_string(key_str)) {
            hex_to_bytes(key_str, key, key_len);
        } else {
            *key_len = strlen(key_str);
            if (*key_len > 64) *key_len = 64;
            memcpy(key, key_str, *key_len);
        }
        utils_show_key(key, *key_len);
    } else {
        keygen_random_key(key, DEFAULT_KEY_SIZE);
        *key_len = DEFAULT_KEY_SIZE;
        utils_show_key(key, *key_len);
    }
}

static char* make_output_name(const char *filename, const char *ext) {
    char *output_name = (char*)malloc(1024);
    if (!output_name) return NULL;
    
    strncpy(output_name, filename, 1024 - 5);
    output_name[1024 - 5] = '\0';
    
    char *dot = strrchr(output_name, '.');
    char *slash = strrchr(output_name, '/');
    
#ifdef _WIN32
    char *bslash = strrchr(output_name, '\\');
    if (bslash && (!slash || bslash > slash)) slash = bslash;
#endif
    
    if (dot && (!slash || dot > slash)) *dot = '\0';
    
    strcat(output_name, ext);
    return output_name;
}

int args_encrypt_file(const char *filename, const char *key_str) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        printf(COLOR_RED "Error: Cannot open file '%s'\n" COLOR_RESET, filename);
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fclose(f);
    
    if (file_size <= 0) {
        printf(COLOR_RED "Error: File is empty\n" COLOR_RESET);
        return 1;
    }
    
    uint8_t key[64];
    size_t key_len;
    prepare_key(key_str, key, &key_len);
    
    char *output_name = make_output_name(filename, ".enc");
    if (!output_name) {
        printf(COLOR_RED "Error: Memory allocation failed\n" COLOR_RESET);
        return 1;
    }
    
    int result = cipher_encrypt_file(filename, output_name, key, key_len, show_progress);
    
    if (result == 0) {
        printf("\n" COLOR_GREEN "Successfully encrypted: %s\n" COLOR_RESET, output_name);
    } else {
        printf("\n" COLOR_RED "Error: Encryption failed (code: %d)\n" COLOR_RESET, result);
    }
    
    free(output_name);
    return result;
}

int args_decrypt_file(const char *filename, const char *key_str) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        printf(COLOR_RED "Error: Cannot open file '%s'\n" COLOR_RESET, filename);
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fclose(f);
    
    if (file_size <= 0) {
        printf(COLOR_RED "Error: File is empty\n" COLOR_RESET);
        return 1;
    }
    
    uint8_t key[64];
    size_t key_len;
    
    if (strlen(key_str) % 2 == 0 && is_hex_string(key_str)) {
        hex_to_bytes(key_str, key, &key_len);
    } else {
        key_len = strlen(key_str);
        if (key_len > 64) key_len = 64;
        memcpy(key, key_str, key_len);
    }
    utils_show_key(key, key_len);
    
    char *output_name = make_output_name(filename, ".dec");
    if (!output_name) {
        printf(COLOR_RED "Error: Memory allocation failed\n" COLOR_RESET);
        return 1;
    }
    
    int result = cipher_decrypt_file(filename, output_name, key, key_len, show_progress);
    
    if (result == 0) {
        printf("\n" COLOR_GREEN "Successfully decrypted: %s\n" COLOR_RESET, output_name);
    } else if (result == -2) {
        printf("\n" COLOR_RED "Wrong key or corrupted data (authentication failed)!\n" COLOR_RESET);
    } else {
        printf("\n" COLOR_RED "Error: Decryption failed (code: %d)\n" COLOR_RESET, result);
    }
    
    free(output_name);
    return result;
}

void print_usage(const char *program_name) {
    printf("Apex Cipher v26.08\n\n");
    printf("Usage:\n");
    printf("  %s                      - Interactive REPL mode\n", program_name);
    printf("  %s encode <file>        - Encrypt file with random key\n", program_name);
    printf("  %s encode <file> <key>  - Encrypt file with provided key\n", program_name);
    printf("  %s decode <file> <key>  - Decrypt file with key\n", program_name);
    printf("\n");
}