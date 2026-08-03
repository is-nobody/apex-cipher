#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "repl.h"
#include "cipher.h"
#include "utils.h"
#include "keygen.h"
#include "crypto_context.h"
#include "codecs.h"

#define COLOR_GREEN "\033[1;32m"
#define COLOR_RED "\033[1;31m"
#define COLOR_YELLOW "\033[1;33m"
#define COLOR_RESET "\033[0m"

static int is_hex_string(const char *str) {
    if (!str || !*str) return 0;
    for (size_t i = 0; str[i]; i++) {
        if (!isxdigit((unsigned char)str[i])) {
            return 0;
        }
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

static int encrypt_file(const char *filename, const char *key_str) {
    FILE *input = fopen(filename, "rb");
    if (!input) {
        printf(COLOR_RED "Error: Cannot open file '%s'\n" COLOR_RESET, filename);
        return 1;
    }
    
    fseek(input, 0, SEEK_END);
    long file_size = ftell(input);
    fseek(input, 0, SEEK_SET);
    
    if (file_size <= 0 || file_size > MAX_TEXT) {
        printf(COLOR_RED "Error: File is empty or too large (max %d bytes)\n" COLOR_RESET, MAX_TEXT);
        fclose(input);
        return 1;
    }
    
    uint8_t *data = (uint8_t*)malloc(file_size);
    if (!data) {
        printf(COLOR_RED "Error: Memory allocation failed\n" COLOR_RESET);
        fclose(input);
        return 1;
    }
    
    size_t bytes_read = fread(data, 1, file_size, input);
    fclose(input);
    
    if (bytes_read != (size_t)file_size) {
        printf(COLOR_RED "Error: Failed to read file\n" COLOR_RESET);
        free(data);
        return 1;
    }
    
    uint8_t key[64];
    size_t key_len;
    
    if (key_str) {
        if (strlen(key_str) % 2 == 0 && is_hex_string(key_str)) {
            hex_to_bytes(key_str, key, &key_len);
        } else {
            key_len = strlen(key_str);
            if (key_len > 64) key_len = 64;
            memcpy(key, key_str, key_len);
        }
        utils_show_key(key, key_len);
    } else {
        keygen_random_key(key, DEFAULT_KEY_SIZE);
        key_len = DEFAULT_KEY_SIZE;
        utils_show_key(key, key_len);
    }
    
    uint8_t encrypted[MAX_ENCRYPTED];
    size_t enc_len;
    
    if (cipher_encrypt(data, bytes_read, key, key_len, encrypted, &enc_len) != 0) {
        printf(COLOR_RED "Error: Encryption failed\n" COLOR_RESET);
        free(data);
        return 1;
    }
    
    free(data);
    
    size_t b64_len = ((enc_len + 2) / 3) * 4 + 1;
    char *b64_output = (char*)malloc(b64_len);
    if (!b64_output) {
        printf(COLOR_RED "Error: Memory allocation failed\n" COLOR_RESET);
        return 1;
    }
    base64_encode(encrypted, enc_len, b64_output);
    
    char output_name[1024];
    strncpy(output_name, filename, sizeof(output_name) - 5);
    output_name[sizeof(output_name) - 5] = '\0';
    
    char *dot = strrchr(output_name, '.');
    char *slash = strrchr(output_name, '/');
    
    if (dot && (!slash || dot > slash)) {
        *dot = '\0';
    }
    
    strcat(output_name, ".enc");
    
    FILE *output = fopen(output_name, "w");
    if (!output) {
        printf(COLOR_RED "Error: Cannot create output file '%s'\n" COLOR_RESET, output_name);
        free(b64_output);
        return 1;
    }
    
    fprintf(output, "%s\n", b64_output);
    
    long enc_file_size = ftell(output);
    fclose(output);
    free(b64_output);
    
    printf(COLOR_GREEN "Successfully encrypted: %s (%ld bytes)\n" COLOR_RESET, output_name, enc_file_size);
    return 0;
}

static int decrypt_file(const char *filename, const char *key_str) {
    FILE *input = fopen(filename, "rb");
    if (!input) {
        printf(COLOR_RED "Error: Cannot open file '%s'\n" COLOR_RESET, filename);
        return 1;
    }
    
    char b64_data[24576];
    if (!fgets(b64_data, sizeof(b64_data), input)) {
        printf(COLOR_RED "Error: Failed to read file\n" COLOR_RESET);
        fclose(input);
        return 1;
    }
    fclose(input);
    
    size_t b64_len = strlen(b64_data);
    if (b64_len > 0 && b64_data[b64_len - 1] == '\n') {
        b64_data[b64_len - 1] = '\0';
    }
    
    uint8_t encrypted[MAX_ENCRYPTED];
    size_t enc_len;
    
    if (!base64_decode(b64_data, encrypted, &enc_len)) {
        printf(COLOR_RED "Error: Invalid Base64 data\n" COLOR_RESET);
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
    
    uint8_t decrypted[MAX_TEXT];
    size_t dec_len;
    
    int result = cipher_decrypt(encrypted, enc_len, key, key_len, decrypted, &dec_len);
    
    if (result == -2) {
        printf(COLOR_RED "Wrong key or corrupted data!\n" COLOR_RESET);
        return 1;
    } else if (result != 0) {
        printf(COLOR_RED "Error: Decryption failed (code: %d)\n" COLOR_RESET, result);
        return 1;
    }
    
    char output_name[1024];
    strncpy(output_name, filename, sizeof(output_name) - 5);
    output_name[sizeof(output_name) - 5] = '\0';
    
    char *dot = strrchr(output_name, '.');
    char *slash = strrchr(output_name, '/');
    
    if (dot && (!slash || dot > slash)) {
        *dot = '\0';
    }
    
    strcat(output_name, ".dec");
    
    FILE *output = fopen(output_name, "wb");
    if (!output) {
        printf(COLOR_RED "Error: Cannot create output file '%s'\n" COLOR_RESET, output_name);
        return 1;
    }
    
    fwrite(decrypted, 1, dec_len, output);
    fclose(output);
    
    printf(COLOR_GREEN "Successfully decrypted: %s (%zu bytes)\n" COLOR_RESET, output_name, dec_len);
    return 0;
}

static void print_usage(const char *program_name) {
    printf("Apex Cipher v26.07\n\n");
    printf("Usage:\n");
    printf("  %s                      - Interactive REPL mode\n", program_name);
    printf("  %s encode <file>        - Encrypt file with random key\n", program_name);
    printf("  %s encode <file> <key>  - Encrypt file with provided key\n", program_name);
    printf("  %s decode <file> <key>  - Decrypt file with key\n", program_name);
    printf("\n");
}

int main(int argc, char *argv[]) {
    crypto_init_default_key();
    
    if (argc == 1) {
        repl_run();
        return 0;
    }
    
    const char *command = argv[1];
    
    if (strcmp(command, "decode") == 0) {
        if (argc == 2) {
            printf(COLOR_RED "Error: File and Key required for decryption\n" COLOR_RESET);
        } else if (argc == 3) {
            printf(COLOR_RED "Error: Key required for decryption\n" COLOR_RESET);
        } else {
            return decrypt_file(argv[2], argv[3]);
        }
        return 1;
    }
    
    if (strcmp(command, "encode") == 0) {
        if (argc == 2) {
            printf(COLOR_RED "Error: File required for encryption\n" COLOR_RESET);
        } else {
            const char *key = (argc > 3) ? argv[3] : NULL;
            return encrypt_file(argv[2], key);
        }
        return 1;
    }
    
    printf(COLOR_RED "Error: Unknown command '%s'\n" COLOR_RESET, command);
    print_usage(argv[0]);
    
    return 1;
}