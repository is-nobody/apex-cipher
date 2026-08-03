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
#define COLOR_CYAN "\033[1;36m"
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

static void show_progress(size_t current, size_t total) {
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
    
    if (dot && (!slash || dot > slash)) {
        *dot = '\0';
    }
    
    strcat(output_name, ext);
    return output_name;
}

static int encrypt_file_small(const char *filename, const char *output_name,
                              uint8_t *key, size_t key_len) {
    FILE *input = fopen(filename, "rb");
    if (!input) {
        printf(COLOR_RED "Error: Cannot open file '%s'\n" COLOR_RESET, filename);
        return 1;
    }
    
    fseek(input, 0, SEEK_END);
    long file_size = ftell(input);
    fseek(input, 0, SEEK_SET);
    
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
    
    show_progress(file_size, file_size);
    
    uint8_t encrypted[MAX_ENCRYPTED];
    size_t enc_len;
    
    if (cipher_encrypt(data, bytes_read, key, key_len, encrypted, &enc_len) != 0) {
        printf("\n" COLOR_RED "Error: Encryption failed\n" COLOR_RESET);
        free(data);
        return 1;
    }
    
    free(data);
    
    size_t b64_len = ((enc_len + 2) / 3) * 4 + 1;
    char *b64_output = (char*)malloc(b64_len);
    if (!b64_output) {
        printf("\n" COLOR_RED "Error: Memory allocation failed\n" COLOR_RESET);
        return 1;
    }
    base64_encode(encrypted, enc_len, b64_output);
    
    FILE *output = fopen(output_name, "w");
    if (!output) {
        printf("\n" COLOR_RED "Error: Cannot create output file '%s'\n" COLOR_RESET, output_name);
        free(b64_output);
        return 1;
    }
    
    fprintf(output, "%s\n", b64_output);
    fclose(output);
    free(b64_output);
    
    return 0;
}

static int decrypt_file_small(const char *filename, const char *output_name,
                              uint8_t *key, size_t key_len) {
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
    
    FILE *output = fopen(output_name, "wb");
    if (!output) {
        printf(COLOR_RED "Error: Cannot create output file '%s'\n" COLOR_RESET, output_name);
        return 1;
    }
    
    fwrite(decrypted, 1, dec_len, output);
    fclose(output);
    
    return 0;
}

static int encrypt_file(const char *filename, const char *key_str) {
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
    
    int result;
    
    if (file_size <= MAX_TEXT) {
        result = encrypt_file_small(filename, output_name, key, key_len);
        if (result == 0) {
            FILE *out = fopen(output_name, "rb");
            long enc_size = 0;
            if (out) {
                fseek(out, 0, SEEK_END);
                enc_size = ftell(out);
                fclose(out);
            }
            printf("\n" COLOR_GREEN "Successfully encrypted: %s (%ld bytes)\n" COLOR_RESET, output_name, enc_size);
        }
    } else {
        result = cipher_encrypt_file(filename, output_name, key, key_len, show_progress);
        
        if (result == 0) {
            printf("\n" COLOR_GREEN "Successfully encrypted: %s\n" COLOR_RESET, output_name);
        } else {
            printf("\n" COLOR_RED "Error: Encryption failed (code: %d)\n" COLOR_RESET, result);
        }
    }
    
    free(output_name);
    return result;
}

static int decrypt_file(const char *filename, const char *key_str) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        printf(COLOR_RED "Error: Cannot open file '%s'\n" COLOR_RESET, filename);
        return 1;
    }
    
    uint8_t header[16];
    size_t header_read = fread(header, 1, 16, f);
    
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fclose(f);
    
    if (file_size <= 0 || header_read == 0) {
        printf(COLOR_RED "Error: File is empty or unreadable\n" COLOR_RESET);
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
    
    int result;
    
    int is_base64 = 1;
    for (size_t i = 0; i < header_read; i++) {
        if (header[i] < 32 || header[i] > 126) {
            is_base64 = 0;
            break;
        }
    }
    
    if (is_base64 && file_size < 24576) {
        result = decrypt_file_small(filename, output_name, key, key_len);
        if (result == 0) {
            FILE *out = fopen(output_name, "rb");
            long dec_size = 0;
            if (out) {
                fseek(out, 0, SEEK_END);
                dec_size = ftell(out);
                fclose(out);
            }
            printf(COLOR_GREEN "Successfully decrypted: %s (%ld bytes)\n" COLOR_RESET, output_name, dec_size);
        }
    } else {
        result = cipher_decrypt_file(filename, output_name, key, key_len, show_progress);
        
        if (result == 0) {
            printf("\n" COLOR_GREEN "Successfully decrypted: %s\n" COLOR_RESET, output_name);
        } else if (result == -2) {
            printf("\n" COLOR_RED "Wrong key or corrupted data (authentication failed)!\n" COLOR_RESET);
        } else {
            printf("\n" COLOR_RED "Error: Decryption failed (code: %d)\n" COLOR_RESET, result);
        }
    }
    
    if (result != 0) {
        remove(output_name);
    }
    
    free(output_name);
    return result;
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