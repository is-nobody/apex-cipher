#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "utils.h"
#include "codecs.h"

void utils_print_base64(const uint8_t *data, size_t len) {
    size_t out_size = ((len + 2) / 3) * 4 + 1;
    char *out = (char*)malloc(out_size);
    if (!out) return;
    base64_encode(data, len, out);
    printf("%s\n", out);
    free(out);
}

void utils_print_safe(const uint8_t *data, size_t len) {
    fwrite(data, 1, len, stdout);
}

size_t utils_read_base64_line(uint8_t *buffer, size_t max_len) {
    char line[8192];
    
    printf("Enter encoded: ");
    
    if (!fgets(line, sizeof(line), stdin)) {
        return 0;
    }
    
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n') {
        line[len - 1] = '\0';
        len--;
    }
    
    char cleaned[8192];
    size_t clen = 0;
    for (size_t i = 0; i < len && clen < sizeof(cleaned) - 1; i++) {
        if (!isspace((unsigned char)line[i])) {
            cleaned[clen++] = line[i];
        }
    }
    cleaned[clen] = '\0';
    
    size_t decoded_len;
    if (base64_decode(cleaned, buffer, &decoded_len)) {
        return decoded_len;
    }
    
    return 0;
}

void utils_show_key(const uint8_t *key, size_t key_len) {
    printf("Key: ");
    for (size_t i = 0; i < key_len; i++) {
        printf("%02x", key[i]);
    }
    printf(" (%zu bytes)\n", key_len);
}