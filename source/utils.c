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
    size_t total = 0;
    int started = 0;
    
    printf("Paste base64 (empty line to finish):\n");
    
    while (fgets(line, sizeof(line), stdin)) {
        int empty = 1;
        for (char *p = line; *p && *p != '\n'; p++) {
            if (!isspace((unsigned char)*p)) {
                empty = 0;
                break;
            }
        }
        
        if (empty && started) break;
        if (empty && !started) continue;
        
        started = 1;
        
        char cleaned[8192];
        size_t clen = 0;
        for (char *p = line; *p && clen < sizeof(cleaned) - 1; p++) {
            if (!isspace((unsigned char)*p)) {
                cleaned[clen++] = *p;
            }
        }
        cleaned[clen] = '\0';
        
        if (clen == 0) break;
        
        size_t decoded_len;
        if (base64_decode(cleaned, buffer + total, &decoded_len)) {
            total += decoded_len;
            if (total >= max_len) break;
        }
    }
    
    return total;
}

void utils_show_key(const uint8_t *key, size_t key_len) {
    printf("Current key: \"");
    fwrite(key, 1, key_len, stdout);
    printf("\" (%zu bytes)\n", key_len);
}