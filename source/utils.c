#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "utils.h"

void utils_print_safe(const uint8_t *data, size_t len) {
    fwrite(data, 1, len, stdout);
}

void utils_show_key(const uint8_t *key, size_t key_len) {
    printf("Key: ");
    for (size_t i = 0; i < key_len; i++) {
        printf("%02x", key[i]);
    }
    printf(" (%zu bytes)\n", key_len);
}