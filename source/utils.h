#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>

void utils_print_base64(const uint8_t *data, size_t len);
void utils_print_safe(const uint8_t *data, size_t len);
size_t utils_read_base64_line(uint8_t *buffer, size_t max_len);
void utils_show_key(const uint8_t *key, size_t key_len);

#endif