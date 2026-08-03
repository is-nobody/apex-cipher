#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>

void utils_print_safe(const uint8_t *data, size_t len);
void utils_show_key(const uint8_t *key, size_t key_len);

#endif