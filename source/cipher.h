#ifndef CIPHER_H
#define CIPHER_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

int cipher_encrypt_file(const char *input_path,
                        const char *output_path,
                        const uint8_t *key, size_t key_len,
                        void (*progress)(size_t current, size_t total));

int cipher_decrypt_file(const char *input_path,
                        const char *output_path,
                        const uint8_t *key, size_t key_len,
                        void (*progress)(size_t current, size_t total));

#endif