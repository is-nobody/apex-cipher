#ifndef CIPHER_H
#define CIPHER_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#define MAX_TEXT 16384
#define MAX_ENCRYPTED (16 + sizeof(uint32_t) + ((MAX_TEXT + 15) / 16) * 16 + 32)

int cipher_encrypt(const uint8_t *data, size_t data_len,
                   const uint8_t *key, size_t key_len,
                   uint8_t *ciphertext, size_t *out_len);

int cipher_decrypt(const uint8_t *ciphertext, size_t len,
                   const uint8_t *key, size_t key_len,
                   uint8_t *plaintext, size_t *out_len);

int cipher_encrypt_file(const char *input_path,
                        const char *output_path,
                        const uint8_t *key, size_t key_len,
                        void (*progress)(size_t current, size_t total));

int cipher_decrypt_file(const char *input_path,
                        const char *output_path,
                        const uint8_t *key, size_t key_len,
                        void (*progress)(size_t current, size_t total));

#endif