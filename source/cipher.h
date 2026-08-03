#ifndef CIPHER_H
#define CIPHER_H

#include <stdint.h>
#include <stddef.h>

#define MAX_TEXT 16384
#define MAX_ENCRYPTED (16 + sizeof(uint32_t) + ((MAX_TEXT + 15) / 16) * 16 + 32)

int cipher_encrypt(const uint8_t *data, size_t data_len,
                   const uint8_t *key, size_t key_len,
                   uint8_t *ciphertext, size_t *out_len);

int cipher_decrypt(const uint8_t *ciphertext, size_t len,
                   const uint8_t *key, size_t key_len,
                   uint8_t *plaintext, size_t *out_len);

#endif