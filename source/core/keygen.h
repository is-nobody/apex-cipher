// source/core/keygen.h
#ifndef KEYGEN_H
#define KEYGEN_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include "sbox.h"

#define ROUNDS 10
#define DEFAULT_KEY_SIZE 32

void keygen_expand(const uint8_t *master_key, size_t key_len,
                   uint8_t round_keys[ROUNDS + 1][BLOCK_SIZE]);

void keygen_generate_iv(uint8_t iv[BLOCK_SIZE]);

void keygen_random_key(uint8_t *key, size_t len);

#endif