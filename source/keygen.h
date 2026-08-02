#ifndef KEYGEN_H
#define KEYGEN_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include "sbox.h"

#define ROUNDS 10

void keygen_expand(const uint8_t *master_key, size_t key_len,
                   uint8_t round_keys[ROUNDS][BLOCK_SIZE]);

void keygen_generate_iv(uint8_t iv[BLOCK_SIZE]);

#endif