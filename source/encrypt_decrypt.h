#ifndef ENCRYPT_DECRYPT_H
#define ENCRYPT_DECRYPT_H

#include <stdint.h>
#include "sbox.h"
#include "keygen.h"

void encrypt_block(uint8_t *block, uint8_t round_keys[ROUNDS][BLOCK_SIZE]);
void decrypt_block(uint8_t *block, uint8_t round_keys[ROUNDS][BLOCK_SIZE]);

#endif