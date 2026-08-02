#ifndef ROUND_OPS_H
#define ROUND_OPS_H

#include <stdint.h>
#include "sbox.h"

void round_xor_with_key(uint8_t *block, const uint8_t *key);
void round_apply_sbox(uint8_t *block);
void round_apply_inv_sbox(uint8_t *block);
void round_rotate_left(uint8_t *block, int shift);
void round_rotate_right(uint8_t *block, int shift);

#endif