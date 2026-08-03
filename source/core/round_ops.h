#ifndef ROUND_OPS_H
#define ROUND_OPS_H

#include <stdint.h>
#include "sbox.h"

void round_xor_with_key(uint8_t *block, const uint8_t *key);
void round_apply_sbox(uint8_t *block);
void round_apply_inv_sbox(uint8_t *block);
void round_shift_rows(uint8_t *block);
void round_inv_shift_rows(uint8_t *block);
void round_mix(uint8_t *block);
void round_inv_mix(uint8_t *block);

#endif