#include "encrypt_decrypt.h"
#include "round_ops.h"

void encrypt_block(uint8_t *block, uint8_t round_keys[ROUNDS][BLOCK_SIZE]) {
    for (int r = 0; r < ROUNDS; r++) {
        round_xor_with_key(block, round_keys[r]);
        round_apply_sbox(block);
        round_shift_rows(block);
        round_mix(block);
    }
    round_xor_with_key(block, round_keys[0]);
}

void decrypt_block(uint8_t *block, uint8_t round_keys[ROUNDS][BLOCK_SIZE]) {
    round_xor_with_key(block, round_keys[0]);
    
    for (int r = ROUNDS - 1; r >= 0; r--) {
        round_inv_mix(block);
        round_inv_shift_rows(block);
        round_apply_inv_sbox(block);
        round_xor_with_key(block, round_keys[r]);
    }
}