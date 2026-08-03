#include "encrypt_decrypt.h"
#include "round_ops.h"

void encrypt_block(uint8_t *block, uint8_t round_keys[ROUNDS + 1][BLOCK_SIZE]) {
    round_xor_with_key(block, round_keys[0]);
    
    for (int r = 1; r < ROUNDS; r++) {
        round_apply_sbox(block);
        round_shift_rows(block);
        round_mix(block);
        round_xor_with_key(block, round_keys[r]);
    }
    
    round_apply_sbox(block);
    round_shift_rows(block);
    round_xor_with_key(block, round_keys[ROUNDS]);
}

void decrypt_block(uint8_t *block, uint8_t round_keys[ROUNDS + 1][BLOCK_SIZE]) {
    round_xor_with_key(block, round_keys[ROUNDS]);
    
    round_inv_shift_rows(block);
    round_apply_inv_sbox(block);
    
    for (int r = ROUNDS - 1; r >= 1; r--) {
        round_xor_with_key(block, round_keys[r]);
        round_inv_mix(block);
        round_inv_shift_rows(block);
        round_apply_inv_sbox(block);
    }
    
    round_xor_with_key(block, round_keys[0]);
}