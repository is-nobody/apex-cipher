#include <string.h>
#include "round_ops.h"

void round_xor_with_key(uint8_t *block, const uint8_t *key) {
    uint32_t *b = (uint32_t*)block;
    const uint32_t *k = (const uint32_t*)key;
    b[0] ^= k[0];
    b[1] ^= k[1];
    b[2] ^= k[2];
    b[3] ^= k[3];
}

void round_apply_sbox(uint8_t *block) {
    uint32_t *b = (uint32_t*)block;
    for (int i = 0; i < 4; i++) {
        uint32_t w = b[i];
        b[i] = ((uint32_t)SBOX[w & 0xFF]) |
               ((uint32_t)SBOX[(w >> 8) & 0xFF] << 8) |
               ((uint32_t)SBOX[(w >> 16) & 0xFF] << 16) |
               ((uint32_t)SBOX[(w >> 24) & 0xFF] << 24);
    }
}

void round_apply_inv_sbox(uint8_t *block) {
    uint32_t *b = (uint32_t*)block;
    for (int i = 0; i < 4; i++) {
        uint32_t w = b[i];
        b[i] = ((uint32_t)INV_SBOX[w & 0xFF]) |
               ((uint32_t)INV_SBOX[(w >> 8) & 0xFF] << 8) |
               ((uint32_t)INV_SBOX[(w >> 16) & 0xFF] << 16) |
               ((uint32_t)INV_SBOX[(w >> 24) & 0xFF] << 24);
    }
}

void round_rotate_left(uint8_t *block, int shift) {
    if (shift == 0) return;
    uint32_t *b = (uint32_t*)block;
    uint32_t tmp[4];
    int words = shift / 4;
    for (int i = 0; i < 4; i++) {
        tmp[i] = b[(i + words) % 4];
    }
    memcpy(b, tmp, 16);
}

void round_rotate_right(uint8_t *block, int shift) {
    if (shift == 0) return;
    uint32_t *b = (uint32_t*)block;
    uint32_t tmp[4];
    int words = (4 - shift / 4) % 4;
    for (int i = 0; i < 4; i++) {
        tmp[i] = b[(i + words) % 4];
    }
    memcpy(b, tmp, 16);
}