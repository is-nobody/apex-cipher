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
    for (int i = 0; i < BLOCK_SIZE; i++) {
        block[i] = SBOX[block[i]];
    }
}

void round_apply_inv_sbox(uint8_t *block) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        block[i] = INV_SBOX[block[i]];
    }
}

static uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1B;
        b >>= 1;
    }
    return p;
}

static void mix_bytes(uint8_t *block) {
    uint8_t tmp[BLOCK_SIZE];
    memcpy(tmp, block, BLOCK_SIZE);
    
    for (int col = 0; col < 4; col++) {
        int base = col * 4;
        block[base + 0] = gf_mul(2, tmp[base + 0]) ^ gf_mul(3, tmp[base + 1]) ^ tmp[base + 2] ^ tmp[base + 3];
        block[base + 1] = tmp[base + 0] ^ gf_mul(2, tmp[base + 1]) ^ gf_mul(3, tmp[base + 2]) ^ tmp[base + 3];
        block[base + 2] = tmp[base + 0] ^ tmp[base + 1] ^ gf_mul(2, tmp[base + 2]) ^ gf_mul(3, tmp[base + 3]);
        block[base + 3] = gf_mul(3, tmp[base + 0]) ^ tmp[base + 1] ^ tmp[base + 2] ^ gf_mul(2, tmp[base + 3]);
    }
}

static void inv_mix_bytes(uint8_t *block) {
    uint8_t tmp[BLOCK_SIZE];
    memcpy(tmp, block, BLOCK_SIZE);
    
    for (int col = 0; col < 4; col++) {
        int base = col * 4;
        block[base + 0] = gf_mul(14, tmp[base + 0]) ^ gf_mul(11, tmp[base + 1]) ^ gf_mul(13, tmp[base + 2]) ^ gf_mul(9, tmp[base + 3]);
        block[base + 1] = gf_mul(9, tmp[base + 0]) ^ gf_mul(14, tmp[base + 1]) ^ gf_mul(11, tmp[base + 2]) ^ gf_mul(13, tmp[base + 3]);
        block[base + 2] = gf_mul(13, tmp[base + 0]) ^ gf_mul(9, tmp[base + 1]) ^ gf_mul(14, tmp[base + 2]) ^ gf_mul(11, tmp[base + 3]);
        block[base + 3] = gf_mul(11, tmp[base + 0]) ^ gf_mul(13, tmp[base + 1]) ^ gf_mul(9, tmp[base + 2]) ^ gf_mul(14, tmp[base + 3]);
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

void round_mix(uint8_t *block) {
    mix_bytes(block);
}

void round_inv_mix(uint8_t *block) {
    inv_mix_bytes(block);
}