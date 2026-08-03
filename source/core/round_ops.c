#include <string.h>
#include "round_ops.h"

static uint8_t gf_mul2[256];
static uint8_t gf_mul3[256];
static uint8_t gf_mul9[256];
static uint8_t gf_mul11[256];
static uint8_t gf_mul13[256];
static uint8_t gf_mul14[256];
static int gf_tables_initialized = 0;

static uint8_t gf_mul_slow(uint8_t a, uint8_t b) {
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

static void init_gf_tables(void) {
    if (gf_tables_initialized) return;
    for (int i = 0; i < 256; i++) {
        gf_mul2[i] = gf_mul_slow(i, 2);
        gf_mul3[i] = gf_mul_slow(i, 3);
        gf_mul9[i] = gf_mul_slow(i, 9);
        gf_mul11[i] = gf_mul_slow(i, 11);
        gf_mul13[i] = gf_mul_slow(i, 13);
        gf_mul14[i] = gf_mul_slow(i, 14);
    }
    gf_tables_initialized = 1;
}

void round_xor_with_key(uint8_t *block, const uint8_t *key) {
    uint32_t b[4];
    uint32_t k[4];
    
    memcpy(b, block, 16);
    memcpy(k, key, 16);
    
    b[0] ^= k[0];
    b[1] ^= k[1];
    b[2] ^= k[2];
    b[3] ^= k[3];
    
    memcpy(block, b, 16);
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

void round_shift_rows(uint8_t *block) {
    uint8_t tmp[BLOCK_SIZE];
    
    tmp[0]  = block[0];
    tmp[4]  = block[4];
    tmp[8]  = block[8];
    tmp[12] = block[12];
    
    tmp[1]  = block[5];
    tmp[5]  = block[9];
    tmp[9]  = block[13];
    tmp[13] = block[1];
    
    tmp[2]  = block[10];
    tmp[6]  = block[14];
    tmp[10] = block[2];
    tmp[14] = block[6];
    
    tmp[3]  = block[15];
    tmp[7]  = block[3];
    tmp[11] = block[7];
    tmp[15] = block[11];
    
    memcpy(block, tmp, BLOCK_SIZE);
}

void round_inv_shift_rows(uint8_t *block) {
    uint8_t tmp[BLOCK_SIZE];
    
    tmp[0]  = block[0];
    tmp[4]  = block[4];
    tmp[8]  = block[8];
    tmp[12] = block[12];
    
    tmp[1]  = block[13];
    tmp[5]  = block[1];
    tmp[9]  = block[5];
    tmp[13] = block[9];
    
    tmp[2]  = block[10];
    tmp[6]  = block[14];
    tmp[10] = block[2];
    tmp[14] = block[6];
    
    tmp[3]  = block[7];
    tmp[7]  = block[11];
    tmp[11] = block[15];
    tmp[15] = block[3];
    
    memcpy(block, tmp, BLOCK_SIZE);
}

static void mix_bytes(uint8_t *block) {
    init_gf_tables();
    
    uint8_t a0 = block[0],  a1 = block[1],  a2 = block[2],  a3 = block[3];
    uint8_t b0 = block[4],  b1 = block[5],  b2 = block[6],  b3 = block[7];
    uint8_t c0 = block[8],  c1 = block[9],  c2 = block[10], c3 = block[11];
    uint8_t d0 = block[12], d1 = block[13], d2 = block[14], d3 = block[15];
    
    block[0]  = gf_mul2[a0] ^ gf_mul3[a1] ^ a2 ^ a3;
    block[1]  = a0 ^ gf_mul2[a1] ^ gf_mul3[a2] ^ a3;
    block[2]  = a0 ^ a1 ^ gf_mul2[a2] ^ gf_mul3[a3];
    block[3]  = gf_mul3[a0] ^ a1 ^ a2 ^ gf_mul2[a3];
    
    block[4]  = gf_mul2[b0] ^ gf_mul3[b1] ^ b2 ^ b3;
    block[5]  = b0 ^ gf_mul2[b1] ^ gf_mul3[b2] ^ b3;
    block[6]  = b0 ^ b1 ^ gf_mul2[b2] ^ gf_mul3[b3];
    block[7]  = gf_mul3[b0] ^ b1 ^ b2 ^ gf_mul2[b3];
    
    block[8]  = gf_mul2[c0] ^ gf_mul3[c1] ^ c2 ^ c3;
    block[9]  = c0 ^ gf_mul2[c1] ^ gf_mul3[c2] ^ c3;
    block[10] = c0 ^ c1 ^ gf_mul2[c2] ^ gf_mul3[c3];
    block[11] = gf_mul3[c0] ^ c1 ^ c2 ^ gf_mul2[c3];
    
    block[12] = gf_mul2[d0] ^ gf_mul3[d1] ^ d2 ^ d3;
    block[13] = d0 ^ gf_mul2[d1] ^ gf_mul3[d2] ^ d3;
    block[14] = d0 ^ d1 ^ gf_mul2[d2] ^ gf_mul3[d3];
    block[15] = gf_mul3[d0] ^ d1 ^ d2 ^ gf_mul2[d3];
}

static void inv_mix_bytes(uint8_t *block) {
    init_gf_tables();
    
    uint8_t a0 = block[0],  a1 = block[1],  a2 = block[2],  a3 = block[3];
    uint8_t b0 = block[4],  b1 = block[5],  b2 = block[6],  b3 = block[7];
    uint8_t c0 = block[8],  c1 = block[9],  c2 = block[10], c3 = block[11];
    uint8_t d0 = block[12], d1 = block[13], d2 = block[14], d3 = block[15];
    
    block[0]  = gf_mul14[a0] ^ gf_mul11[a1] ^ gf_mul13[a2] ^ gf_mul9[a3];
    block[1]  = gf_mul9[a0]  ^ gf_mul14[a1] ^ gf_mul11[a2] ^ gf_mul13[a3];
    block[2]  = gf_mul13[a0] ^ gf_mul9[a1]  ^ gf_mul14[a2] ^ gf_mul11[a3];
    block[3]  = gf_mul11[a0] ^ gf_mul13[a1] ^ gf_mul9[a2]  ^ gf_mul14[a3];
    
    block[4]  = gf_mul14[b0] ^ gf_mul11[b1] ^ gf_mul13[b2] ^ gf_mul9[b3];
    block[5]  = gf_mul9[b0]  ^ gf_mul14[b1] ^ gf_mul11[b2] ^ gf_mul13[b3];
    block[6]  = gf_mul13[b0] ^ gf_mul9[b1]  ^ gf_mul14[b2] ^ gf_mul11[b3];
    block[7]  = gf_mul11[b0] ^ gf_mul13[b1] ^ gf_mul9[b2]  ^ gf_mul14[b3];
    
    block[8]  = gf_mul14[c0] ^ gf_mul11[c1] ^ gf_mul13[c2] ^ gf_mul9[c3];
    block[9]  = gf_mul9[c0]  ^ gf_mul14[c1] ^ gf_mul11[c2] ^ gf_mul13[c3];
    block[10] = gf_mul13[c0] ^ gf_mul9[c1]  ^ gf_mul14[c2] ^ gf_mul11[c3];
    block[11] = gf_mul11[c0] ^ gf_mul13[c1] ^ gf_mul9[c2]  ^ gf_mul14[c3];
    
    block[12] = gf_mul14[d0] ^ gf_mul11[d1] ^ gf_mul13[d2] ^ gf_mul9[d3];
    block[13] = gf_mul9[d0]  ^ gf_mul14[d1] ^ gf_mul11[d2] ^ gf_mul13[d3];
    block[14] = gf_mul13[d0] ^ gf_mul9[d1]  ^ gf_mul14[d2] ^ gf_mul11[d3];
    block[15] = gf_mul11[d0] ^ gf_mul13[d1] ^ gf_mul9[d2]  ^ gf_mul14[d3];
}

void round_mix(uint8_t *block) {
    mix_bytes(block);
}

void round_inv_mix(uint8_t *block) {
    inv_mix_bytes(block);
}