#include "hash.h"
#include "sbox.h"
#include <string.h>

#define HASH_ROUNDS 10

static void hash_mix(uint32_t *state) {
    uint8_t *bytes = (uint8_t*)state;
    
    for (int i = 0; i < 32; i++) {
        bytes[i] = SBOX[bytes[i]];
    }
    
    for (int r = 0; r < HASH_ROUNDS; r++) {
        uint32_t temp[8];
        
        for (int i = 0; i < 8; i++) {
            temp[i] = state[i] ^ 
                      ((state[(i + 1) % 8] >> 7) | (state[(i + 1) % 8] << 25)) ^
                      ((state[(i + 3) % 8] >> 13) | (state[(i + 3) % 8] << 19));
            temp[i] += state[(i + 5) % 8];
            temp[i] ^= (state[(i + 7) % 8] << 11) | (state[(i + 7) % 8] >> 21);
        }
        
        memcpy(state, temp, 32);
    }
}

static void hash_compress(HASH_CTX *ctx, const uint8_t *block) {
    uint32_t W[8];
    uint32_t old_state[8];
    
    memcpy(old_state, ctx->state, 32);
    
    for (int i = 0; i < 8; i++) {
        W[i] = ((uint32_t)block[i * 8]     << 24) |
               ((uint32_t)block[i * 8 + 1] << 16) |
               ((uint32_t)block[i * 8 + 2] << 8)  |
               ((uint32_t)block[i * 8 + 3])       |
               ((uint32_t)block[i * 8 + 4] << 24) |
               ((uint32_t)block[i * 8 + 5] << 16) |
               ((uint32_t)block[i * 8 + 6] << 8)  |
               ((uint32_t)block[i * 8 + 7]);
    }
    
    for (int i = 0; i < 8; i++) {
        ctx->state[i] ^= W[i];
    }
    
    hash_mix(ctx->state);
    
    for (int i = 0; i < 8; i++) {
        ctx->state[i] += old_state[i];
    }
}

void hash_init(HASH_CTX *ctx) {
    ctx->count = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x9b05688c;
    ctx->state[5] = 0x1f83d9ab;
    ctx->state[6] = 0x5be0cd19;
    ctx->state[7] = 0xcbbb9d5d;
}

void hash_update(HASH_CTX *ctx, const uint8_t *data, size_t len) {
    size_t i = 0;
    
    while (i < len) {
        size_t buffer_index = (size_t)(ctx->count % HASH_BLOCK_SIZE);
        size_t space = HASH_BLOCK_SIZE - buffer_index;
        size_t chunk = (len - i < space) ? len - i : space;
        
        memcpy(ctx->buffer + buffer_index, data + i, chunk);
        ctx->count += chunk;
        i += chunk;
        
        if (ctx->count % HASH_BLOCK_SIZE == 0) {
            hash_compress(ctx, ctx->buffer);
        }
    }
}

void hash_final(HASH_CTX *ctx, uint8_t digest[HASH_DIGEST_SIZE]) {
    size_t buffer_index = (size_t)(ctx->count % HASH_BLOCK_SIZE);
    
    ctx->buffer[buffer_index++] = 0x80;
    
    if (buffer_index > 56) {
        memset(ctx->buffer + buffer_index, 0, HASH_BLOCK_SIZE - buffer_index);
        hash_compress(ctx, ctx->buffer);
        buffer_index = 0;
    }
    
    memset(ctx->buffer + buffer_index, 0, 56 - buffer_index);
    
    uint64_t bits = ctx->count * 8;
    for (int i = 7; i >= 0; i--) {
        ctx->buffer[56 + i] = (uint8_t)(bits & 0xFF);
        bits >>= 8;
    }
    
    hash_compress(ctx, ctx->buffer);
    
    for (int i = 0; i < 8; i++) {
        digest[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}