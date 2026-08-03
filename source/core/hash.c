#include "hash.h"
#include "sbox.h"
#include <string.h>

#define HASH_ROUNDS 10

static void hash_mix(uint32_t *state) {
    uint8_t *bytes = (uint8_t*)state;
    
    bytes[0]  = SBOX[bytes[0]];   bytes[1]  = SBOX[bytes[1]];
    bytes[2]  = SBOX[bytes[2]];   bytes[3]  = SBOX[bytes[3]];
    bytes[4]  = SBOX[bytes[4]];   bytes[5]  = SBOX[bytes[5]];
    bytes[6]  = SBOX[bytes[6]];   bytes[7]  = SBOX[bytes[7]];
    bytes[8]  = SBOX[bytes[8]];   bytes[9]  = SBOX[bytes[9]];
    bytes[10] = SBOX[bytes[10]];  bytes[11] = SBOX[bytes[11]];
    bytes[12] = SBOX[bytes[12]];  bytes[13] = SBOX[bytes[13]];
    bytes[14] = SBOX[bytes[14]];  bytes[15] = SBOX[bytes[15]];
    bytes[16] = SBOX[bytes[16]];  bytes[17] = SBOX[bytes[17]];
    bytes[18] = SBOX[bytes[18]];  bytes[19] = SBOX[bytes[19]];
    bytes[20] = SBOX[bytes[20]];  bytes[21] = SBOX[bytes[21]];
    bytes[22] = SBOX[bytes[22]];  bytes[23] = SBOX[bytes[23]];
    bytes[24] = SBOX[bytes[24]];  bytes[25] = SBOX[bytes[25]];
    bytes[26] = SBOX[bytes[26]];  bytes[27] = SBOX[bytes[27]];
    bytes[28] = SBOX[bytes[28]];  bytes[29] = SBOX[bytes[29]];
    bytes[30] = SBOX[bytes[30]];  bytes[31] = SBOX[bytes[31]];
    
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