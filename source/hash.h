#ifndef HASH_H
#define HASH_H

#include <stdint.h>
#include <stddef.h>

#define HASH_BLOCK_SIZE 64
#define HASH_DIGEST_SIZE 32

typedef struct {
    uint8_t buffer[HASH_BLOCK_SIZE];
    uint32_t state[8];
    uint64_t count;
} HASH_CTX;

void hash_init(HASH_CTX *ctx);
void hash_update(HASH_CTX *ctx, const uint8_t *data, size_t len);
void hash_final(HASH_CTX *ctx, uint8_t digest[HASH_DIGEST_SIZE]);

#endif