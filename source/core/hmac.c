#include "hmac.h"
#include "hash.h"
#include <string.h>

void hmac_compute(const uint8_t *key, size_t key_len,
                  const uint8_t *data, size_t data_len,
                  uint8_t digest[HMAC_SIZE]) {
    
    uint8_t key_block[HMAC_BLOCK_SIZE];
    uint8_t ipad[HMAC_BLOCK_SIZE];
    uint8_t opad[HMAC_BLOCK_SIZE];
    HASH_CTX ctx;
    uint8_t inner_hash[HASH_DIGEST_SIZE];
    
    if (key_len > HMAC_BLOCK_SIZE) {
        hash_init(&ctx);
        hash_update(&ctx, key, key_len);
        hash_final(&ctx, key_block);
        memset(key_block + HASH_DIGEST_SIZE, 0, HMAC_BLOCK_SIZE - HASH_DIGEST_SIZE);
    } else {
        memcpy(key_block, key, key_len);
        if (key_len < HMAC_BLOCK_SIZE) {
            memset(key_block + key_len, 0, HMAC_BLOCK_SIZE - key_len);
        }
    }
    
    for (int i = 0; i < HMAC_BLOCK_SIZE; i++) {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }
    
    hash_init(&ctx);
    hash_update(&ctx, ipad, HMAC_BLOCK_SIZE);
    hash_update(&ctx, data, data_len);
    hash_final(&ctx, inner_hash);
    
    hash_init(&ctx);
    hash_update(&ctx, opad, HMAC_BLOCK_SIZE);
    hash_update(&ctx, inner_hash, HASH_DIGEST_SIZE);
    hash_final(&ctx, digest);
}