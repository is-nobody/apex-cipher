#include "kdf.h"
#include "hmac.h"
#include <string.h>

int kdf_derive(const uint8_t *password, size_t password_len,
                const uint8_t *salt, size_t salt_len,
                uint32_t iterations,
                uint8_t *derived_key, size_t key_len) {
    
    if (!password || !salt || !derived_key || key_len == 0) {
        return -1;
    }
    
    uint8_t block[HMAC_SIZE];
    uint8_t u[HMAC_SIZE];
    uint32_t blocks_needed = (key_len + HMAC_SIZE - 1) / HMAC_SIZE;
    
    for (uint32_t block_num = 1; block_num <= blocks_needed; block_num++) {
        uint8_t salt_block[128];
        size_t salt_block_len = 0;
        
        memcpy(salt_block, salt, salt_len);
        salt_block_len += salt_len;
        
        salt_block[salt_block_len++] = (uint8_t)(block_num >> 24);
        salt_block[salt_block_len++] = (uint8_t)(block_num >> 16);
        salt_block[salt_block_len++] = (uint8_t)(block_num >> 8);
        salt_block[salt_block_len++] = (uint8_t)(block_num);
        
        hmac_compute(password, password_len, salt_block, salt_block_len, u);
        memcpy(block, u, HMAC_SIZE);
        
        for (uint32_t i = 1; i < iterations; i++) {
            hmac_compute(password, password_len, u, HMAC_SIZE, u);
            for (size_t j = 0; j < HMAC_SIZE; j++) {
                block[j] ^= u[j];
            }
        }
        
        size_t copy_len = (block_num == blocks_needed && key_len % HMAC_SIZE != 0) 
                          ? key_len % HMAC_SIZE 
                          : HMAC_SIZE;
        memcpy(derived_key + (block_num - 1) * HMAC_SIZE, block, copy_len);
    }
    
    return 0;
}