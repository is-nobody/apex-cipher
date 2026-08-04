#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "keygen.h"
#include "hmac.h"

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

#ifdef __linux__
#include <sys/random.h>
#include <errno.h>
#endif

static int secure_random(uint8_t *buf, size_t len) {
#ifdef _WIN32
    NTSTATUS status = BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (status == 0) ? 0 : -1;
#elif defined(__linux__)
    ssize_t result = getrandom(buf, len, 0);
    if (result == (ssize_t)len) return 0;
    
    if (result > 0) {
        size_t bytes_read = (size_t)result;
        FILE *f = fopen("/dev/urandom", "rb");
        if (!f) return -1;
        while (bytes_read < len) {
            size_t r = fread(buf + bytes_read, 1, len - bytes_read, f);
            if (r == 0) { fclose(f); return -1; }
            bytes_read += r;
        }
        fclose(f);
        return 0;
    }
    
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t bytes_read = 0;
    while (bytes_read < len) {
        size_t r = fread(buf + bytes_read, 1, len - bytes_read, f);
        if (r == 0) { fclose(f); return -1; }
        bytes_read += r;
    }
    fclose(f);
    return 0;
#else
    arc4random_buf(buf, len);
    return 0;
#endif
}

void keygen_expand(const uint8_t *master_key, size_t key_len,
                   const uint8_t *salt, size_t salt_len,
                   uint8_t round_keys[ROUNDS + 1][BLOCK_SIZE]) {
    
    uint8_t seed[32];
    uint8_t round_material[32];
    memset(seed, 0, sizeof(seed));
    
    memcpy(seed, salt, salt_len < 24 ? salt_len : 24);
    
    if (salt_len < 24) {
        for (size_t i = salt_len; i < 24; i++) {
            seed[i] = (uint8_t)(0xA0 + i);
        }
    }
    
    seed[24] = 0x52; // 'R'
    seed[25] = 0x4B; // 'K'
    seed[26] = 0x45; // 'E'
    seed[27] = 0x59; // 'Y'
    seed[28] = (uint8_t)(key_len & 0xFF);
    seed[29] = (uint8_t)((key_len >> 8) & 0xFF);
    seed[30] = 0x00; // reserved
    seed[31] = 0x00; // reserved
    
    for (int r = 0; r <= ROUNDS; r++) {
        uint8_t round_seed[32];
        memcpy(round_seed, seed, 32);
        
        round_seed[0] ^= (uint8_t)(r & 0xFF);
        round_seed[8] ^= (uint8_t)((r >> 8) & 0xFF);
        round_seed[16] ^= (uint8_t)(r & 0xFF);
        round_seed[24] ^= (uint8_t)((r >> 8) & 0xFF);
        
        hmac_compute(master_key, key_len, round_seed, 32, round_material);
        
        memcpy(round_keys[r], round_material, BLOCK_SIZE);
        
        for (int i = 0; i < BLOCK_SIZE; i++) {
            round_keys[r][i] = HASH_SBOX[round_keys[r][i] ^ round_material[16 + (i % 16)]];
        }
    }
    
    volatile uint8_t *vp = seed;
    for (size_t i = 0; i < sizeof(seed); i++) vp[i] = 0;
    vp = round_material;
    for (size_t i = 0; i < sizeof(round_material); i++) vp[i] = 0;
}

void keygen_generate_iv(uint8_t iv[BLOCK_SIZE]) {
    if (secure_random(iv, BLOCK_SIZE) != 0) {
        fprintf(stderr, "Failed to generate secure IV\n");
        abort();
    }
}

void keygen_random_key(uint8_t *key, size_t len) {
    if (secure_random(key, len) != 0) {
        fprintf(stderr, "Failed to generate secure key\n");
        abort();
    }
}