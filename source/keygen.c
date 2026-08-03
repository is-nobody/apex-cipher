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
                   uint8_t round_keys[ROUNDS][BLOCK_SIZE]) {
    uint8_t seed[32];
    memset(seed, 0, sizeof(seed));
    
    for (int r = 0; r < ROUNDS; r++) {
        seed[0] = (uint8_t)(r & 0xFF);
        seed[1] = (uint8_t)((r >> 8) & 0xFF);
        seed[2] = 0x52;
        seed[3] = 0x4B;
        
        seed[4] = (uint8_t)(key_len & 0xFF);
        seed[5] = (uint8_t)((key_len >> 8) & 0xFF);
        
        uint8_t round_material[32];
        hmac_compute(master_key, key_len, seed, 6, round_material);
        
        memcpy(round_keys[r], round_material, BLOCK_SIZE);
        
        for (int i = 0; i < BLOCK_SIZE; i++) {
            round_keys[r][i] = SBOX[round_keys[r][i] ^ round_material[16 + (i % 16)]];
        }
    }
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