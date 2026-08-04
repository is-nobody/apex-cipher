#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "keygen.h"
#include "hmac.h"
#include "cipher_ops.h"

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

#ifdef __linux__
#include <sys/random.h>
#include <errno.h>
#endif

static const uint8_t Rcon[15] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D
};

static uint32_t SubWord(uint32_t word) {
    return ((uint32_t)SBOX[(word >> 24) & 0xFF] << 24) |
           ((uint32_t)SBOX[(word >> 16) & 0xFF] << 16) |
           ((uint32_t)SBOX[(word >> 8) & 0xFF] << 8)  |
           ((uint32_t)SBOX[word & 0xFF]);
}

static uint32_t RotWord(uint32_t word) {
    return (word << 8) | (word >> 24);
}

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
                   uint8_t round_keys[ROUNDS + 1][BLOCK_SIZE]) {
    
    uint8_t key256[32];
    
    if (key_len >= 32) {
        memcpy(key256, master_key, 32);
    } else {
        uint8_t salt[] = "apex-key-expansion-salt-v1";
        hmac_compute(master_key, key_len, salt, sizeof(salt) - 1, key256);
    }
    
    uint32_t W[NB * (NR + 1)];
    uint32_t temp;
    
    for (int i = 0; i < 8; i++) {
        W[i] = ((uint32_t)key256[4*i]   << 24) |
               ((uint32_t)key256[4*i+1] << 16) |
               ((uint32_t)key256[4*i+2] << 8)  |
               ((uint32_t)key256[4*i+3]);
    }
    
    for (int i = 8; i < NB * (NR + 1); i++) {
        temp = W[i - 1];
        if (i % 8 == 0) {
            temp = SubWord(RotWord(temp)) ^ ((uint32_t)Rcon[i/8] << 24);
        } else if (i % 8 == 4) {
            temp = SubWord(temp);
        }
        W[i] = W[i - 8] ^ temp;
    }
    
    for (int r = 0; r <= NR; r++) {
        for (int j = 0; j < 4; j++) {
            uint32_t word = W[r * 4 + j];
            round_keys[r][j*4]   = (uint8_t)(word >> 24);
            round_keys[r][j*4+1] = (uint8_t)(word >> 16);
            round_keys[r][j*4+2] = (uint8_t)(word >> 8);
            round_keys[r][j*4+3] = (uint8_t)(word);
        }
    }
    
    volatile uint32_t *vp = W;
    for (int i = 0; i < NB * (NR + 1); i++) vp[i] = 0;
    
    cipher_secure_zero(key256, sizeof(key256));
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