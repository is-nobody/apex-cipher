#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "keygen.h"

void keygen_expand(const uint8_t *master_key, size_t key_len,
                   uint8_t round_keys[ROUNDS][BLOCK_SIZE]) {
    uint8_t state = 0;
    for (int r = 0; r < ROUNDS; r++) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            state = SBOX[state ^ master_key[i % key_len] ^ (r * 7 + i * 13)];
            round_keys[r][i] = state ^ master_key[(i + r) % key_len] ^ (r * 0x1B);
        }
    }
}

void keygen_generate_iv(uint8_t iv[BLOCK_SIZE]) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        if (fread(iv, 1, BLOCK_SIZE, f) < BLOCK_SIZE) {
            for (int i = 0; i < BLOCK_SIZE; i++) {
                iv[i] = (uint8_t)(rand() ^ (i * 127));
            }
        }
        fclose(f);
    } else {
        srand(time(NULL));
        for (int i = 0; i < BLOCK_SIZE; i++) {
            iv[i] = (uint8_t)(rand() ^ (i * 127) ^ (clock() & 0xFF));
        }
    }
}

void keygen_random_key(uint8_t *key, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        if (fread(key, 1, len, f) < len) {
            for (size_t i = 0; i < len; i++) {
                key[i] = (uint8_t)(rand() ^ (i * 127) ^ (clock() & 0xFF));
            }
        }
        fclose(f);
    } else {
        srand(time(NULL));
        for (size_t i = 0; i < len; i++) {
            key[i] = (uint8_t)(rand() ^ (i * 127) ^ (clock() & 0xFF));
        }
    }
}