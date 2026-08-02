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
        size_t bytes_read = fread(iv, 1, BLOCK_SIZE, f);
        fclose(f);
        
        if (bytes_read < BLOCK_SIZE) {
            for (size_t i = bytes_read; i < BLOCK_SIZE; i++) {
                iv[i] = (uint8_t)(rand() ^ (i * 127));
            }
        }
    } else {
        srand(time(NULL));
        for (int i = 0; i < BLOCK_SIZE; i++) {
            iv[i] = (uint8_t)(rand() ^ (i * 127) ^ (clock() & 0xFF));
        }
    }
}