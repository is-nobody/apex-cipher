#include "crypto_context.h"
#include "keygen.h"
#include <string.h>

uint8_t default_key[DEFAULT_KEY_SIZE];

void crypto_init_default_key(void) {
    keygen_random_key(default_key, DEFAULT_KEY_SIZE);
}

void crypto_get_default_key(uint8_t key[DEFAULT_KEY_SIZE]) {
    memcpy(key, default_key, DEFAULT_KEY_SIZE);
}