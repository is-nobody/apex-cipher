#ifndef CRYPTO_CONTEXT_H
#define CRYPTO_CONTEXT_H

#include <stdint.h>
#include <stddef.h>

#define MAX_TEXT 16384
#define DEFAULT_KEY_SIZE 32

extern uint8_t default_key[DEFAULT_KEY_SIZE];

void crypto_init_default_key(void);
void crypto_get_default_key(uint8_t key[DEFAULT_KEY_SIZE]);

#endif