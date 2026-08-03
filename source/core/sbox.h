#ifndef SBOX_H
#define SBOX_H

#include <stdint.h>

#define BLOCK_SIZE 16

extern const uint8_t SBOX[256];
extern uint8_t INV_SBOX[256];

void sbox_init(void);

#endif