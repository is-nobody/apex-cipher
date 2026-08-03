#ifndef KDF_H
#define KDF_H

#include <stdint.h>
#include <stddef.h>

#define KDF_SALT_SIZE 16
#define KDF_ITERATIONS 25000
#define KDF_DERIVED_KEY_SIZE 32

void kdf_derive(const uint8_t *password, size_t password_len,
                const uint8_t *salt, size_t salt_len,
                uint32_t iterations,
                uint8_t *derived_key, size_t key_len);

#endif