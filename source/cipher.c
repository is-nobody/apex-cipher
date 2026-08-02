#include <string.h>
#include "cipher.h"
#include "sbox.h"
#include "keygen.h"
#include "encrypt_decrypt.h"
#include "hmac.h"

static void secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

static int ct_memcmp(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff;
}

int cipher_encrypt(const uint8_t *data, size_t data_len,
                   const uint8_t *key, size_t key_len,
                   uint8_t *ciphertext, size_t *out_len) {
    sbox_init();
    
    if (data_len == 0 || data_len > MAX_TEXT) return -1;
    
    uint8_t round_keys[ROUNDS][BLOCK_SIZE];
    keygen_expand(key, key_len, round_keys);
    
    uint8_t iv[BLOCK_SIZE];
    keygen_generate_iv(iv);
    
    memcpy(ciphertext, iv, BLOCK_SIZE);
    size_t pos = BLOCK_SIZE;
    
    uint32_t data_size = (uint32_t)data_len;
    memcpy(ciphertext + pos, &data_size, sizeof(data_size));
    pos += sizeof(data_size);
    
    size_t padded_len = ((data_len + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE;
    size_t encrypt_start = pos;
    
    uint8_t prev[BLOCK_SIZE];
    memcpy(prev, iv, BLOCK_SIZE);
    
    uint8_t block[BLOCK_SIZE];

    for (size_t offset = 0; offset < padded_len; offset += BLOCK_SIZE) {
        uint8_t block[BLOCK_SIZE] = {0};
        size_t chunk = (offset + BLOCK_SIZE <= data_len) ? BLOCK_SIZE : (data_len - offset);
        memcpy(block, data + offset, chunk);
        
        for (int i = 0; i < BLOCK_SIZE; i++) {
            block[i] ^= prev[i];
        }
        
        encrypt_block(block, round_keys);
        memcpy(prev, block, BLOCK_SIZE);
        memcpy(ciphertext + pos, block, BLOCK_SIZE);
        pos += BLOCK_SIZE;
    }
    
    size_t ct_len = pos - encrypt_start;
    uint8_t mac[HMAC_SIZE];
    hmac_compute(key, key_len, ciphertext + encrypt_start, ct_len, mac);
    memcpy(ciphertext + pos, mac, HMAC_SIZE);
    pos += HMAC_SIZE;
    
    *out_len = pos;
    
    secure_zero(round_keys, sizeof(round_keys));
    secure_zero(prev, sizeof(prev));
    secure_zero(block, sizeof(block));
    
    return 0;
}

int cipher_decrypt(const uint8_t *ciphertext, size_t len,
                   const uint8_t *key, size_t key_len,
                   uint8_t *plaintext, size_t *out_len) {
    sbox_init();
    
    if (len < BLOCK_SIZE + sizeof(uint32_t) + BLOCK_SIZE + HMAC_SIZE) return -1;
    if (len > MAX_ENCRYPTED) return -1;
    
    uint32_t data_len;
    memcpy(&data_len, ciphertext + BLOCK_SIZE, sizeof(data_len));
    
    if (data_len == 0 || data_len > MAX_TEXT) return -1;
    
    size_t min_len = BLOCK_SIZE + sizeof(uint32_t) + 
                    ((data_len + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE + HMAC_SIZE;
    if (len < min_len) return -1;

    size_t actual_ct_len = len - BLOCK_SIZE - sizeof(uint32_t) - HMAC_SIZE;

    const uint8_t *enc_data = ciphertext + BLOCK_SIZE + sizeof(uint32_t);
    uint8_t computed_mac[HMAC_SIZE];
    hmac_compute(key, key_len, enc_data, actual_ct_len, computed_mac);
    
    const uint8_t *stored_mac = ciphertext + len - HMAC_SIZE;
    
    if (ct_memcmp(computed_mac, stored_mac, HMAC_SIZE) != 0) {
        return -2;
    }
    
    uint8_t iv[BLOCK_SIZE];
    memcpy(iv, ciphertext, BLOCK_SIZE);
    
    uint8_t round_keys[ROUNDS][BLOCK_SIZE];
    keygen_expand(key, key_len, round_keys);
    
    uint8_t prev[BLOCK_SIZE];
    memcpy(prev, iv, BLOCK_SIZE);
    
    uint8_t decrypted[BLOCK_SIZE];

    *out_len = 0;
    
    for (size_t offset = 0; offset < actual_ct_len && *out_len < data_len; offset += BLOCK_SIZE) {
        uint8_t decrypted[BLOCK_SIZE];
        memcpy(decrypted, enc_data + offset, BLOCK_SIZE);
        
        decrypt_block(decrypted, round_keys);
        
        for (int i = 0; i < BLOCK_SIZE; i++) {
            decrypted[i] ^= prev[i];
        }
        
        memcpy(prev, enc_data + offset, BLOCK_SIZE);
        
        size_t to_copy = (data_len - *out_len < BLOCK_SIZE) ? (data_len - *out_len) : BLOCK_SIZE;
        memcpy(plaintext + *out_len, decrypted, to_copy);
        *out_len += to_copy;
    }
    
    secure_zero(round_keys, sizeof(round_keys));
    secure_zero(prev, sizeof(prev));
    secure_zero(computed_mac, sizeof(computed_mac));
    if (*out_len == data_len) {
        secure_zero(decrypted, sizeof(decrypted));
    }
    
    return (*out_len == data_len) ? 0 : -1;
}