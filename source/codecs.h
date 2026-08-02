#ifndef CODECS_H
#define CODECS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

void base64_encode(const uint8_t* data, size_t len, char* out);
bool base64_decode(const char* str, uint8_t* out, size_t* out_len);
void base64url_encode(const uint8_t* data, size_t len, char* out);
bool base64url_decode(const char* str, uint8_t* out, size_t* out_len);

#endif