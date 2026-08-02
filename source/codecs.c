#include "codecs.h"
#include <string.h>
#include <stdlib.h>

static const char b64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
static const char b64url_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=";

void base64_encode(const uint8_t* data, size_t len, char* out) {
    size_t i = 0, j = 0;
    uint32_t buffer = 0;
    int bits_left = 0;
    
    while (i < len) {
        buffer = (buffer << 8) | data[i++];
        bits_left += 8;
        while (bits_left >= 6) {
            out[j++] = b64_chars[(buffer >> (bits_left - 6)) & 0x3F];
            bits_left -= 6;
        }
    }
    
    if (bits_left > 0) {
        out[j++] = b64_chars[(buffer << (6 - bits_left)) & 0x3F];
    }
    
    while (j % 4 != 0) {
        out[j++] = '=';
    }
    out[j] = '\0';
}

static int base64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    if (c == '=') return 0;
    return -1;
}

bool base64_decode(const char* str, uint8_t* out, size_t* out_len) {
    size_t len = strlen(str);
    if (len == 0) { *out_len = 0; return true; }
    
    for (size_t i = 0; i < len; i++) {
        if (str[i] != '=' && base64_decode_char(str[i]) < 0) return false;
    }
    
    uint32_t buffer = 0;
    int bits_left = 0;
    *out_len = 0;
    int padding = 0;
    
    for (size_t i = 0; i < len; i++) {
        if (str[i] == '=') {
            padding++;
            continue;
        }
        
        buffer = (buffer << 6) | base64_decode_char(str[i]);
        bits_left += 6;
        
        if (bits_left >= 8) {
            out[(*out_len)++] = (uint8_t)(buffer >> (bits_left - 8));
            bits_left -= 8;
        }
    }
    
    return true;
}

void base64url_encode(const uint8_t* data, size_t len, char* out) {
    size_t i = 0, j = 0;
    uint32_t buffer = 0;
    int bits_left = 0;
    
    while (i < len) {
        buffer = (buffer << 8) | data[i++];
        bits_left += 8;
        while (bits_left >= 6) {
            out[j++] = b64url_chars[(buffer >> (bits_left - 6)) & 0x3F];
            bits_left -= 6;
        }
    }
    
    if (bits_left > 0) {
        out[j++] = b64url_chars[(buffer << (6 - bits_left)) & 0x3F];
    }
    
    out[j] = '\0';
}

static int base64url_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    if (c == '=') return 0;
    return -1;
}

bool base64url_decode(const char* str, uint8_t* out, size_t* out_len) {
    size_t len = strlen(str);
    if (len == 0) { *out_len = 0; return true; }
    
    uint32_t buffer = 0;
    int bits_left = 0;
    *out_len = 0;
    
    for (size_t i = 0; i < len; i++) {
        if (str[i] == '=') break;
        int val = base64url_decode_char(str[i]);
        if (val < 0) return false;
        
        buffer = (buffer << 6) | val;
        bits_left += 6;
        
        if (bits_left >= 8) {
            out[(*out_len)++] = (uint8_t)(buffer >> (bits_left - 8));
            bits_left -= 8;
        }
    }
    return true;
}