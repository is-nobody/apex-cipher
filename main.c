// main.c
#include <stdio.h>
#include <string.h>
#include "args.h"
#include "crypto_context.h"

#define COLOR_RED "\033[1;31m"
#define COLOR_RESET "\033[0m"

int main(int argc, char *argv[]) {
    crypto_init_default_key();
    
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char *command = argv[1];
    
    if (strcmp(command, "decode") == 0) {
        if (argc != 4) {
            printf(COLOR_RED "Error: decode requires file and key\n" COLOR_RESET);
            print_usage(argv[0]);
            return 1;
        }
        return args_decrypt_file(argv[2], argv[3]);
    }
    
    if (strcmp(command, "encode") == 0) {
        if (argc < 3) {
            printf(COLOR_RED "Error: encode requires at least file\n" COLOR_RESET);
            print_usage(argv[0]);
            return 1;
        }
        const char *key = (argc > 3) ? argv[3] : NULL;
        return args_encrypt_file(argv[2], key);
    }
    
    printf(COLOR_RED "Error: Unknown command '%s'\n" COLOR_RESET, command);
    print_usage(argv[0]);
    
    return 1;
}