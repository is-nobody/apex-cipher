// main.c
#include <stdio.h>
#include <string.h>
#include "repl.h"
#include "args.h"
#include "crypto_context.h"

#define COLOR_RED "\033[1;31m"
#define COLOR_RESET "\033[0m"

int main(int argc, char *argv[]) {
    crypto_init_default_key();
    
    if (argc == 1) {
        repl_run();
        return 0;
    }
    
    const char *command = argv[1];
    
    if (strcmp(command, "decode") == 0) {
        if (argc == 2) {
            printf(COLOR_RED "Error: File and Key required for decryption\n" COLOR_RESET);
        } else if (argc == 3) {
            printf(COLOR_RED "Error: Key required for decryption\n" COLOR_RESET);
        } else {
            return args_decrypt_file(argv[2], argv[3]);
        }
        return 1;
    }
    
    if (strcmp(command, "encode") == 0) {
        if (argc == 2) {
            printf(COLOR_RED "Error: File required for encryption\n" COLOR_RESET);
        } else {
            const char *key = (argc > 3) ? argv[3] : NULL;
            return args_encrypt_file(argv[2], key);
        }
        return 1;
    }
    
    printf(COLOR_RED "Error: Unknown command '%s'\n" COLOR_RESET, command);
    print_usage(argv[0]);
    
    return 1;
}