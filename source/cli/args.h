// source/cli/args.h
#ifndef ARGS_H
#define ARGS_H

int args_encrypt_file(const char *filename, const char *key_str);
int args_decrypt_file(const char *filename, const char *key_str);
void print_usage(const char *program_name);

#endif