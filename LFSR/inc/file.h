#ifndef FILE_H
#define FILE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

int encrypt_file(const char *input_file, const char *output_file, uint8_t seed);

int decrypt_file(const char *input_file, const char *output_file, uint8_t seed);

bool compare_files(const char *file1, const char *file2);

int process_files(const char *input_file, const char *encrypted_file,
                  const char *decrypted_file, uint8_t seed);

#endif // FILE_H
