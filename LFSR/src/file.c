#include "file.h"
#include "lfsr.h"
#include <stdio.h>

#define BUFFER_SIZE 1024

static int process_file(const char *input_file, const char *output_file,
                        uint8_t seed, int is_encrypt) {
  FILE *input = fopen(input_file, "rb");
  if (!input) {
    perror("Failed to open input file");
    return -1;
  }

  FILE *output = fopen(output_file, "wb");
  if (!output) {
    perror("Failed to open output file");
    fclose(input);
    return -1;
  }

  lfsr_init(seed);

  uint8_t buffer[BUFFER_SIZE];
  uint8_t processed_buffer[BUFFER_SIZE];
  size_t bytes_read;

  while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, input)) > 0) {
    if (is_encrypt) {
      lfsr_encrypt(buffer, processed_buffer, bytes_read);
    } else {
      lfsr_decrypt(buffer, processed_buffer, bytes_read);
    }
    fwrite(processed_buffer, 1, bytes_read, output);
  }

  fclose(input);
  fclose(output);

  return 0;
}

int encrypt_file(const char *input_file, const char *output_file,
                 uint8_t seed) {
  return process_file(input_file, output_file, seed, 1);
}

int decrypt_file(const char *input_file, const char *output_file,
                 uint8_t seed) {
  return process_file(input_file, output_file, seed, 0);
}

bool compare_files(const char *file1, const char *file2) {
  FILE *fp1 = fopen(file1, "rb");
  FILE *fp2 = fopen(file2, "rb");

  if (!fp1 || !fp2) {
    printf("Failed to open one of the files for comparison.\n");
    if (fp1)
      fclose(fp1);
    if (fp2)
      fclose(fp2);
    return false;
  }

  bool result = true;
  int ch1, ch2;
  do {
    ch1 = fgetc(fp1);
    ch2 = fgetc(fp2);
    if (ch1 != ch2) {
      result = false;
      break;
    }
  } while (ch1 != EOF && ch2 != EOF);
  if (ch1 != ch2) {
    result = false;
  }

  fclose(fp1);
  fclose(fp2);

  return result;
}

int process_files(const char *input_file, const char *encrypted_file,
                  const char *decrypted_file, uint8_t seed) {
  int result = 0;

  printf("Encrypting file...\n");
  if (encrypt_file(input_file, encrypted_file, seed) != 0) {
    printf("File encryption failed.\n");
    result = -1;
  } else {
    printf("File encrypted successfully! Output: %s\n", encrypted_file);
  }

  if (result == 0) {
    printf("Decrypting file...\n");
    if (decrypt_file(encrypted_file, decrypted_file, seed) != 0) {
      printf("File decryption failed.\n");
      result = -1;
    } else {
      printf("File decrypted successfully! Output: %s\n", decrypted_file);

      if (compare_files(input_file, decrypted_file)) {
        printf("The contents of the input and decrypted files match.\n");
      } else {
        printf("Warning: The contents of the input and decrypted files do not "
               "match.\n");
        result = -1;
      }
    }
  }

  return result;
}