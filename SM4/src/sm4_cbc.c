#include "sm4.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void generate_iv(unsigned char iv[SM4_BLOCK_SIZE]) {
  for (int i = 0; i < SM4_BLOCK_SIZE; i++) {
    iv[i] = rand() % 256;
  }
}

unsigned char *read_file(const char *filename, size_t *file_size) {
  FILE *file = fopen(filename, "rb");
  if (!file) {
    perror("Failed to open file");
    exit(EXIT_FAILURE);
  }

  fseek(file, 0, SEEK_END);
  *file_size = ftell(file);
  fseek(file, 0, SEEK_SET);

  unsigned char *data = malloc(*file_size);
  if (!data) {
    perror("Memory allocation failed");
    fclose(file);
    exit(EXIT_FAILURE);
  }

  fread(data, 1, *file_size, file);
  fclose(file);
  return data;
}

void sm4_cbc_encrypt(const unsigned char *input, size_t length,
                     unsigned char *output,
                     const unsigned char key[SM4_KEY_SIZE],
                     unsigned char iv[SM4_BLOCK_SIZE]) {
  uint32_t encSubKeys[SM4_ROUNDS];
  sm4_make_enc_subkeys(key, encSubKeys);

  unsigned char xor_block[SM4_BLOCK_SIZE];
  memcpy(xor_block, iv, SM4_BLOCK_SIZE);

  for (size_t i = 0; i < length; i += SM4_BLOCK_SIZE) {
    for (int j = 0; j < SM4_BLOCK_SIZE; j++) {
      xor_block[j] ^= input[i + j];
    }
    sm4_encrypt_block(xor_block, encSubKeys, output + i);
    memcpy(xor_block, output + i, SM4_BLOCK_SIZE);
  }
}

void sm4_cbc_decrypt(const unsigned char *input, size_t length,
                     unsigned char *output,
                     const unsigned char key[SM4_KEY_SIZE],
                     unsigned char iv[SM4_BLOCK_SIZE]) {
  uint32_t decSubKeys[SM4_ROUNDS];
  sm4_make_dec_subkeys(key, decSubKeys);

  unsigned char xor_block[SM4_BLOCK_SIZE];
  unsigned char temp_block[SM4_BLOCK_SIZE];
  memcpy(xor_block, iv, SM4_BLOCK_SIZE);

  for (size_t i = 0; i < length; i += SM4_BLOCK_SIZE) {
    memcpy(temp_block, input + i, SM4_BLOCK_SIZE);
    sm4_decrypt_block(input + i, decSubKeys, output + i);
    for (int j = 0; j < SM4_BLOCK_SIZE; j++) {
      output[i + j] ^= xor_block[j];
    }
    memcpy(xor_block, temp_block, SM4_BLOCK_SIZE);
  }
}

void test_performance(const char *filename) {
  unsigned char key[SM4_KEY_SIZE];
  unsigned char iv[SM4_BLOCK_SIZE];
  size_t data_size;
  unsigned char *input = read_file(filename, &data_size);
  unsigned char *output = malloc(data_size);
  unsigned char *decrypted = malloc(data_size);

  if (!output || !decrypted) {
    perror("Memory allocation failed");
    free(input);
    exit(EXIT_FAILURE);
  }

  for (int i = 0; i < SM4_KEY_SIZE; i++)
    key[i] = rand() % 256;
  generate_iv(iv);

  printf("Testing with file: %s (Size: %zu Bytes)\n", filename, data_size);

  clock_t start = clock();
  sm4_cbc_encrypt(input, data_size, output, key, iv);
  clock_t end = clock();
  printf("Encryption Time: %.2f ms\n",
         (double)(end - start) / CLOCKS_PER_SEC * 1000);

  start = clock();
  sm4_cbc_decrypt(output, data_size, decrypted, key, iv);
  end = clock();
  printf("Decryption Time: %.2f ms\n",
         (double)(end - start) / CLOCKS_PER_SEC * 1000);

  if (memcmp(input, decrypted, data_size) == 0) {
    printf("Decryption Verified!\n");
  } else {
    printf("Decryption Failed!\n");
  }

  free(input);
  free(output);
  free(decrypted);
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("Usage: %s <file1> [file2 ...]\n", argv[0]);
    return EXIT_FAILURE;
  }

  srand(time(NULL));

  for (int i = 1; i < argc; i++) {
    test_performance(argv[i]);
  }

  return 0;
}