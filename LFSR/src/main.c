#include "lfsr.h"
#include "file.h"
#include <stdio.h>

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr,
            "Usage: %s <input_file> <encrypted_file> <decrypted_file>\n",
            argv[0]);
    return -1;
  }

  const char *input_file = argv[1];
  const char *encrypted_file = argv[2];
  const char *decrypted_file = argv[3];
  uint8_t seed = 0b1011;

  process_message("HELLO LFSR", seed);

  if (process_files(input_file, encrypted_file, decrypted_file, seed) != 0) {
    return -1;
  }

  return 0;
}