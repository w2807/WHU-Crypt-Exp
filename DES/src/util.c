#include "util.h"
#include "config.h"
#include <stdint.h>

inline uint64_t initial_permutation(uint64_t input) {

  uint64_t output = 0;

  for (int i = 0; i < 64; i++) {
    output |= ((input >> (64 - IP[i])) & 1) << (63 - i);
  }

  return output;
}

inline uint64_t inverse_permutation(uint64_t input) {

  uint64_t output = 0;

  for (int i = 0; i < 64; i++) {
    output |= ((input >> (64 - IP_INV[i])) & 1) << (63 - i);
  }

  return output;
}

inline uint64_t e_box(uint32_t input) {

  uint64_t output = 0;

  for (int i = 0; i < 48; i++) {
    output |= ((uint64_t)((input >> (32 - E[i])) & 1)) << (47 - i);
  }

  return output;
}

inline uint32_t p_box(uint32_t input) {

  uint32_t output = 0;

  for (int i = 0; i < 32; i++) {
    output |= ((input >> (32 - P[i])) & 1) << (31 - i);
  }

  return output;
}

inline uint32_t sBox(uint64_t input) {
  uint32_t output = 0;
  for (int i = 0; i < 8; i++) {
    uint8_t six_bits = (input >> (42 - 6 * i)) & 0x3F;
    uint8_t row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01);
    uint8_t col = (six_bits & 0x1E) >> 1;
    uint8_t sBoxVal = SBox[i][row][col];
    output = (output << 4) | sBoxVal;
  }
  return output;
}

inline uint32_t feistel(uint32_t half_block, uint64_t subkey) {

  uint64_t expanded_half = e_box(half_block);

  uint64_t xored = expanded_half ^ subkey;

  uint32_t substituted = sBox(xored);

  return p_box(substituted);
}

inline uint64_t permuted_choice_1(uint64_t key) {

  uint64_t output = 0;

  for (int i = 0; i < 56; i++) {
    output |= ((key >> (64 - PC1[i])) & 1) << (55 - i);
  }

  return output;
}

inline uint64_t permuted_choice_2(uint64_t key) {

  uint64_t output = 0;

  for (int i = 0; i < 48; i++) {
    output |= ((key >> (56 - PC2[i])) & 1) << (47 - i);
  }

  return output;
}

inline uint64_t read_subkey(const unsigned char subKeys[16][6], int round) {
  uint64_t subKey = 0;
  for (int byte = 0; byte < 6; ++byte) {
    subKey = (subKey << 8) | subKeys[round][byte];
  }
  return subKey;
}