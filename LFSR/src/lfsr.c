#include "lfsr.h"
#include <stdio.h>
#include <string.h>

static uint8_t lfsr_state = 0;

#define FEEDBACK_MASK 0b10011 // 本原多项式：g(x) = x^4 + x + 1

void lfsr_init(uint8_t seed) {
  if (seed == 0) {
    seed = 1;
  }
  lfsr_state = seed & ((1 << LFSR_WIDTH) - 1); 
}

uint8_t lfsr_next_bit() {
  uint8_t output = lfsr_state & 1;

  uint8_t feedback = (lfsr_state & FEEDBACK_MASK) ^ ((lfsr_state >> 1) & 1);
  feedback = feedback & 1;

  lfsr_state = (lfsr_state >> 1) | (feedback << (LFSR_WIDTH - 1));

  return output;
}

void lfsr_encrypt(const uint8_t *plaintext, uint8_t *ciphertext,
                  size_t length) {
  for (size_t i = 0; i < length; i++) {
    ciphertext[i] = plaintext[i];
    for (int bit = 0; bit < 8; bit++) {
      uint8_t key_bit = lfsr_next_bit();
      ciphertext[i] ^= (key_bit << bit);
    }
  }
}

void lfsr_decrypt(const uint8_t *ciphertext, uint8_t *plaintext,
                  size_t length) {
  lfsr_encrypt(ciphertext, plaintext, length);
}

void process_message(const char *message, uint8_t seed) {
  size_t length = strlen(message);
  uint8_t encrypted[length], decrypted[length];

  lfsr_init(seed);
  lfsr_encrypt((const uint8_t *)message, encrypted, length);
  printf("Encrypted message: ");
  for (size_t i = 0; i < length; i++) {
    printf("%02X ", encrypted[i]);
  }
  printf("\n");

  lfsr_init(seed);
  lfsr_decrypt(encrypted, decrypted, length);
  printf("Decrypted message: ");
  for (size_t i = 0; i < length; i++) {
    printf("%c", decrypted[i]);
  }
  printf("\n");
}