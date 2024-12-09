#ifndef LFSR_H
#define LFSR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#define LFSR_WIDTH 4

void lfsr_init(uint8_t seed);

uint8_t lfsr_next_bit();

void lfsr_encrypt(const uint8_t *plaintext, uint8_t *ciphertext, size_t length);

void lfsr_decrypt(const uint8_t *ciphertext, uint8_t *plaintext, size_t length);

void process_message(const char *message, uint8_t seed);

#ifdef __cplusplus
}
#endif

#endif // LFSR_H
