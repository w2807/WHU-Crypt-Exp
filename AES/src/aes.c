#include "aes.h"
#include <stdint.h>
#include <wmmintrin.h>

static __m128i KEY[11];

int aes_make_enc_subkeys(const unsigned char key[16],
                         unsigned char subKeys[11][16]) {
  if (!key || !subKeys)
    return 1;

  KEY[0] = _mm_loadu_si128((const __m128i *)key);

  AES_EXPAND_KEYS(KEY);

  for (int i = 0; i < 11; i++) {
    _mm_storeu_si128((__m128i *)subKeys[i], KEY[i]);
  }
  return 0;
}

int aes_make_dec_subkeys(const unsigned char key[16],
                         unsigned char subKeys[11][16]) {
  __m128i DECRYPT_KEY[11];

  KEY[0] = _mm_loadu_si128((const __m128i *)key);

  DECRYPT_KEY[0] = KEY[10];
  DECRYPT_KEY[10] = KEY[0];

  for (int i = 1; i < 10; i++) {
    DECRYPT_KEY[i] = _mm_aesimc_si128(KEY[10 - i]);
  }

  for (int i = 0; i < 11; i++) {
    _mm_storeu_si128((__m128i *)subKeys[i], DECRYPT_KEY[i]);
  }

  return 0;
}

void aes_encrypt_block(const unsigned char *input,
                       unsigned char subKeys[11][16], unsigned char *output) {
  __m128i block = _mm_loadu_si128((const __m128i *)input);

  block = _mm_xor_si128(block, _mm_loadu_si128((const __m128i *)subKeys[0]));

  for (int i = 1; i < 10; i++) {
    block =
        _mm_aesenc_si128(block, _mm_loadu_si128((const __m128i *)subKeys[i]));
  }

  block = _mm_aesenclast_si128(block,
                               _mm_loadu_si128((const __m128i *)subKeys[10]));

  _mm_storeu_si128((__m128i *)output, block);
}

void aes_decrypt_block(const unsigned char *input,
                       unsigned char subKeys[11][16], unsigned char *output) {
  __m128i block = _mm_loadu_si128((const __m128i *)input);

  block = _mm_xor_si128(block, _mm_loadu_si128((const __m128i *)subKeys[0]));

  for (int i = 1; i < 10; i++) {
    block =
        _mm_aesdec_si128(block, _mm_loadu_si128((const __m128i *)subKeys[i]));
  }

  block =
      _mm_aesdeclast_si128(block, _mm_loadu_si128((const __m128i *)subKeys[10]));

  _mm_storeu_si128((__m128i *)output, block);
}