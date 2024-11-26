#ifndef AES_H
#define AES_H

#ifdef __cplusplus
extern "C" {
#endif

#define AES_KEY_EXPAND_STEP(KEY, ROUND, RCON)                                  \
  do {                                                                         \
    __m128i temp = _mm_aeskeygenassist_si128(KEY[ROUND - 1], RCON);            \
    temp = _mm_shuffle_epi32(temp, _MM_SHUFFLE(3, 3, 3, 3));                   \
    KEY[ROUND] =                                                               \
        _mm_xor_si128(KEY[ROUND - 1], _mm_slli_si128(KEY[ROUND - 1], 4));      \
    KEY[ROUND] = _mm_xor_si128(KEY[ROUND], _mm_slli_si128(KEY[ROUND], 4));     \
    KEY[ROUND] = _mm_xor_si128(KEY[ROUND], _mm_slli_si128(KEY[ROUND], 4));     \
    KEY[ROUND] = _mm_xor_si128(KEY[ROUND], temp);                              \
  } while (0)

#define AES_EXPAND_KEYS(KEY)                                                   \
  do {                                                                         \
    AES_KEY_EXPAND_STEP(KEY, 1, 0x01);                                         \
    AES_KEY_EXPAND_STEP(KEY, 2, 0x02);                                         \
    AES_KEY_EXPAND_STEP(KEY, 3, 0x04);                                         \
    AES_KEY_EXPAND_STEP(KEY, 4, 0x08);                                         \
    AES_KEY_EXPAND_STEP(KEY, 5, 0x10);                                         \
    AES_KEY_EXPAND_STEP(KEY, 6, 0x20);                                         \
    AES_KEY_EXPAND_STEP(KEY, 7, 0x40);                                         \
    AES_KEY_EXPAND_STEP(KEY, 8, 0x80);                                         \
    AES_KEY_EXPAND_STEP(KEY, 9, 0x1B);                                         \
    AES_KEY_EXPAND_STEP(KEY, 10, 0x36);                                        \
  } while (0)

#define AES_BLOCK_BITS 128 /* bits of AES algoithm block */
#define AES_BLOCK_SIZE 16  /* bytes of AES algoithm block */
#define AES_KEY_SIZE 16    /* bytes of AES algoithm double key */

/**
 * @brief Generate encryption subkeys
 * @param[in] key original key
 * @param[out] subKeys generated encryption subkeys
 * @return 0 OK
 * @return 1 Failed
 */
int aes_make_enc_subkeys(const unsigned char key[16],
                         unsigned char subKeys[11][16]);

/**
 * @brief Generate decryption subkeys
 * @param[in] key original key
 * @param[out] subKeys generated decryption subkeys
 * @return 0 OK
 * @return 1 Failed
 */
int aes_make_dec_subkeys(const unsigned char key[16],
                         unsigned char subKeys[11][16]);

/**
 * @brief AES encrypt single block
 * @param[in] input plaintext, [length = AES_BLOCK_SIZE]
 * @param[in] subKeys subKeys
 * @param[out] output ciphertext, [length = AES_BLOCK_SIZE]
 */
void aes_encrypt_block(const unsigned char *input,
                       unsigned char subKeys[11][16], unsigned char *output);

/**
 * @brief AES decrypt single block
 * @param[in] input ciphertext, [length = AES_BLOCK_SIZE]
 * @param[in] subKeys subKeys
 * @param[out] output plaintext, [length = AES_BLOCK_SIZE]
 */
void aes_decrypt_block(const unsigned char *input,
                       unsigned char subKeys[11][16], unsigned char *output);

#ifdef __cplusplus
}
#endif

#endif // AES_H
