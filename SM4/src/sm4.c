#include "sm4.h"
#include "table.h"

// Left rotate
#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// Tau transformation
#define S32(A)                                                                 \
  ((S[((A) >> 24) & 0xFF] << 24) | (S[((A) >> 16) & 0xFF] << 16) |             \
   (S[((A) >> 8) & 0xFF] << 8) | (S[(A) & 0xFF]))

// Linear transformation
#define L32(B) (B ^ ROL32(B, 2) ^ ROL32(B, 10) ^ ROL32(B, 18) ^ ROL32(B, 24))
#define L32_(B) (B ^ ROL32(B, 13) ^ ROL32(B, 23))

// Key schedule function
static void sm4_key_schedule(const unsigned char key[16],
                             uint32_t subKeys[SM4_ROUNDS], int is_enc) {
  uint32_t K[4];
  int i;

  for (i = 0; i < 4; i++) {
    K[i] = FK[i] ^ ((key[i * 4] << 24) | (key[i * 4 + 1] << 16) |
                    (key[i * 4 + 2] << 8) | key[i * 4 + 3]);
  }

  for (i = 0; i < 32; i++) {
    uint32_t tmp = K[1] ^ K[2] ^ K[3] ^ CK[i];
    tmp = S32(tmp);
    subKeys[is_enc ? i : (31 - i)] = K[0] ^ L32_(tmp);

    K[0] = K[1];
    K[1] = K[2];
    K[2] = K[3];
    K[3] = subKeys[is_enc ? i : (31 - i)];
  }
}

int sm4_make_enc_subkeys(const unsigned char key[16],
                         uint32_t subKeys[SM4_ROUNDS]) {
  sm4_key_schedule(key, subKeys, 1);
  return 0;
}

int sm4_make_dec_subkeys(const unsigned char key[16],
                         uint32_t subKeys[SM4_ROUNDS]) {
  sm4_key_schedule(key, subKeys, 0);
  return 0;
}

static void sm4_one_block(const unsigned char *input,
                          const uint32_t subKeys[SM4_ROUNDS],
                          unsigned char *output) {
  uint32_t X[4], tmp;
  int i;

  for (i = 0; i < 4; i++) {
    X[i] = (input[i * 4] << 24) | (input[i * 4 + 1] << 16) |
           (input[i * 4 + 2] << 8) | input[i * 4 + 3];
  }

  for (i = 0; i < 32; i++) {
    tmp = X[1] ^ X[2] ^ X[3] ^ subKeys[i];
    tmp = S32(tmp);
    tmp = X[0] ^ L32(tmp);

    X[0] = X[1];
    X[1] = X[2];
    X[2] = X[3];
    X[3] = tmp;
  }

  for (i = 0; i < 4; i++) {
    output[i * 4] = (X[3 - i] >> 24) & 0xFF;
    output[i * 4 + 1] = (X[3 - i] >> 16) & 0xFF;
    output[i * 4 + 2] = (X[3 - i] >> 8) & 0xFF;
    output[i * 4 + 3] = X[3 - i] & 0xFF;
  }
}

void sm4_encrypt_block(const unsigned char *input,
                       const uint32_t encSubKeys[SM4_ROUNDS],
                       unsigned char *output) {
  sm4_one_block(input, encSubKeys, output);
}

void sm4_decrypt_block(const unsigned char *input,
                       const uint32_t decSubKeys[SM4_ROUNDS],
                       unsigned char *output) {
  sm4_one_block(input, decSubKeys, output);
}