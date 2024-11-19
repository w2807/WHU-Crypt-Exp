#include "des.h"
#include "config.h"
#include "util.h"
#include <stdint.h>

int des_make_subkeys(const unsigned char key[8], unsigned char subKeys[16][6]) {
  uint64_t key64 = 0;
  // 将字节数组转换为64位整数
  for (int i = 0; i < 8; ++i) {
    key64 = (key64 << 8) | key[i];
  }

  uint64_t permutedKey = permuted_choice_1(key64);
  

  uint32_t C = (permutedKey >> 28) & 0x0FFFFFFF;
  uint32_t D = permutedKey & 0x0FFFFFFF;

  // 生成16个子密钥
  for (int round = 0; round < 16; ++round) {
    // 左循环移位
    C = ((C << SHIFTS[round]) | (C >> (28 - SHIFTS[round]))) & 0x0FFFFFFF;
    D = ((D << SHIFTS[round]) | (D >> (28 - SHIFTS[round]))) & 0x0FFFFFFF;

    uint64_t CD = ((uint64_t)C << 28) | D;

    uint64_t subKey = permuted_choice_2(CD);
    

    for (int byte = 0; byte < 6; ++byte) {
      subKeys[round][byte] = (subKey >> (40 - byte * 8)) & 0xFF;
    }
  }

  return 0;
}

void des_encrypt_block(const unsigned char *input, unsigned char subKeys[16][6],
                       unsigned char *output) {
    // 将输入转换为64位整数
    uint64_t block = 0;
    for (int i = 0; i < 8; ++i) {
      block = (block << 8) | input[i];
    }

    uint64_t permuted = initial_permutation(block);

    uint32_t L = (permuted >> 32) & 0xFFFFFFFF;
    uint32_t R = permuted & 0xFFFFFFFF;

    // 16轮迭代
    for (int round = 0; round < 16; ++round) {
      uint32_t temp = R;

      uint64_t subKey = read_subkey(subKeys, round);

      R = L ^ feistel(R, subKey);
      L = temp;
    }

    uint64_t preOutput = ((uint64_t)R << 32) | L;
    uint64_t finalBlock = inverse_permutation(preOutput);

    // 将结果转换回字节数组
    for (int i = 7; i >= 0; --i) {
      output[i] = finalBlock & 0xFF;
      finalBlock >>= 8;
    }
  }

// 单块解密
void des_decrypt_block(const unsigned char *input, unsigned char subKeys[16][6],
                       unsigned char *output) {
  // 将输入转换为64位整数
  uint64_t block = 0;
  for (int i = 0; i < 8; ++i) {
    block = (block << 8) | input[i];
  }

  // 初始置换 IP
  uint64_t permuted = initial_permutation(block);

  uint32_t L = (permuted >> 32) & 0xFFFFFFFF;
  uint32_t R = permuted & 0xFFFFFFFF;

  // 16轮迭代，使用逆序子密钥
  for (int round = 15; round >= 0; --round) {
    uint32_t temp = R;

    uint64_t subKey = read_subkey(subKeys, round);

    R = L ^ feistel(R, subKey);
    L = temp;
  }

  uint64_t preOutput = ((uint64_t)R << 32) | L;

  uint64_t finalBlock = inverse_permutation(preOutput);

  // 将结果转换回字节数组
  for (int i = 7; i >= 0; --i) {
    output[i] = finalBlock & 0xFF;
    finalBlock >>= 8;
  }
}