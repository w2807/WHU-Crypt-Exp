#include <stdint.h>
#ifndef UTIL_H
#define UTIL_H

/**
 * @brief 初始置换函数
 * @param[in] input 输入数据
 * @return 初始置换后的数据
 */
uint64_t initial_permutation(uint64_t input);

/**
 * @brief 逆初始置换函数
 * @param[in] input 输入数据
 * @return 逆初始置换后的数据
 */
uint64_t inverse_permutation(uint64_t input);

/**
 * @brief E盒扩展函数
 * @param[in] input 32位输入
 * @return 48位输出
 */
uint64_t e_box(uint32_t input);

/**
 * @brief P盒置换函数
 * @param[in] input 32位输入
 * @return 32位输出
 */
uint32_t p_box(uint32_t input);

/**
 * @brief S盒代换函数
 * @param[in] input 扩展并异或后的48位输入
 * @return S盒代换后的32位输出
 */
uint32_t sBox(uint64_t input);

/**
 * @brief 轮函数
 * @param[in] half_block 32位半块
 * @param[in] subkey 48位子密钥
 * @return 32位输出
 */
uint32_t feistel(uint32_t half_block, uint64_t subkey);

/**
 * @brief PC-1置换函数
 * @param[in] key 64位密钥
 * @return 56位输出
 */
uint64_t permuted_choice_1(uint64_t key);

/**
 * @brief PC-2置换函数
 * @param[in] key 56位密钥
 * @return 48位输出
 */
uint64_t permuted_choice_2(uint64_t key);

/**
 * @brief 从 subKeys 数组中读取并构建48位子密钥
 * @param[in] subKeys 子密钥数组
 * @param[in] round 当前轮数
 * @return 48位子密钥
 */
uint64_t read_subkey(const unsigned char subKeys[16][6], int round);

#endif